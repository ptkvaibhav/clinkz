"""JS/TS (Node/Express backend) source ingestion → :class:`SourceModel` (slice A1).

The first cross-language rung of the discovery engine: a deterministic,
**regex / bounded-scan-only** ingestor (never ``eval``, bounded file count + bytes,
source treated as untrusted data) — the *same discipline* as
:class:`~clinkz.discovery.source_ingest.JavaSourceIngestor` and
``agents/_route_discovery.py``. It surfaces JS *sink shapes* that reduce to the
**existing** :class:`~clinkz.discovery.models.PrimitiveClass` values
(``EGRESS_FETCH`` / ``FILE_READ``); it adds no capability class, oracle or proof —
the JS shapes ride the exact same catalog → intent → reachability → hypothesis →
proof path a Java shape does.

Deliberately shallow, backend-only, and bounded — a MIRROR of the Java ingestor's
philosophy, **not** a JS AST / whole-program dataflow engine:

  1. **Entrypoints are Express/router route registrations.** ``app.get('/x', h)`` /
     ``router.post("/y", h)`` / ``app.use('/x', h)`` — the HTTP verb + the mounted path
     literal. The handler body is either **inline** (an arrow/``function`` body in the
     registration args) or, for the dominant real-world ESM/TS shape, a **factory
     imported from a separate routes file** (``app.post('/x', asyncHandler(make()))``
     with ``export function make () { return (req, res) => {…} }`` elsewhere) — resolved
     cross-file by a two-pass handler registry (the JS analogue of the Java pass's
     cross-file resolution). That body is the intra-handler scope taint is resolved
     within, mirroring the Java handler's ``doGet``/``doPost`` body.
  2. **Untrusted channels are ``req.query`` / ``req.body`` / ``req.params`` /
     ``req.headers`` reads.** A ``const x = req.query.url`` binds a local to a
     request parameter (the JS analogue of ``String x = request.getParameter("p")``);
     a ``req.params.id`` read rides the URL *path* (→ ``path_params``).
  3. **Call sites are JS idioms of the existing primitive classes only.**
     ``EGRESS_FETCH`` — ``axios(…)`` / ``axios.get/post`` / ``fetch(…)`` /
     ``http(s).get/request`` / the ``request`` lib — with a request-tainted URL
     argument (the ``URL.openConnection()`` analogue). ``FILE_READ`` —
     ``fs.readFile`` / ``fs.readFileSync`` / ``fs.createReadStream`` /
     ``res.sendFile`` — with a request-tainted path argument (the ``new File(name)``
     analogue). Each is tagged with a fixed-vocabulary ``sink_shape_id``
     (``js.http_egress`` / ``js.fs_read``) the Layer-2 write-back keys a fact on.
  4. **A basename-strip / normalize guard on the tainted file path is a real guard.**
     ``path.basename(x)`` / ``path.normalize(x)`` applied to the tainted value is
     the file-read analogue of Flink's ``.getName()`` fix — its presence marks the
     value sanitized (Intent → SANCTIONED, Δ removed ⇒ no hypothesis); its absence is
     the intent-gap (EXPOSED). Conservative by design: the safe direction is to
     over-guard (drop a true positive) rather than emit a phantom.
  5. **The manifest is ``package.json`` (+ lock).** The JS analogue of the ``pom.xml``
     log4j-core scan. Two distinct keying concepts (slice A2a):

       * **Model-level ``manifest_technology_key``** — the HTTP-client library an
         ``EGRESS_FETCH`` used (else the backend framework) + its version. Used for the
         ``bundles`` transfer edges and (for a Java target) the ``LOG_INTERPOLATION``
         fact key. It is NOT the EGRESS_FETCH / FILE_READ fact key.
       * **Per-sink ``CallSite.carrying_dependency`` (A2a — the correctness core)** — a
         capability is keyed on a carrying dependency ONLY when the sink is *library-borne*
         (its source file lives inside a bundled local-path / workspace dependency),
         attributed from the sink's path + that package's ``package.json``. An **app-code**
         sink (``routes/`` / ``src/`` / the app root) that merely *calls* a library gets NO
         carrying dependency and stays fingerprint-keyed — so an app-level capability
         (Juice Shop's ``fetch``-based SSRF) is never mis-keyed on ``express`` and falsely
         transferred. Declared local packages are also surfaced as observed technology
         identities so a package present-per-manifest but source-withheld this engagement
         stays recall-observable (the JS→JS transfer path).

Angular / any browser-side frontend is **out of scope** (``node_modules`` / build
output / ``*.min.js`` / ``*.d.ts`` are never ingested). Taint is one hop (request read
→ local, and a local / inline request read reaching a sink argument). Documented
deferrals (the deliberately-shallow floor): a request destructured in the arrow *param
signature* (``({ params }) =>``) rather than via ``req.``; a handler referenced *bare*
(not called) in the args; multi-hop propagation through an intermediate reassignment or
an inner helper function; and SSRF host-check guards. Slice A2b added cross-file
factory-handler resolution so the ingestor reaches real-world Express/TS backends
(OWASP Juice Shop) whose handler bodies live outside the ``server.ts`` route table.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import NamedTuple

from clinkz.discovery.models import (
    CallSite,
    CoverageGrade,
    Entrypoint,
    Guard,
    PrimitiveClass,
    SourceModel,
)

logger = logging.getLogger(__name__)

# --- Ingestion bounds (source is untrusted; never unbounded) ----------------
_MAX_FILES = 2000
_MAX_FILE_BYTES = 512 * 1024
# Bounded window (chars) a handler body / balanced brace-or-paren scan may span.
_MAX_HANDLER_SCAN = 8000

# Directories never ingested — dependencies, build output, frontend bundles. Keeps
# the scan bounded and backend-only (Angular/browser code lives under these).
_SKIP_DIRS = frozenset(
    {"node_modules", ".git", "dist", "build", "out", "coverage", ".next", ".nuxt", ".cache"}
)
_SOURCE_GLOBS = ("*.js", "*.mjs", "*.cjs", "*.ts")

# --- Express route registration (the entrypoint) ----------------------------
# ``app.get('/x', …)`` / ``router.post("/y", …)`` — HTTP verb + path literal. The
# path is captured from a matched quote (single/double/backtick) so a template route
# is tolerated; ``all`` registers every verb; ``use('/path', handler)`` is a mounted
# handler (a bare ``use(mw)`` without a path literal never matches — the regex requires
# a quoted first arg — so global middleware is not mistaken for a route).
_RE_ROUTE = re.compile(
    r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*(['\"`])([^'\"`]*)\2"
)
# The handler body opens at an arrow ``=> {`` or a ``function (…) {`` signature.
_RE_HANDLER_OPEN = re.compile(r"=>\s*\{|\bfunction\b[^{;]*\{")

# --- Cross-file factory-handler resolution (the real-world ESM/TS pattern) ---
# Idiomatic Express/TS apps (OWASP Juice Shop et al.) register a handler FACTORY
# imported from another module — ``app.post('/x', asyncHandler(makeHandler()))`` —
# whose body lives in ``export function makeHandler () { return (req, res) => {…} }``
# in a SEPARATE routes file. A1 assumed an inline body immediately after the route, so
# it never reached these bodies (the ``named-handler / controller-module indirection``
# A1 deferred). Pass 1 indexes every exported handler function by name; pass 2 links a
# route registration to a referenced factory's body across files. Still bounded /
# regex-only (the JS analogue of the Java pass's 2-pass cross-file resolution) — no AST,
# no call-graph, no dataflow engine.
_RE_EXPORT_HANDLER = re.compile(r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(")
# A ``name(`` call inside a route registration's argument list — the candidate factory
# reference resolved against the pass-1 registry (a bare, un-called reference is a
# documented deferral).
_RE_HANDLER_REF = re.compile(r"\b(\w+)\s*\(")
# Max chars between a handler function's params ``)`` and its body ``{`` (skips a TS
# return-type annotation); bounds the body-brace search.
_MAX_SIG_TO_BODY = 300

# --- Untrusted request reads (the channel) ----------------------------------
_REQ_SOURCES = r"query|body|params|headers"
# ``const x = req.query.name`` / ``let x = req.body['name']`` — a request param bound
# to a local. group(1)=local var, group(2)=dot-name, group(3)=bracket-name.
_RE_VAR_FROM_REQ = re.compile(
    rf"(?:const|let|var)\s+(\w+)\s*=\s*\breq\.(?:{_REQ_SOURCES})"
    r"(?:\.(\w+)|\[\s*['\"](\w+)['\"]\s*\])"
)
# ``const { a, b: alias } = req.query`` — destructured request params. group(1) is
# the (comma-separated) name list, group(2) is the request source.
_RE_DESTRUCTURE_REQ = re.compile(
    rf"(?:const|let|var)\s*\{{\s*([^}}]+?)\s*\}}\s*=\s*\breq\.({_REQ_SOURCES})\b"
)
# Any ``req.query.name`` / ``req.params.id`` / ``req.body['x']`` read — used both to
# collect the entrypoint's read params and to taint a sink argument that reads a
# request value inline. group(1)=source, group(2)=dot-name, group(3)=bracket-name.
_RE_REQ_READ = re.compile(rf"\breq\.({_REQ_SOURCES})(?:\.(\w+)|\[\s*['\"](\w+)['\"]\s*\])")

# --- Sinks (JS idioms of the EXISTING primitive classes) --------------------
# EGRESS_FETCH: a server-side HTTP fetch. ``(?<![\w.])`` rejects a property access
# (``res.fetch(`` is not ``fetch(``) and a longer identifier. Built-ins (fetch, http,
# https) and libraries (axios, got, request, superagent, needle) are all covered; the
# receiver library is recovered from the match for the manifest carrying-dependency.
_RE_EGRESS_SINK = re.compile(
    r"(?<![\w.])("
    r"axios\.(?:get|post|put|patch|delete|request|head)"
    r"|axios"
    r"|fetch"
    r"|https?\.(?:get|request)"
    r"|got"
    r"|request"
    r"|superagent\.(?:get|post)"
    r"|needle\.(?:get|post|request)"
    r")\s*\("
)
# FILE_READ: a filesystem read whose path may be request-tainted. ``res.sendFile`` is
# an arbitrary-file-serve sink; ``fs.readFile*`` / ``createReadStream`` are reads.
_RE_FILE_SINK = re.compile(
    r"(?<![\w.])(fs\.(?:readFile|readFileSync|createReadStream)|(?:res|response)\.sendFile)\s*\("
)
# A basename-strip / normalize guard applied to the tainted path — the file-read
# analogue of Flink's ``.getName()`` fix (SANCTIONED ⇒ Δ removed).
_RE_PATH_SANITIZER = re.compile(r"\bpath\s*\.\s*(?:basename|normalize)\s*\(")
_FILE_READ_GUARD_SYMBOL = "path_basename_strip"

# Stable sink-shape ids — the recognizer's fixed Layer-2 vocabulary (design §S1.3),
# a *tag on already-existing detection* the capability-learning write-back keys a
# fact on. The JS analogues of ``java.url_openconnection`` / ``java.file_sink``.
_SINK_SHAPE_EGRESS = "js.http_egress"
_SINK_SHAPE_FILE_READ = "js.fs_read"

# --- Manifest (package.json / lock) — the carrying-dependency scan ----------
# An egress sink's receiver library → its npm package name (built-ins fetch/http/https
# have no package). The manifest keys the surfaced EGRESS_FETCH capability on whichever
# of these the app actually bundled — the JS analogue of keying Log4Shell on log4j-core.
_EGRESS_LIB_PACKAGE: dict[str, str] = {
    "axios": "axios",
    "got": "got",
    "request": "request",
    "superagent": "superagent",
    "needle": "needle",
}
# Priority when several carrying libraries are bundled (deterministic tie-break).
_EGRESS_LIB_PRIORITY: tuple[str, ...] = ("axios", "got", "request", "superagent", "needle")
# Backend frameworks — the fallback carrying identity when no egress library owns the
# surfaced capability (e.g. only ``fs`` sinks), so a JS SourceModel always carries some
# manifest key A2 can attach facts to.
_BACKEND_FRAMEWORKS: tuple[str, ...] = ("express", "koa", "fastify", "@hapi/hapi", "@nestjs/core")
# A version spec (``^1.6.0`` / ``~4.18.2`` / ``>=1.0.0``) → its point version.
_RE_VERSION_POINT = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024

# --- Per-sink carrying-dependency attribution (slice A2a) --------------------
# A dependency spec that points at a LOCAL package directory (bundled first-party
# code whose source IS ingested), not an npm-registry range whose source lives under
# the skipped ``node_modules``. These are the attribution targets: a sink whose file
# lives inside one of these directories is library-borne and keyed on that package.
_LOCAL_SPEC_PREFIXES = ("file:", "link:", "portal:")
# Bound on indexed local/workspace packages (a monorepo is bounded in practice).
_MAX_LOCAL_DEPS = 128


class _HandlerDef(NamedTuple):
    """A resolved route-handler body + the file/offset it was defined in.

    ``text`` is the defining file's full text (so sink line numbers resolve against
    the file the sink actually lives in — the routes file for a cross-file factory,
    not the ``server.ts`` where the route is registered). ``body_start`` is the
    absolute offset of ``body`` within ``text``.
    """

    file: str
    text: str
    body: str
    body_start: int


class _LocalDep(NamedTuple):
    """A declared local-path / workspace dependency's directory + package identity.

    ``directory`` is the resolved on-disk root of the bundled package; ``name`` /
    ``version`` come from that package's OWN ``package.json`` (falling back to the
    declared dependency name when the package has no readable manifest version). A sink
    whose source file lives under ``directory`` is *library-borne* and keyed on
    ``name@version`` (slice A2a) — the app's own tree is never indexed, so an app-code
    sink stays fingerprint-keyed.
    """

    directory: Path
    name: str
    version: str


def _line_of(text: str, index: int) -> int:
    """1-based line number of *index* within *text*."""
    return text.count("\n", 0, index) + 1


def _balanced_slice(text: str, open_index: int, opener: str, closer: str) -> tuple[str, int]:
    """Return ``(inner, end_index)`` for the balanced ``opener…closer`` at *open_index*.

    Bounded (never unbounded over untrusted source): scans at most
    :data:`_MAX_HANDLER_SCAN` chars. ``inner`` is the substring between the delimiters
    (exclusive); ``end_index`` is the index of the matching closer, or ``-1`` when
    *open_index* is not *opener* or the delimiters do not balance within the bound.
    """
    if open_index >= len(text) or text[open_index] != opener:
        return "", -1
    depth = 0
    end = min(len(text), open_index + _MAX_HANDLER_SCAN)
    for i in range(open_index, end):
        char = text[i]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : i], i
    return "", -1


def _first_arg(arg_slice: str) -> str:
    """The first argument expression in *arg_slice* (up to the first depth-0 comma)."""
    depth = 0
    for i, char in enumerate(arg_slice):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            return arg_slice[:i].strip()
    return arg_slice.strip()


class JsSourceIngestor:
    """Ingest a JS/TS (Node/Express) source tree into a :class:`SourceModel`.

    Bounded, regex-only, backend-only. Satisfies the
    :class:`~clinkz.discovery.ingestor.SourceIngestor` protocol structurally (one
    public ``ingest_path``), so the language-dispatch factory can return it
    interchangeably with :class:`~clinkz.discovery.source_ingest.JavaSourceIngestor`.
    """

    def ingest_path(self, root: str | Path) -> SourceModel:
        """Ingest every backend ``*.js/.mjs/.cjs/.ts`` under *root* (bounded).

        Two deterministic passes (the JS analogue of the Java pass's cross-file
        resolution). Pass 1 indexes every exported handler *factory* by name (the
        real-world ESM/TS shape where the handler body lives in a separate routes
        file). Pass 2 walks Express route registrations, resolves each to its handler
        body — inline, or a pass-1 factory referenced across files — resolves the
        intra-handler taint (request read → local var), and surfaces the tainted
        egress / file-read call sites in that body. Then read ``package.json`` (+
        lock) for the carrying-dependency manifest and the tech fingerprint.
        """
        root = Path(root)
        model = SourceModel()
        if not root.exists():
            logger.warning("js source ingest: path does not exist: %s", root)
            return model

        texts = self._read_files(root)
        pkg = self._read_package_json(root)
        deps: dict[str, str] = {}
        if pkg:
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        dep_index = self._local_dependency_index(root, deps, pkg)
        registry = self._build_handler_registry(texts)
        used_egress_libs: set[str] = set()
        route_idiom_seen = False
        for file, text in texts:
            if _RE_ROUTE.search(text):
                route_idiom_seen = True
            self._ingest_text(text, file, model, registry, used_egress_libs, dep_index)

        model.files_ingested = len(texts)
        if model.call_sites:
            model.coverage_grade = CoverageGrade.PARTIAL
        self._apply_manifest_and_tech(
            model, pkg, deps, dep_index, root, used_egress_libs, route_idiom_seen
        )
        logger.info(
            "js source ingest: %d files → %d entrypoints, %d call-sites, %d guards; manifest=%s",
            len(texts),
            len(model.entrypoints),
            len(model.call_sites),
            len(model.guards),
            model.manifest_evidence or "(none)",
        )
        return model

    def _read_files(self, root: Path) -> list[tuple[str, str]]:
        """Bounded, backend-only list of ``(path, text)`` under *root*."""
        if root.is_file():
            candidates = [root] if root.suffix in {".js", ".mjs", ".cjs", ".ts"} else []
        else:
            seen: set[Path] = set()
            for glob in _SOURCE_GLOBS:
                for path in root.rglob(glob):
                    if any(part in _SKIP_DIRS for part in path.parts):
                        continue
                    if path.name.endswith((".min.js", ".d.ts")):
                        continue
                    seen.add(path)
            candidates = sorted(seen)
        texts: list[tuple[str, str]] = []
        for path in candidates[:_MAX_FILES]:
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("js source ingest: cannot read %s: %s", path, exc)
                continue
            texts.append((str(path), text))
        return texts

    @staticmethod
    def _build_handler_registry(texts: list[tuple[str, str]]) -> dict[str, _HandlerDef]:
        """Pass 1: index every ``export function <Name> (...) { … }`` by name.

        The registry lets pass 2 resolve a route registered against a factory
        referenced across files (``app.post('/x', asyncHandler(makeHandler()))``) to
        the handler body defined in another module. First definition wins (deterministic
        on duplicate names). Bounded: balanced-brace over each function body only.
        """
        registry: dict[str, _HandlerDef] = {}
        for file, text in texts:
            for match in _RE_EXPORT_HANDLER.finditer(text):
                name = match.group(1)
                if name in registry:
                    continue
                paren_open = match.end() - 1  # the '(' of the params list
                _, paren_close = _balanced_slice(text, paren_open, "(", ")")
                if paren_close < 0:
                    continue
                brace = text.find("{", paren_close, paren_close + _MAX_SIG_TO_BODY)
                if brace < 0:
                    continue
                body, end = _balanced_slice(text, brace, "{", "}")
                if end < 0:
                    continue
                registry[name] = _HandlerDef(file=file, text=text, body=body, body_start=brace + 1)
        return registry

    def _ingest_text(
        self,
        text: str,
        file: str,
        model: SourceModel,
        registry: dict[str, _HandlerDef],
        used_egress_libs: set[str],
        dep_index: list[_LocalDep],
    ) -> None:
        """Pass 2: extract entrypoints / call sites / guards from route handlers."""
        for match in _RE_ROUTE.finditer(text):
            verb = match.group(1)
            route = match.group(3)
            handler = self._resolve_handler(text, file, match, registry)
            if handler is None:
                continue
            params, path_params, var_to_param = self._collect_channel(handler.body)
            model.entrypoints.append(
                Entrypoint(
                    route=route,
                    http_methods=self._methods(verb),
                    handler_symbol=f"{verb.upper()} {route or '/'}",
                    params=params,
                    path_params=path_params,
                    file=file,
                    line=_line_of(text, match.start()),
                )
            )
            self._sinks_in_body(
                handler.body,
                handler.body_start,
                handler.text,
                handler.file,
                var_to_param,
                model,
                used_egress_libs,
                dep_index,
            )

    @staticmethod
    def _resolve_handler(
        text: str, file: str, match: re.Match[str], registry: dict[str, _HandlerDef]
    ) -> _HandlerDef | None:
        """Resolve a route registration to its handler body (inline, or cross-file).

        The full registration argument list is balanced-sliced from the call's ``(``
        (so the scan is confined to THIS registration, never spilling into the next
        route). An inline arrow/function body within the args is used directly (the A1
        shape); otherwise the first referenced factory ``name(`` present in the pass-1
        registry supplies the body from its defining file. Returns ``None`` when neither
        resolves (a bare middleware, or an un-indexed handler — a documented deferral).
        """
        call_open = text.find("(", match.start(), match.end())
        if call_open < 0:
            return None
        arglist, arglist_end = _balanced_slice(text, call_open, "(", ")")
        if arglist_end < 0:
            return None
        arglist_abs = call_open + 1
        sig = _RE_HANDLER_OPEN.search(arglist)
        if sig is not None:
            brace_local = arglist.find("{", sig.start(), sig.end())
            if brace_local >= 0:
                body, end = _balanced_slice(arglist, brace_local, "{", "}")
                if end >= 0:
                    return _HandlerDef(
                        file=file, text=text, body=body, body_start=arglist_abs + brace_local + 1
                    )
        for ref in _RE_HANDLER_REF.finditer(arglist):
            handler = registry.get(ref.group(1))
            if handler is not None:
                return handler
        return None

    @staticmethod
    def _methods(verb: str) -> list[str]:
        """Map an Express verb to HTTP methods (``all`` → the common set)."""
        if verb == "all":
            return ["GET", "POST", "PUT", "PATCH", "DELETE"]
        return [verb.upper()]

    @staticmethod
    def _collect_channel(body: str) -> tuple[list[str], list[str], dict[str, str]]:
        """Collect ``(params, path_params, var_to_param)`` read in a handler body.

        ``params`` is every request parameter the handler reads (ordered, deduped);
        ``path_params`` is the subset read via ``req.params`` (URL path segments);
        ``var_to_param`` maps a local bound from a request read to its parameter name,
        so a sink argument that is that local resolves back to the channel.
        """
        params: list[str] = []
        path_params: list[str] = []
        var_to_param: dict[str, str] = {}

        def _add(name: str, source: str) -> None:
            if name and name not in params:
                params.append(name)
            if source == "params" and name and name not in path_params:
                path_params.append(name)

        for match in _RE_REQ_READ.finditer(body):
            _add(match.group(2) or match.group(3), match.group(1))
        for match in _RE_DESTRUCTURE_REQ.finditer(body):
            source = match.group(2)
            for item in match.group(1).split(","):
                token = item.strip()
                if not token:
                    continue
                # ``name: alias`` — the request param is ``name``, the local is ``alias``.
                name, _, alias = token.partition(":")
                name = name.strip()
                local = (alias.strip() or name) if ":" in token else name
                _add(name, source)
                if local:
                    var_to_param[local] = name
        for match in _RE_VAR_FROM_REQ.finditer(body):
            var_to_param[match.group(1)] = match.group(2) or match.group(3)
        return params, path_params, var_to_param

    def _sinks_in_body(
        self,
        body: str,
        body_start: int,
        text: str,
        file: str,
        var_to_param: dict[str, str],
        model: SourceModel,
        used_egress_libs: set[str],
        dep_index: list[_LocalDep],
    ) -> None:
        """Surface tainted egress / file-read call sites within one handler body.

        Every sink is attributed to a carrying dependency ONLY when its defining ``file``
        lives inside a bundled dependency (slice A2a); a sink in the app's own tree gets
        no carrying dependency and stays fingerprint-keyed. Attribution is a property of
        the file, constant across every sink in this body, so it is resolved once.
        """
        carrying, carrying_version = self._attribute_carrying_dependency(file, dep_index)
        for match in _RE_EGRESS_SINK.finditer(body):
            symbol = match.group(1)
            tainted_by = self._sink_taint(body, match.end() - 1, var_to_param)
            if tainted_by is None:
                continue  # a constant/non-request URL is not attack surface
            lib = symbol.split(".")[0]
            if lib in _EGRESS_LIB_PACKAGE:
                used_egress_libs.add(lib)
            model.call_sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.EGRESS_FETCH,
                    symbol=symbol,
                    file=file,
                    line=_line_of(text, body_start + match.start()),
                    tainted_by=tainted_by,
                    sink_shape_id=_SINK_SHAPE_EGRESS,
                    carrying_dependency=carrying,
                    carrying_version=carrying_version,
                )
            )
        for match in _RE_FILE_SINK.finditer(body):
            symbol = match.group(1)
            tainted_by = self._sink_taint(body, match.end() - 1, var_to_param)
            if tainted_by is None:
                continue
            guard_symbol = self._file_guard_symbol(body, tainted_by, var_to_param, file, model)
            model.call_sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.FILE_READ,
                    symbol=symbol,
                    file=file,
                    line=_line_of(text, body_start + match.start()),
                    tainted_by=tainted_by,
                    guard_symbol=guard_symbol,
                    sink_shape_id=_SINK_SHAPE_FILE_READ,
                    carrying_dependency=carrying,
                    carrying_version=carrying_version,
                )
            )

    @staticmethod
    def _sink_taint(body: str, open_index: int, var_to_param: dict[str, str]) -> str | None:
        """The request parameter tainting a sink's first argument, or ``None``.

        The first argument is either a direct request read (``req.query.url``), a local
        bound from one (``const url = req.query.url``), or an expression embedding such a
        local (a template literal / concatenation) — in each case the value flows from
        the named channel.
        """
        args, _ = _balanced_slice(body, open_index, "(", ")")
        arg = _first_arg(args)
        if not arg:
            return None
        inline = _RE_REQ_READ.search(arg)
        if inline is not None:
            return inline.group(2) or inline.group(3)
        for var, param in var_to_param.items():
            if re.search(rf"(?<![\w.])\b{re.escape(var)}\b", arg):
                return param
        return None

    @staticmethod
    def _file_guard_symbol(
        body: str,
        tainted_by: str,
        var_to_param: dict[str, str],
        file: str,
        model: SourceModel,
    ) -> str | None:
        """A basename-strip / normalize guard on the tainted path (SANCTIONED), or None.

        Conservative: if the tainted value (or any local bound from it) is ever passed
        through ``path.basename`` / ``path.normalize`` in the handler, the path is treated
        as sanitized. Over-guarding drops a true positive (the safe direction) rather than
        emitting a phantom.
        """
        aliases = {v for v, p in var_to_param.items() if p == tainted_by} | {tainted_by}
        for match in _RE_PATH_SANITIZER.finditer(body):
            args, _ = _balanced_slice(body, match.end() - 1, "(", ")")
            if any(re.search(rf"(?<![\w.])\b{re.escape(a)}\b", args) for a in aliases):
                model.guards.append(
                    Guard(
                        symbol=_FILE_READ_GUARD_SYMBOL,
                        kind="path_basename_strip",
                        operands=[tainted_by],
                        bypassable_by_default=False,
                        file=file,
                        line=0,
                    )
                )
                return _FILE_READ_GUARD_SYMBOL
        return None

    def _apply_manifest_and_tech(
        self,
        model: SourceModel,
        pkg: dict | None,
        deps: dict[str, str],
        dep_index: list[_LocalDep],
        root: Path,
        used_egress_libs: set[str],
        route_idiom_seen: bool,
    ) -> None:
        """Populate ``technologies`` + the carrying-dependency manifest from package.json."""
        technologies = ["Node.js"]
        if "express" in deps or route_idiom_seen:
            technologies.append("Express")
        for framework, display in (
            ("koa", "Koa"),
            ("fastify", "Fastify"),
            ("@nestjs/core", "NestJS"),
        ):
            if framework in deps and display not in technologies:
                technologies.append(display)
        # Surface each declared local-path / workspace dependency as an observed technology
        # identity (``<name> <version>``) — slice A2a. A package that is PRESENT PER
        # MANIFEST but whose source is withheld this engagement is still recall-observable:
        # recall reaches a package-keyed capability fact via the observed identity and seeds
        # the hypothesis (the JS→JS transfer path). A registry dependency is never surfaced
        # this way (its source lives under the skipped ``node_modules``). Bounded + deduped.
        for dep in dep_index:
            identity = f"{dep.name} {dep.version}".strip()
            if identity and identity not in technologies:
                technologies.append(identity)
        if model.entrypoints or model.call_sites or pkg is not None:
            model.technologies = technologies

        key, version = self._carrying_dependency(used_egress_libs, deps, root)
        if key:
            model.manifest_technology_key = key
            model.manifest_observed_version = version
            model.manifest_evidence = (
                f"{key}@{version or '?'} declared in package.json"
                " — carrying dependency of the surfaced capability"
            )

    # --- Per-sink carrying-dependency attribution (slice A2a) ---------------
    def _local_dependency_index(
        self, root: Path, deps: dict[str, str], pkg: dict | None
    ) -> list[_LocalDep]:
        """Index the app's declared local-path / workspace dependencies (§S1.3, A2a).

        These are the *bundled first-party* packages whose OWN source is ingested this
        engagement (unlike a registry dependency, whose source lives under the skipped
        ``node_modules``). A sink whose file lives under one of these directories is
        library-borne and keyed on that package. The app's own tree is never indexed, so
        an app-code sink stays fingerprint-keyed. Deterministic (path + each package's own
        ``package.json`` — no install/resolution), bounded, deepest-directory-first so a
        nested package wins attribution.
        """
        if not root.is_dir():
            return []
        index: dict[Path, _LocalDep] = {}
        for name, spec in deps.items():
            directory = self._resolve_local_spec(root, spec)
            if directory is not None:
                dep = self._read_local_package(directory, name)
                if dep is not None:
                    index.setdefault(dep.directory, dep)
            if len(index) >= _MAX_LOCAL_DEPS:
                break
        for pattern in self._workspace_patterns(pkg):
            for directory in self._resolve_workspace_glob(root, pattern):
                if len(index) >= _MAX_LOCAL_DEPS:
                    break
                dep = self._read_local_package(directory, "")
                if dep is not None:
                    index.setdefault(dep.directory, dep)
        return sorted(index.values(), key=lambda d: len(str(d.directory)), reverse=True)

    @staticmethod
    def _resolve_local_spec(root: Path, spec: str) -> Path | None:
        """A local-path dependency spec → its resolved directory, or ``None``.

        ``file:./pkg`` / ``link:../pkg`` / ``portal:pkg`` and a bare relative/absolute path
        are local; an npm-registry range (``^1.2.3``) is not (returns ``None``).
        """
        if not isinstance(spec, str):
            return None
        spec = spec.strip()
        raw = ""
        for prefix in _LOCAL_SPEC_PREFIXES:
            if spec.startswith(prefix):
                raw = spec[len(prefix) :].strip()
                break
        else:
            if spec.startswith(("./", "../", "/")):
                raw = spec
        if not raw:
            return None
        try:
            return (root / raw).resolve()
        except (OSError, ValueError):
            return None

    def _read_local_package(self, directory: Path, fallback_name: str) -> _LocalDep | None:
        """A local package directory → its ``(directory, name, version)`` identity, or None.

        Name/version come from the package's OWN ``package.json``; when that manifest is
        absent but the directory and a declared name exist (the *source-withheld* case —
        fixture-B), the dependency is still indexed with an empty version so it remains
        recall-observable as a technology identity.
        """
        try:
            if not directory.is_dir():
                return None
            pkg_path = directory / "package.json"
            if not pkg_path.exists() or pkg_path.stat().st_size > _MAX_MANIFEST_BYTES:
                if fallback_name:
                    return _LocalDep(directory=directory, name=fallback_name, version="")
                return None
            data = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            logger.warning("js source ingest: cannot read local package %s: %s", directory, exc)
            return None
        if not isinstance(data, dict):
            return None
        name = str(data.get("name") or fallback_name or "")
        if not name:
            return None
        return _LocalDep(directory=directory, name=name, version=str(data.get("version") or ""))

    @staticmethod
    def _workspace_patterns(pkg: dict | None) -> list[str]:
        """The ``workspaces`` globs declared in package.json (array or ``{packages:[…]}``)."""
        if not pkg:
            return []
        workspaces = pkg.get("workspaces")
        if isinstance(workspaces, list):
            return [str(p) for p in workspaces if isinstance(p, str)]
        if isinstance(workspaces, dict):
            packages = workspaces.get("packages")
            if isinstance(packages, list):
                return [str(p) for p in packages if isinstance(p, str)]
        return []

    @staticmethod
    def _resolve_workspace_glob(root: Path, pattern: str) -> list[Path]:
        """Resolve a workspace glob to package directories that carry a ``package.json``."""
        directories: list[Path] = []
        try:
            for match in root.glob(pattern):
                if any(part in _SKIP_DIRS for part in match.parts):
                    continue
                if match.is_dir() and (match / "package.json").exists():
                    directories.append(match.resolve())
        except (OSError, ValueError):
            return []
        return directories

    @staticmethod
    def _attribute_carrying_dependency(file: str, dep_index: list[_LocalDep]) -> tuple[str, str]:
        """The ``(dependency, version)`` for a library-borne sink, else ``("", "")``.

        Deterministic: the sink's resolved path is tested against each indexed dependency
        directory (deepest first), so a sink in ``packages/vuln-lib/index.js`` is
        attributed to ``vuln-lib`` while a sink in the app's own ``routes/`` / ``src/``
        tree matches no dependency directory and stays fingerprint-keyed (§S1.3 — the
        app-level case must NOT become library-transferable).
        """
        if not dep_index or not file:
            return "", ""
        try:
            resolved = Path(file).resolve()
        except (OSError, ValueError):
            return "", ""
        for dep in dep_index:
            if resolved == dep.directory or resolved.is_relative_to(dep.directory):
                return dep.name, dep.version
        return "", ""

    def _carrying_dependency(
        self, used_egress_libs: set[str], deps: dict[str, str], root: Path
    ) -> tuple[str, str]:
        """The model-level ``(technology_key, observed_version)`` for the manifest note.

        Prefer the HTTP-client library an ``EGRESS_FETCH`` actually used and the app
        bundled (the capability's carrying dependency), then the backend framework;
        version resolved from the lockfile if present, else the package.json spec.

        This is the MODEL-level manifest key (used for the ``bundles`` transfer edges and
        the ``LOG_INTERPOLATION`` fact key). It is deliberately NOT the EGRESS_FETCH /
        FILE_READ fact key — those are keyed *per sink* by
        :meth:`_attribute_carrying_dependency`, so an app-code sink that merely *calls* a
        library (Juice Shop's ``fetch``-based SSRF) is never mis-keyed on that library
        and falsely transferred (slice A2a).
        """
        for lib in _EGRESS_LIB_PRIORITY:
            if lib in used_egress_libs and lib in deps:
                return lib, self._resolve_version(lib, deps[lib], root)
        for framework in _BACKEND_FRAMEWORKS:
            if framework in deps:
                return framework, self._resolve_version(framework, deps[framework], root)
        return "", ""

    @staticmethod
    def _read_package_json(root: Path) -> dict | None:
        """Parse the nearest ``package.json`` (root, else first found), bounded; None on miss."""
        search_root = root if root.is_dir() else root.parent
        candidate = search_root / "package.json"
        paths: list[Path] = []
        if candidate.exists():
            paths.append(candidate)
        else:
            for path in search_root.rglob("package.json"):
                if any(part in _SKIP_DIRS for part in path.parts):
                    continue
                paths.append(path)
                break
        for path in paths:
            try:
                if path.stat().st_size > _MAX_MANIFEST_BYTES:
                    continue
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError) as exc:
                logger.warning("js source ingest: cannot parse %s: %s", path, exc)
                continue
            if isinstance(data, dict):
                return data
        return None

    def _resolve_version(self, name: str, spec: str, root: Path) -> str:
        """Resolve *name*'s observed point version — lockfile first, then the spec."""
        locked = self._lockfile_version(name, root)
        if locked:
            return locked
        match = _RE_VERSION_POINT.search(spec or "")
        return match.group(1) if match else ""

    @staticmethod
    def _lockfile_version(name: str, root: Path) -> str:
        """The resolved version of *name* from ``package-lock.json`` (v1/v2/v3), or ``""``."""
        search_root = root if root.is_dir() else root.parent
        lock = search_root / "package-lock.json"
        if not lock.exists():
            return ""
        try:
            if lock.stat().st_size > _MAX_MANIFEST_BYTES:
                return ""
            data = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return ""
        if not isinstance(data, dict):
            return ""
        packages = data.get("packages")
        if isinstance(packages, dict):
            entry = packages.get(f"node_modules/{name}")
            if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                return entry["version"]
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            entry = dependencies.get(name)
            if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                return entry["version"]
        return ""
