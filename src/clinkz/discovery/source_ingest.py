"""Source Ingestion → :class:`SourceModel` (§2.2).

A deterministic, **regex / bounded-scan-only** ingestor (never ``eval``, bounded
file count + bytes, source treated as untrusted data) — the same discipline as
``agents/_route_discovery.py``.

Slice 1 (GeoServer) targeted a single shape: an ``HttpServlet`` whose ``doGet``/
``doPost`` reads ``request.getParameter("url")`` and calls ``url.openConnection()``
**in the same handler**. Slice 2 (the transfer slice) generalizes the ingestor so
the *same* deterministic pass also surfaces a second, differently-shaped Java
fetch channel — Apache Solr's ``stream.url`` (`Remote-Streaming-Fileread`) — with
**no Solr-specific literal** in the code. Every Solr particular (`stream.url`,
`URLStream`) is *learned from Solr's own source*, never hardcoded. Three general
idioms carry the transfer:

  1. **Entrypoints are not only servlets.** A function that reads a request
     parameter is an entrypoint, whether via ``request.getParameter("x")``
     (servlet) or a request-param *bag* (``params.get(NAME)`` /
     ``params.getParams(NAME)`` — Solr ``SolrParams``, Spring, …).
  2. **Param names resolve through symbolic constants.**
     ``params.getParams(CommonParams.STREAM_URL)`` → the constant
     ``STREAM_URL = "stream.url"`` is resolved from the ingested source (a
     bounded, cross-file constant map). GeoServer's string-literal param names
     are the degenerate case.
  3. **Egress sinks include cross-class URL-fetch wrappers.** A class whose body
     opens a ``URLConnection`` (`.openConnection()`/`.openStream()`) is an
     *egress-fetch wrapper type*; ``new Wrapper(new URL(attacker))`` in an
     entrypoint is then an ``EGRESS_FETCH`` call site tainted by the attacker
     param — the Solr ``new ContentStreamBase.URLStream(new URL(url))`` shape,
     where the literal ``openConnection`` lives one class away. GeoServer's
     direct ``u.openConnection()`` is the in-handler case, unchanged.

A **second capability class** (file read, Flink CVE-2020-17519) reuses the SAME
two-pass ingestor with three additional general Java idioms — the sink shape and
its channel differ, the machinery does not (it extends, it does not fork):

  4. **Typed request PATH parameters are entrypoints.** ``getPathParameter(
     Xxx.class)`` reads an untrusted URL path segment; the class resolves to its
     wire name via a ``KEY`` constant (pass-1 registry), and the mounted route
     (``/jobmanager/logs/:filename``) is learned from a ``String.format("/…:%s",
     Xxx.KEY)`` route builder — no route/param literal in the logic (JAX-RS
     ``@PathParam`` / Spring ``@PathVariable`` are the same typed-path-param shape).
  5. **File-read sinks.** A request-tainted path reaching ``new File(dir, name)`` /
     ``new FileInputStream(name)`` / ``Files.read*(name)`` is a ``FILE_READ`` call
     site — the arbitrary-file-read analogue of the egress ``openConnection`` sink.
  6. **Basename-strip / canonicalize guards.** ``new File(pathParam).getName()`` /
     ``getCanonicalPath`` / ``normalize`` applied to the tainted path before the
     sink is the file-read analogue of the host-check guard: its presence marks the
     value sanitized (Intent → SANCTIONED, Δ removed); its ABSENCE is the intent-gap
     (EXPOSED) — exactly the missing ``.getName()`` Flink's fix added.

A **third capability class** (Log4Shell log-sink egress, CVE-2021-44228) adds two
more general idioms — the sink is a *logging call* and the capability is gated on a
*build manifest*, not intra-function taint:

  7. **Logging calls are sinks.** An SLF4J/Log4j logging call
     (``log(ger)?.(trace|debug|info|warn|error|fatal)(…)`` — incl. Solr's
     ``log().info(…)`` accessor) whose argument is request-derived (a tainted var,
     a request-param-bag read ``req.getParams()``/``getParameterMap()``, or a
     direct ``getParameter``/``getHeader``/``getQueryString`` accessor) is a
     ``LOG_INTERPOLATION`` call site. The channel→sink path is *not* required to be
     intra-function (the reachability layer grades it heuristic), so the sink is a
     coarse "request reaches a logger" fact — exactly the Log4Shell shape where the
     interpolation happens deep inside log4j-core (design §P6.5.3).
  8. **Manifest-derived, version-gated capability.** A vulnerable ``log4j-core``
     (< 2.15.0, JNDI message-lookups un-gated) declared in a build manifest
     (``pom.xml`` ``<version>``, a gradle/ivy coordinate ``…:log4j-core:2.14.1``)
     or a shipped-jar filename (``log4j-core-2.14.1.jar``) emits the
     :data:`~clinkz.discovery.constants.LOG4J_VULNERABLE_TOKEN` into
     ``SourceModel.technologies`` — the token the LOG_INTERPOLATION catalog
     primitive matches on. The version is learned from the manifest; a patched
     line (≥ 2.15) emits no token ⇒ the primitive is not active ⇒ N/A by
     construction (design §P6.5.2 version-gating).

It stays deliberately shallow: single-language (Java), pattern-based, bounded —
not a whole-program analyzer. Cross-function / cross-service reachability beyond
the wrapper + heuristic-log-sink cases remains the next slice.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from clinkz.discovery.constants import LOG4J_VULNERABLE_TOKEN
from clinkz.discovery.models import (
    CallSite,
    CoverageGrade,
    Entrypoint,
    Guard,
    PrimitiveClass,
    SourceModel,
)
from clinkz.discovery.versions import parse_version

logger = logging.getLogger(__name__)

# --- Ingestion bounds (source is untrusted; never unbounded) ----------------
_MAX_FILES = 2000
_MAX_FILE_BYTES = 512 * 1024

# --- Class / handler shapes -------------------------------------------------
_RE_SERVLET_CLASS = re.compile(r"\bclass\s+(\w+)\s+extends\s+HttpServlet\b")
_RE_ANY_CLASS = re.compile(r"\b(?:class|interface)\s+(\w+)")
_RE_HANDLER = re.compile(
    r"\b(?:protected|public)\s+void\s+(doGet|doPost|service|processRequest)\s*\("
)

# --- Request-parameter reads (the untrusted channel) ------------------------
# A named reference is either a "string literal" or a symbolic Foo.BAR constant.
_NAMEREF = r'(?:"[^"]+"|[A-Za-z_][\w.]*)'
# A trailing ``, <default>`` arg many param-bag getters accept (Solr's
# ``params.get(ACTION, STATUS.toString())`` / ``Properties.getProperty(k, d)``): the
# first arg is the param NAME, the rest is a default we ignore. ``[^)]*`` stops at
# the first ``)`` so a defaulted read still captures its name (bounded, no nesting).
_OPT_DEFAULT = r"(?:,[^)]*)?"
# Servlet: request.getParameter("p")
_RE_GET_PARAM = re.compile(r'getParameter\(\s*"([^"]+)"\s*\)')
# Param-bag scalar read: params.get(NAME) / params.get(NAME, default) — the String
# form (NOT getParams()).
_RE_PARAM_BAG_GET = re.compile(rf"\.get\(\s*({_NAMEREF})\s*{_OPT_DEFAULT}\)")
# Param-bag array read: params.getParams(NAME) — the String[] form.
_RE_PARAM_BAG_GETPARAMS = re.compile(rf"\.getParams\(\s*({_NAMEREF})\s*{_OPT_DEFAULT}\)")
# ``var = ...getParameter("p")`` — a request parameter bound to a local.
_RE_VAR_FROM_PARAM = re.compile(r'(\w+)\s*=\s*[^;]*?getParameter\(\s*"([^"]+)"\s*\)')
# ``var = ...params.get(NAME[, default])`` — scalar bag read bound to a local.
_RE_VAR_FROM_BAG_GET = re.compile(rf"(\w+)\s*=\s*[^;]*?\.get\(\s*({_NAMEREF})\s*{_OPT_DEFAULT}\)")
# ``var = ...params.getParams(NAME)`` — array bag read bound to a local.
_RE_VAR_FROM_BAG_GETPARAMS = re.compile(
    rf"(\w+)\s*=\s*[^;]*?\.getParams\(\s*({_NAMEREF})\s*{_OPT_DEFAULT}\)"
)
# ``for (Type elem : coll)`` — a foreach element bound to a collection.
_RE_FOR_EACH = re.compile(r"for\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)")

# --- URL construction + egress sinks ----------------------------------------
# ``var = new URL(arg)`` — capture the constructor argument (a var or an expr).
_RE_VAR_FROM_NEWURL = re.compile(r"(\w+)\s*=\s*new\s+URL\(\s*([^)]+?)\s*\)")
# ``var.openConnection()`` — the direct in-handler fetch (GeoServer).
_RE_OPEN_CONNECTION = re.compile(r"(\w+)\.openConnection\(\s*\)")
# ``new Wrapper( new URL( arg ) )`` — a URL fetched via a wrapper class (Solr).
_RE_NEW_URL_IN_CTOR = re.compile(r"new\s+([\w.]+)\s*\(\s*new\s+URL\(\s*([^)]+?)\s*\)")
# A URL-fetch call anywhere in a class body ⇒ that class is an egress wrapper.
_RE_URL_FETCH = re.compile(r"\.(?:openConnection|openStream)\s*\(")

# --- File-read sinks + path-parameter channel (the SECOND capability class) --
# A typed request PATH-parameter read: ``getPathParameter(Xxx.class)`` (Flink's
# framework idiom; JAX-RS ``@PathParam`` / Spring ``@PathVariable`` are the same
# shape). The class simple name resolves to the wire param name via its ``KEY``
# constant (pass-1 registry). ``var = ...getPathParameter(Xxx.class)...`` binds the
# request path param to a local, so the sink taint traces back to it.
_RE_PATH_PARAM_READ = re.compile(r"getPathParameter\(\s*(\w+)\.class\s*\)")
_RE_VAR_FROM_PATHPARAM = re.compile(
    r"(\w+)\s*=\s*([^;]*?getPathParameter\(\s*(\w+)\.class\s*\)[^;]*)"
)
# File-read sinks: the request-tainted path becomes the file name/path. Captures
# the (last / sole) constructor or reader argument — a bare local var, which the
# taint map then resolves to a request param. Covers ``new File(dir, name)`` /
# ``new File(name)``, ``new FileInputStream(name)`` / ``new RandomAccessFile(name,
# ...)``, and ``Files.<read>(name)``. Deliberately literal-free: no path, no
# param, no framework name is baked in.
_RE_FILE_SINK = re.compile(
    r"new\s+File\s*\(\s*(?:[^,()]+,\s*)?(\w+)\s*\)"
    r"|new\s+(?:FileInputStream|FileReader)\s*\(\s*(\w+)\s*\)"
    r"|new\s+RandomAccessFile\s*\(\s*(\w+)\s*,"
    r"|\bFiles\.(?:readAllBytes|readAllLines|lines|readString|newInputStream|newBufferedReader)"
    r"\s*\(\s*(\w+)\b"
)
# A basename-strip / canonicalization guard applied to the tainted path *before*
# it reaches the sink — the file-read analogue of the egress host-check guard, and
# exactly the fix Flink shipped (``new File(pathParam).getName()``). Its presence
# in the tainting assignment marks the value sanitized ⇒ Intent reads SANCTIONED
# (Δ removed). Absence ⇒ the intent-gap (EXPOSED).
_RE_PATH_SANITIZER = re.compile(
    r"\.getName\(\s*\)|getCanonicalPath|getCanonicalFile|\.normalize\(\s*\)|toRealPath"
    r"|FilenameUtils\.getName"
)
# Symbol recorded for a detected basename-strip/canonicalize guard.
_FILE_READ_GUARD_SYMBOL = "path_basename_strip"

# ``public static final String KEY = "filename"`` inside a path-parameter class —
# the wire name a ``getPathParameter(Xxx.class)`` read resolves to. Restricted to
# the ``KEY`` field (the idiomatic path-param key name), scanned per class body so
# each param class maps to its own key.
_RE_KEY_CONST = re.compile(r'\bString\s+KEY\s*=\s*"([^"]+)"')
# ``String.format("/route/:%s", Xxx.KEY)`` — a REST route built from a path-param
# key. The literal (``/jobmanager/logs/:%s``) + the resolved key give the concrete
# route (``/jobmanager/logs/:filename``). No route string is hardcoded.
_RE_ROUTE_FORMAT = re.compile(r'String\.format\(\s*"(/[^"]*%s[^"]*)"\s*,\s*(\w+)\.KEY\s*\)')
# A plain route literal already carrying a ``:name`` placeholder (the degenerate
# case where the framework writes the route out in full).
_RE_ROUTE_LITERAL = re.compile(r'"(/[^"]*:(\w+)[^"]*)"')

# --- Logging-call sinks (the Log4Shell LOG_INTERPOLATION class) --------------
# An SLF4J/Log4j logging call: ``log.info(…)`` / ``logger.warn(…)`` / Solr's
# ``log().info(…)`` accessor. Case-tolerant on the receiver (``log`` / ``LOG`` /
# ``logger``); the match ends at the opening ``(`` so the argument slice is read by
# a bounded balanced-paren scan. Literal-free — no framework/message string baked in.
_RE_LOG_CALL = re.compile(
    r"\b(?:log|logger)\s*(?:\(\s*\))?\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\(",
    re.IGNORECASE,
)
# ``var = …req.getParams()`` / ``getParameterMap()`` / ``getParameterValues()`` —
# a local bound to the WHOLE untrusted request param bag (Solr's ``SolrParams
# params = it.req.getParams()``). Any request param — incl. ``action`` — rides in
# it, so logging it is the log-sink channel. Broader than the named-scalar
# ``_RE_VAR_FROM_BAG_GET`` (which needs a ``.get(NAME)``).
_RE_REQUEST_BAG_VAR = re.compile(
    r"(\w+)\s*=\s*[^;]*?\.(?:getParams|getParameterMap|getParameterValues|getParameterNames)\s*\("
)
# A direct untrusted-request accessor appearing INSIDE a logging call's arguments —
# the request is logged without being bound to a local first.
_RE_REQUEST_ACCESSOR = re.compile(
    r"\.(?:getParams|getParameterMap|getParameterValues|getParameter|getQueryString"
    r"|getRequestURI|getRequestURL|getHeader|getPathInfo)\s*\("
)
# Symbol recorded for a LOG_INTERPOLATION (log-sink) call site.
_LOG_SINK_SYMBOL = "log_interpolation"

# Stable sink-shape ids — the recognizer's fixed Layer-2 vocabulary (design §1.3 /
# §S1.3). A *tag on already-existing detection* the capability-learning write-back
# keys a fact on; growing this set means teaching a NEW source idiom, exactly like
# growing the Layer-1 oracles.
_SINK_SHAPE_EGRESS = "java.url_openconnection"
_SINK_SHAPE_FILE_READ = "java.file_sink"
_SINK_SHAPE_LOG = "log4j.log_sink"
# Coarse taint marker for a log sink whose logged value is the whole request (not a
# single named param) — the reachability layer connects it to entrypoint params by
# the heuristic prior, so the exact bag var name is not load-bearing.
_LOG_SINK_COARSE_TAINT = "*request*"
# Bounded window (chars) scanned for a logging call's balanced argument list.
_MAX_LOG_ARGS_SCAN = 600

# --- Manifest capability (log4j-core version → JNDI lookup egress) -----------
# The vulnerable-log4j threshold: message-lookup JNDI egress is un-gated below
# 2.15.0; 2.15+ restricts it, 2.16+/JndiLookup-removed disables it (design §P6.5.2).
_LOG4J_SAFE_VERSION: tuple[int, int, int] = (2, 15, 0)
# The carrying dependency the Layer-2 capability fact is keyed on (design §2.4):
# Log4Shell is a property of log4j-core, so any app that bundles it inherits the
# capability. Recognizer vocabulary, not a target literal.
_LOG4J_TECHNOLOGY_KEY = "log4j-core"
# Manifest filenames worth reading for a declared log4j-core version (bounded).
_MANIFEST_NAMES: tuple[str, ...] = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "ivy.xml",
    "ivy-versions.properties",
    "versions.props",
    "versions.lock",
    "gradle.properties",
    "libs.versions.toml",
    "dependencies.txt",
    "MANIFEST.MF",
)
# A shipped-jar / license-sha1 filename embeds the exact version (Solr ships
# ``log4j-core-2.14.1.jar.sha1``): the distribution's own manifest.
_RE_LOG4J_JAR = re.compile(r"log4j-core-(\d+\.\d+(?:\.\d+)?)\.jar", re.IGNORECASE)
# A gradle / ivy coordinate: ``org.apache.logging.log4j:log4j-core:2.14.1`` (``:``
# or a slashed ivy path). Version captured directly.
_RE_LOG4J_COORD = re.compile(
    r"org\.apache\.logging\.log4j[:/]log4j-core[:/](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE
)
# A Maven POM ``<artifactId>log4j-core</artifactId>`` whose version is the nearest
# following ``<version>…</version>`` (bounded forward window).
_RE_LOG4J_POM_ARTIFACT = re.compile(r"log4j-core\s*</artifactId>", re.IGNORECASE)
_RE_POM_VERSION = re.compile(r"<version>\s*(\d+\.\d+(?:\.\d+)?)\s*</version>", re.IGNORECASE)
# Max chars to look ahead from a POM artifactId for its version element.
_MAX_POM_VERSION_LOOKAHEAD = 240

# --- Constants (route + param-name resolution) ------------------------------
# ``[static] [final] String NAME = "value"`` incl. interface constants
# (``String STREAM_URL = "stream.url"`` — no modifiers). Restricted to
# UPPER_SNAKE names so method-local ``String x = "y"`` locals never pollute the map.
_RE_STRING_CONST = re.compile(r'\bString\s+([A-Z][A-Z0-9_]{2,})\s*=\s*"([^"]+)"')
_RE_SERVLET_PATH_CHECK = re.compile(r"getServletPath\(\s*\)\.equals\(\s*(\w+)\s*\)")

# --- Attacker-controlled vs config-controlled request sources ---------------
_RE_VAR_FROM_REQUEST = re.compile(
    r"(\w+)\s*=\s*[^;]*?request\."
    r"(getRequestURL|getHeader|getServerName|getParameter|getQueryString|getRequestURI)\b"
)
_RE_VAR_FROM_CONFIG = re.compile(
    r"(\w+)\s*=\s*[^;]*?(getProxyBaseUrl|getProxyBaseURL|getSettings|getGlobal|getConfig)\b"
)
# ``X.getHost().equals(Y.getHost())`` — a host-equality guard comparison.
_RE_HOST_COMPARE = re.compile(r"(\w+)\.getHost\(\)\.equals\(\s*(\w+)\.getHost\(\)\s*\)")
# A validation/guard helper invoked with the request (the sink's nearby guard).
_RE_GUARD_CALL = re.compile(r"\b(validate\w*|check\w*)\s*\(\s*request\b")


def _line_of(text: str, index: int) -> int:
    """1-based line number of *index* within *text*."""
    return text.count("\n", 0, index) + 1


def _resolve_param_name(nameref: str, const_map: dict[str, str]) -> str | None:
    """Resolve a param-name reference to its wire name.

    A ``"literal"`` yields itself; a symbolic ``Foo.BAR`` (or bare ``BAR``) is
    resolved by simple name through *const_map* (built from the ingested source).
    Returns ``None`` when a symbolic name cannot be resolved from source.
    """
    nameref = nameref.strip()
    if nameref.startswith('"'):
        return nameref.strip('"')
    simple = nameref.split(".")[-1]
    return const_map.get(simple)


def _balanced_arg_slice(text: str, open_index: int, max_scan: int = _MAX_LOG_ARGS_SCAN) -> str:
    """Return the substring inside the balanced parens starting at *open_index*.

    Bounded (never unbounded over untrusted source); returns ``""`` if *open_index*
    is not a ``(`` or the parens do not balance within *max_scan* chars.
    """
    if open_index >= len(text) or text[open_index] != "(":
        return ""
    depth = 0
    end = min(len(text), open_index + max_scan)
    for i in range(open_index, end):
        char = text[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : i]
    return ""


def _identifier_in(ident: str, text: str) -> bool:
    """Whether *ident* appears as a whole-word identifier (not a field-access tail)."""
    if not ident:
        return False
    return re.search(rf"(?<![\w.]){re.escape(ident)}\b", text) is not None


def _parse_semver(raw: str) -> tuple[int, int, int] | None:
    """Parse ``X`` / ``X.Y`` / ``X.Y.Z`` into a 3-tuple; ``None`` if non-numeric.

    Delegates to the shared :func:`~clinkz.discovery.versions.parse_version` idiom
    (the tuple-compare the Layer-2 predicate matcher is built on) so the manifest
    gate and the recall matcher parse versions identically.
    """
    return parse_version(raw)


class JavaSourceIngestor:
    """Ingest a Java source tree into a :class:`SourceModel` (bounded, no eval)."""

    def ingest_path(self, root: str | Path) -> SourceModel:
        """Ingest every ``*.java`` under *root* (bounded), returning a SourceModel.

        Two deterministic passes. Pass 1 builds the cross-file facts an entrypoint
        file may depend on — the constant map (symbolic param names), the set of
        egress-fetch wrapper types (classes that open a ``URLConnection``), the
        path-parameter key registry (``Xxx.class`` → wire name via its ``KEY``
        constant) and the REST route registry (path-param class → mounted route).
        Pass 2 extracts entrypoints / call sites / guards from each **entrypoint**
        file (a file that reads a request parameter — query, form-bag, or typed
        path parameter), resolving names, wrappers and routes against the pass-1
        facts. Non-entrypoint library files (a wrapper's / route-header's / param's
        own defining file) contribute only pass-1 facts — never a stray entrypoint.
        """
        root = Path(root)
        model = SourceModel()
        if not root.exists():
            logger.warning("source ingest: path does not exist: %s", root)
            return model

        files = sorted(root.rglob("*.java")) if root.is_dir() else [root]
        texts: list[tuple[str, str]] = []
        const_map: dict[str, str] = {}
        wrapper_types: set[str] = set()
        pathparam_keys: dict[str, str] = {}
        for path in files[:_MAX_FILES]:
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("source ingest: cannot read %s: %s", path, exc)
                continue
            texts.append((str(path), text))
            const_map.update({m.group(1): m.group(2) for m in _RE_STRING_CONST.finditer(text)})
            wrapper_types |= self._discover_egress_wrapper_types(text)
            pathparam_keys.update(self._discover_pathparam_keys(text))

        # Route registry needs the full path-param-key map (routes reference param
        # classes across files), so resolve it after pass 1 completes.
        route_by_pathparam: dict[str, str] = {}
        for _file, text in texts:
            route_by_pathparam.update(self._discover_pathparam_routes(text, pathparam_keys))

        saw_servlet = False
        for file, text in texts:
            if self._ingest_text(
                text, file, model, const_map, wrapper_types, pathparam_keys, route_by_pathparam
            ):
                if _RE_SERVLET_CLASS.search(text):
                    saw_servlet = True

        model.files_ingested = len(texts)
        if model.call_sites:
            model.coverage_grade = CoverageGrade.PARTIAL
        if model.entrypoints:
            model.technologies = ["Java", "Java Servlet"] if saw_servlet else ["Java"]
        # Manifest capability (Log4Shell class): a declared vulnerable log4j-core
        # (< 2.15) arms the LOG_INTERPOLATION primitive by emitting its match token.
        # A patched line emits nothing ⇒ the primitive is not active (N/A). Read
        # only when a log sink was actually found — no manifest scan cost otherwise.
        if any(cs.primitive_class is PrimitiveClass.LOG_INTERPOLATION for cs in model.call_sites):
            vulnerable, manifest_evidence, observed_version = self._scan_log4j_manifest(root)
            if vulnerable:
                model.technologies.append(LOG4J_VULNERABLE_TOKEN)
                model.manifest_evidence = manifest_evidence
                model.manifest_technology_key = _LOG4J_TECHNOLOGY_KEY
                model.manifest_observed_version = observed_version
        logger.info(
            "source ingest: %d files → %d entrypoints, %d call-sites, %d guards "
            "(%d consts, %d wrappers, %d path-param keys, %d routes) manifest=%s",
            len(texts),
            len(model.entrypoints),
            len(model.call_sites),
            len(model.guards),
            len(const_map),
            len(wrapper_types),
            len(pathparam_keys),
            len(route_by_pathparam),
            model.manifest_evidence or "(none)",
        )
        return model

    @staticmethod
    def _discover_egress_wrapper_types(text: str) -> set[str]:
        """Class names in *text* whose body performs a URL fetch (egress wrapper).

        For each ``class``/``interface`` declaration, the body slice up to the next
        declaration is scanned for a ``.openConnection()`` / ``.openStream()`` call;
        a match registers the class simple name as an egress-fetch wrapper. This is
        how ``ContentStreamBase.URLStream`` is *learned* to be a fetch type from
        Solr's own source (its ``getStream()`` calls ``url.openConnection()``),
        while its sibling ``FileStream`` / ``StringStream`` — which do not open a
        connection — are correctly not registered.
        """
        wrappers: set[str] = set()
        decls = list(_RE_ANY_CLASS.finditer(text))
        for i, m in enumerate(decls):
            start = m.end()
            end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
            if _RE_URL_FETCH.search(text, start, end):
                wrappers.add(m.group(1))
        return wrappers

    @staticmethod
    def _discover_pathparam_keys(text: str) -> dict[str, str]:
        """Path-parameter classes in *text* → their wire key (``KEY`` constant).

        For each ``class``/``interface`` declaration, the body slice up to the next
        declaration is scanned for ``String KEY = "<wire>"``; a match maps the class
        simple name to ``<wire>``. This is how ``LogFileNamePathParameter`` is
        *learned* to carry the wire name ``filename`` from Flink's own source, so a
        ``getPathParameter(LogFileNamePathParameter.class)`` read one class away
        resolves to ``filename`` — the typed-path-param analogue of Solr's symbolic
        ``CommonParams.STREAM_URL`` resolution. No param name is hardcoded.
        """
        keys: dict[str, str] = {}
        decls = list(_RE_ANY_CLASS.finditer(text))
        for i, m in enumerate(decls):
            start = m.end()
            end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
            km = _RE_KEY_CONST.search(text, start, end)
            if km:
                keys[m.group(1)] = km.group(1)
        return keys

    @staticmethod
    def _discover_pathparam_routes(text: str, pathparam_keys: dict[str, str]) -> dict[str, str]:
        """Path-parameter class → its concrete mounted route, learned from source.

        Two general REST-route idioms, both literal-free:

          * ``String.format("/jobmanager/logs/:%s", LogFileNamePathParameter.KEY)``
            — the route template's ``%s`` is filled by the resolved param key,
            giving ``/jobmanager/logs/:filename`` (Flink's route builder).
          * a plain literal already carrying a ``:name`` placeholder whose ``name``
            is a known path-param key — the degenerate case where the route is
            written out in full.

        Both map the *param class* → route so a handler that reads
        ``getPathParameter(Xxx.class)`` in another file resolves its mounted path.
        """
        routes: dict[str, str] = {}
        for m in _RE_ROUTE_FORMAT.finditer(text):
            template, param_class = m.group(1), m.group(2)
            wire = pathparam_keys.get(param_class)
            if wire is not None:
                routes[param_class] = template.replace("%s", wire, 1)
        if pathparam_keys:
            key_to_class = {v: k for k, v in pathparam_keys.items()}
            for m in _RE_ROUTE_LITERAL.finditer(text):
                route_literal, placeholder = m.group(1), m.group(2)
                cls = key_to_class.get(placeholder)
                if cls is not None:
                    routes.setdefault(cls, route_literal)
        return routes

    def _ingest_text(
        self,
        text: str,
        file: str,
        model: SourceModel,
        const_map: dict[str, str],
        wrapper_types: set[str],
        pathparam_keys: dict[str, str],
        route_by_pathparam: dict[str, str],
    ) -> bool:
        """Extract entrypoint / call sites / guard from one file. Returns ingested?

        A file is an **entrypoint file** only if it reads a request parameter —
        servlet ``getParameter``, a param-bag ``get``/``getParams``, or a typed
        ``getPathParameter(Xxx.class)`` (the file-read class's path channel). Files
        that merely *define* a wrapper, constants or route headers (Solr's
        ``ContentStreamBase`` / ``CommonParams``, Flink's ``JobManagerCustomLog
        Headers`` / ``LogFileNamePathParameter``) contribute only pass-1 facts and
        are skipped here.
        """
        has_param_read = bool(
            _RE_GET_PARAM.search(text)
            or _RE_PARAM_BAG_GET.search(text)
            or _RE_PARAM_BAG_GETPARAMS.search(text)
            or _RE_PATH_PARAM_READ.search(text)
        )
        if not has_param_read:
            return False

        servlet_match = _RE_SERVLET_CLASS.search(text)
        any_class = _RE_ANY_CLASS.search(text)
        handler_symbol = (
            servlet_match.group(1)
            if servlet_match
            else (any_class.group(1) if any_class else "handler")
        )

        var_to_param = self._build_taint_map(text, const_map)
        var_to_urlarg = {m.group(1): m.group(2).strip() for m in _RE_VAR_FROM_NEWURL.finditer(text)}
        attacker_vars = {m.group(1) for m in _RE_VAR_FROM_REQUEST.finditer(text)}
        config_vars = {m.group(1) for m in _RE_VAR_FROM_CONFIG.finditer(text)}

        # File-read (path-traversal) taint: local var → wire path-param name, plus
        # the set of vars whose tainting assignment basename-stripped/canonicalized
        # the path (sanitized), and the path-param classes read here.
        path_taint, sanitized_path_vars, read_classes = self._build_path_taint_map(
            text, pathparam_keys
        )

        guard = self._extract_guard(
            text, file, attacker_vars, config_vars, var_to_urlarg, var_to_param
        )
        if guard:
            model.guards.append(guard)

        call_sites = self._extract_egress_call_sites(
            text, file, var_to_param, var_to_urlarg, wrapper_types, guard.symbol if guard else None
        )

        file_read_sites, need_sanitize_guard = self._extract_file_read_call_sites(
            text, file, path_taint, sanitized_path_vars, var_to_param
        )
        if need_sanitize_guard:
            model.guards.append(self._path_sanitize_guard(text, file))
        log_sites = self._extract_log_call_sites(text, file, var_to_param, attacker_vars)
        model.call_sites.extend(call_sites)
        model.call_sites.extend(file_read_sites)
        model.call_sites.extend(log_sites)

        # Route: a typed-path-param handler resolves its mounted route from the
        # pass-1 route registry (via the param class it reads); a servlet resolves
        # from its own path constant; otherwise the operator's base URL carries it.
        path_route = next(
            (route_by_pathparam[c] for c in read_classes if c in route_by_pathparam), ""
        )
        route = path_route or (self._resolve_route(text, handler_symbol) if servlet_match else "")

        path_params = [wire for c in read_classes if (wire := pathparam_keys.get(c)) is not None]
        params = self._ordered_params(text, const_map)
        for wire in path_params:
            if wire not in params:
                params.append(wire)

        methods = sorted({m.group(1) for m in _RE_HANDLER.finditer(text)} & {"doGet", "doPost"})
        http_methods: list[str] = []
        if "doGet" in methods:
            http_methods.append("GET")
        if "doPost" in methods:
            http_methods.append("POST")
        if not http_methods:
            # A non-servlet param-bag / path-param entrypoint (shared request
            # parser, Flink REST handler) is reached by a GET on its route.
            http_methods = ["GET"]
        model.entrypoints.append(
            Entrypoint(
                route=route,
                http_methods=http_methods,
                handler_symbol=handler_symbol,
                params=params,
                path_params=path_params,
                file=file,
                line=_line_of(text, (servlet_match or any_class or _RE_GET_PARAM).start())
                if (servlet_match or any_class)
                else 0,
            )
        )
        return True

    @staticmethod
    def _build_path_taint_map(
        text: str, pathparam_keys: dict[str, str]
    ) -> tuple[dict[str, str], set[str], list[str]]:
        """Map local var → wire path-param name for ``getPathParameter`` reads.

        Returns ``(path_taint, sanitized_vars, read_classes)``:

          * ``path_taint`` — ``filename`` → ``"filename"`` for
            ``String filename = handlerRequest.getPathParameter(Xxx.class)`` (the
            class resolved to its wire name via the pass-1 key registry).
          * ``sanitized_vars`` — vars whose tainting assignment applied a
            basename-strip/canonicalize (Flink's fixed ``new File(...).getName()``),
            so Intent reads the sink SANCTIONED rather than EXPOSED.
          * ``read_classes`` — the path-param classes read in this handler, used to
            resolve the route and the entrypoint's path params.
        """
        path_taint: dict[str, str] = {}
        sanitized_vars: set[str] = set()
        read_classes: list[str] = []
        for m in _RE_VAR_FROM_PATHPARAM.finditer(text):
            var, rhs, param_class = m.group(1), m.group(2), m.group(3)
            wire = pathparam_keys.get(param_class)
            if wire is None:
                continue
            path_taint[var] = wire
            if param_class not in read_classes:
                read_classes.append(param_class)
            if _RE_PATH_SANITIZER.search(rhs):
                sanitized_vars.add(var)
        # A path param read but never bound to a local (rare) still surfaces its
        # class so the route/params resolve — the reachability edge just needs the
        # tainted sink, which the bound-var case above provides.
        for m in _RE_PATH_PARAM_READ.finditer(text):
            param_class = m.group(1)
            if param_class in pathparam_keys and param_class not in read_classes:
                read_classes.append(param_class)
        return path_taint, sanitized_vars, read_classes

    @staticmethod
    def _extract_file_read_call_sites(
        text: str,
        file: str,
        path_taint: dict[str, str],
        sanitized_path_vars: set[str],
        var_to_param: dict[str, str],
    ) -> tuple[list[CallSite], bool]:
        """Find FILE_READ sinks reachable from a request param in this function.

        A ``new File(dir, name)`` / ``new FileInputStream(name)`` / ``Files.read*(
        name)`` whose argument traces to a request param (a path param preferred,
        else a query/form param) is a file-read call site. A sink whose path was
        basename-stripped/canonicalized in its tainting assignment carries the
        ``path_basename_strip`` guard so Intent marks it SANCTIONED (Flink's fixed
        variant); an unsanitized one carries no guard — the intent-gap (EXPOSED).

        Only *tainted* sinks are emitted: an untainted file read (Solr's
        ``FileStream(File f)`` over a constructor arg, not a request param) has no
        reaching channel and would only add a Δ with no reachability edge. Returns
        ``(sites, need_sanitize_guard)``.
        """
        sites: list[CallSite] = []
        need_sanitize_guard = False
        for m in _RE_FILE_SINK.finditer(text):
            arg = next((g for g in m.groups() if g), None)
            if arg is None:
                continue
            wire = path_taint.get(arg)
            sanitized = arg in sanitized_path_vars
            if wire is None:
                wire = var_to_param.get(arg)  # a query/form-param-tainted file read
            if wire is None:
                continue  # untainted file read — no reaching channel
            guard_symbol = _FILE_READ_GUARD_SYMBOL if sanitized else None
            if sanitized:
                need_sanitize_guard = True
            sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.FILE_READ,
                    symbol="file_read",
                    file=file,
                    line=_line_of(text, m.start()),
                    tainted_by=wire,
                    guard_symbol=guard_symbol,
                    sink_shape_id=_SINK_SHAPE_FILE_READ,
                )
            )
        return sites, need_sanitize_guard

    @staticmethod
    def _path_sanitize_guard(text: str, file: str) -> Guard:
        """A real (non-bypassable) basename-strip/canonicalize guard on a path.

        The file-read analogue of the host-check guard: unlike the bypassable
        host-match guard (two attacker operands), a basename-strip fixes the value
        the attacker controls, so it is a genuine constraint — Intent reads it
        SANCTIONED and the sink is removed from Δ. Flink's fix (``new File(
        pathParam).getName()``) is exactly this guard.
        """
        sm = _RE_PATH_SANITIZER.search(text)
        return Guard(
            symbol=_FILE_READ_GUARD_SYMBOL,
            kind="path_sanitize",
            bypassable_by_default=False,
            file=file,
            line=_line_of(text, sm.start()) if sm else 0,
        )

    @staticmethod
    def _extract_log_call_sites(
        text: str,
        file: str,
        var_to_param: dict[str, str],
        attacker_vars: set[str],
    ) -> list[CallSite]:
        """Find LOG_INTERPOLATION sinks: logging calls whose arg is request-derived.

        A logging call (``log.info(…)`` / ``logger.warn(…)`` / Solr's ``log().info(…)``
        accessor) is a Log4Shell log-sink channel when its argument list references
        untrusted request data — a tainted var (``var_to_param`` / ``attacker_vars``),
        a var bound to the whole request param bag (``req.getParams()``), or a direct
        request accessor. A logging call with no request-derived argument (a static
        ``log.info("started")``) is NOT a channel and is skipped.

        Unlike the egress/file-read sinks, the taint need NOT be intra-function to the
        entrypoint that first read the param — the reachability layer grades the
        log-sink edge ``STATIC_HEURISTIC`` (design §P6.5.3), so this only asserts "a
        request-derived value is logged here". ``tainted_by`` is the specific named
        param if the args reference one, else the coarse ``*request*`` marker (the
        whole bag is logged, so any request param — incl. the CVE's ``action`` — reaches
        the logger). The manifest gate, not this call site, decides activation.
        """
        request_bag_vars = {m.group(1) for m in _RE_REQUEST_BAG_VAR.finditer(text)}
        request_vars = set(var_to_param) | attacker_vars | request_bag_vars
        sites: list[CallSite] = []
        for m in _RE_LOG_CALL.finditer(text):
            args = _balanced_arg_slice(text, m.end() - 1)
            if not args:
                continue
            named_var = next((v for v in var_to_param if _identifier_in(v, args)), None)
            has_request = named_var is not None or any(
                _identifier_in(v, args) for v in request_vars
            )
            if not has_request and not _RE_REQUEST_ACCESSOR.search(args):
                continue  # a log call with no request-derived argument is not a channel
            tainted_by = (
                var_to_param.get(named_var) if named_var else None
            ) or _LOG_SINK_COARSE_TAINT
            sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.LOG_INTERPOLATION,
                    symbol=_LOG_SINK_SYMBOL,
                    file=file,
                    line=_line_of(text, m.start()),
                    tainted_by=tainted_by,
                    guard_symbol=None,
                    sink_shape_id=_SINK_SHAPE_LOG,
                )
            )
        return sites

    @staticmethod
    def _scan_log4j_manifest(root: Path) -> tuple[bool, str, str]:
        """Whether a vulnerable log4j-core (< 2.15) is declared in the source tree.

        Reads bounded build manifests (``pom.xml`` / gradle / ivy / props) and
        shipped-jar / license-sha1 filenames, extracting every declared
        ``log4j-core`` version. Vulnerable when the LOWEST declared version is
        < 2.15.0 (JNDI message-lookups un-gated). The version is learned from the
        manifest — no version literal is baked in — so a patched line (≥ 2.15)
        returns ``(False, "", "")`` and the LOG_INTERPOLATION primitive stays
        inactive (N/A by construction). Bounded single tree walk, source treated as
        untrusted.

        Returns ``(vulnerable, evidence, observed_version)`` — the raw point
        version (e.g. ``2.14.1``) feeds the Layer-2 capability fact's predicate.
        """
        found: list[tuple[tuple[int, int, int], str, str]] = []  # (semver, raw, source)

        def _consider(raw: str, source: str) -> None:
            semver = _parse_semver(raw)
            if semver is not None:
                found.append((semver, raw, source))

        search_root = root if root.is_dir() else root.parent
        seen_files = 0
        for path in search_root.rglob("*"):
            if seen_files >= _MAX_FILES:
                break
            if not path.is_file():
                continue
            seen_files += 1
            name = path.name
            jar_match = _RE_LOG4J_JAR.search(name)
            if jar_match:
                _consider(jar_match.group(1), name)
                continue
            if name not in _MANIFEST_NAMES:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("manifest scan: cannot read %s: %s", path, exc)
                continue
            for cm in _RE_LOG4J_COORD.finditer(content):
                _consider(cm.group(1), name)
            for am in _RE_LOG4J_POM_ARTIFACT.finditer(content):
                window = content[am.end() : am.end() + _MAX_POM_VERSION_LOOKAHEAD]
                vm = _RE_POM_VERSION.search(window)
                if vm:
                    _consider(vm.group(1), name)

        if not found:
            return False, "", ""
        found.sort(key=lambda item: item[0])
        lowest_semver, lowest_raw, source = found[0]
        if lowest_semver >= _LOG4J_SAFE_VERSION:
            return False, "", ""
        return (
            True,
            (
                f"log4j-core {lowest_raw} (< 2.15.0) declared in {source} "
                "→ JNDI message-lookup egress un-gated (CVE-2021-44228)"
            ),
            lowest_raw,
        )

    @staticmethod
    def _build_taint_map(text: str, const_map: dict[str, str]) -> dict[str, str]:
        """Map local var → wire param name (attacker taint, intra-function).

        Covers ``var = getParameter("p")``, ``var = params.get(NAME)`` (scalar),
        and — position-aware — ``for (T elem : coll)`` where ``coll`` was assigned
        from ``params.getParams(NAME)``. The foreach resolution is deliberately
        **nearest-preceding**: Solr reassigns one ``strs`` local across
        ``stream.url`` / ``stream.file`` / ``stream.body``, so a flat last-wins map
        would mis-attribute the loop over the first assignment; pairing the loop
        with the most recent preceding assignment keeps ``url`` bound to
        ``stream.url``.
        """
        var_to_param: dict[str, str] = {}
        for m in _RE_VAR_FROM_PARAM.finditer(text):
            var_to_param[m.group(1)] = m.group(2)
        for m in _RE_VAR_FROM_BAG_GET.finditer(text):
            wire = _resolve_param_name(m.group(2), const_map)
            if wire:
                var_to_param[m.group(1)] = wire

        # Position-ordered array-bag assignments, for nearest-preceding foreach pairing.
        array_assigns: list[tuple[int, str, str]] = []
        for m in _RE_VAR_FROM_BAG_GETPARAMS.finditer(text):
            wire = _resolve_param_name(m.group(2), const_map)
            if wire:
                array_assigns.append((m.start(), m.group(1), wire))
        for m in _RE_FOR_EACH.finditer(text):
            elem, coll = m.group(1), m.group(2)
            preceding = [w for (pos, v, w) in array_assigns if v == coll and pos < m.start()]
            if preceding:
                var_to_param[elem] = preceding[-1]
        return var_to_param

    @staticmethod
    def _ordered_params(text: str, const_map: dict[str, str]) -> list[str]:
        """Distinct request parameters read in the file, in first-seen order.

        Unions servlet ``getParameter`` literals with resolved param-bag reads
        (``get`` / ``getParams`` — symbolic names resolved through *const_map*).
        """
        seen: list[str] = []

        def _add(name: str | None) -> None:
            if name and name not in seen:
                seen.append(name)

        combined = re.compile(
            rf'getParameter\(\s*"([^"]+)"\s*\)'
            rf"|\.(?:get|getParam|getParams)\(\s*({_NAMEREF})\s*{_OPT_DEFAULT}\)"
        )
        for m in combined.finditer(text):
            if m.group(1) is not None:
                _add(m.group(1))
            elif m.group(2) is not None:
                _add(_resolve_param_name(m.group(2), const_map))
        return seen

    @staticmethod
    def _resolve_route(text: str, servlet_class: str) -> str:
        """Resolve the servlet's own path, preferring the getServletPath constant."""
        check = _RE_SERVLET_PATH_CHECK.search(text)
        consts = {m.group(1): m.group(2) for m in _RE_STRING_CONST.finditer(text)}
        if check and check.group(1) in consts:
            return consts[check.group(1)]
        # Fallback: a path-shaped constant naming the servlet, else "/<Class>".
        for name, value in consts.items():
            if value.startswith("/") and servlet_class.lower() in value.lower():
                return value
        return f"/{servlet_class}"

    @staticmethod
    def _extract_egress_call_sites(
        text: str,
        file: str,
        var_to_param: dict[str, str],
        var_to_urlarg: dict[str, str],
        wrapper_types: set[str],
        guard_symbol: str | None,
    ) -> list[CallSite]:
        """Find EGRESS_FETCH sinks reachable from a request param in this function.

        Two shapes, both reduced to the ``openConnection`` primitive:
          * **direct** ``var.openConnection()`` whose receiver traces to a request
            param (GeoServer's in-handler fetch), and
          * **wrapped** ``new Wrapper(new URL(arg))`` where ``Wrapper`` is a
            discovered egress-fetch type and ``arg`` traces to a request param
            (Solr's ``URLStream``; the literal openConnection is one class away).

        Only *tainted* sites are emitted — an untainted egress site has no reaching
        channel in this function and would only add a Δ with no reachability edge.
        """
        sites: list[CallSite] = []

        def _emit(line_index: int, tainted_by: str | None) -> None:
            if tainted_by is None:
                return
            sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.EGRESS_FETCH,
                    symbol="openConnection",
                    file=file,
                    line=_line_of(text, line_index),
                    tainted_by=tainted_by,
                    guard_symbol=guard_symbol,
                    sink_shape_id=_SINK_SHAPE_EGRESS,
                )
            )

        for m in _RE_OPEN_CONNECTION.finditer(text):
            _emit(
                m.start(),
                JavaSourceIngestor._resolve_taint(m.group(1), var_to_param, var_to_urlarg),
            )
        for m in _RE_NEW_URL_IN_CTOR.finditer(text):
            wrapper = m.group(1).split(".")[-1]
            if wrapper not in wrapper_types:
                continue
            _emit(
                m.start(),
                JavaSourceIngestor._resolve_taint(m.group(2), var_to_param, var_to_urlarg),
            )
        return sites

    @staticmethod
    def _resolve_taint(
        var: str, var_to_param: dict[str, str], var_to_urlarg: dict[str, str], _depth: int = 0
    ) -> str | None:
        """Trace *var* through ``new URL(...)`` back to a request-param name.

        Bounded intra-function chase: ``u`` → ``new URL(urlString)`` →
        ``urlString = getParameter("url")`` → ``"url"``; or the Solr shape
        ``new URL(url)`` where ``url`` is a foreach element already bound to
        ``stream.url`` in *var_to_param*. Also resolves an inline
        ``new URL(getParameter("p"))``. Returns the param name or ``None`` if the
        receiver is not attacker-tainted in this function.
        """
        if _depth > 4:
            return None
        if var in var_to_param:
            return var_to_param[var]
        inline = _RE_GET_PARAM.search(var)
        if inline:
            return inline.group(1)
        if var in var_to_urlarg:
            arg = var_to_urlarg[var]
            inline = _RE_GET_PARAM.search(arg)
            if inline:
                return inline.group(1)
            if arg.isidentifier():
                return JavaSourceIngestor._resolve_taint(
                    arg, var_to_param, var_to_urlarg, _depth + 1
                )
        return None

    @staticmethod
    def _extract_guard(
        text: str,
        file: str,
        attacker_vars: set[str],
        config_vars: set[str],
        var_to_urlarg: dict[str, str],
        var_to_param: dict[str, str],
    ) -> Guard | None:
        """Extract the host-check guard and decide whether it is bypassable.

        A ``X.getHost().equals(Y.getHost())`` comparison is **bypassable by
        default** when both operands trace to attacker-controlled request data
        (the ``url`` parameter vs a value derived from ``request.getRequestURL()``
        / the ``Host`` header). A sibling comparison against a config-derived value
        (``getProxyBaseURL()``) is the *real* guard, gated on that config's
        presence — recorded as ``gating_config`` so Intent gates on it, not on the
        bypassable branch (§10 gap #2). A target with no host-check guard (Solr's
        ``stream.url`` — no guard at all) yields ``None`` and Intent reads the
        unguarded sink as the highest-Δ intent-gap.
        """
        compares = list(_RE_HOST_COMPARE.finditer(text))
        if not compares:
            return None
        guard_call = _RE_GUARD_CALL.search(text)
        symbol = guard_call.group(1) if guard_call else "validateURL"

        gating_config = JavaSourceIngestor._config_flag_name(text, config_vars)
        bypassable = False
        chosen_operands: list[str] = []
        chosen_attacker: list[str] = []
        chosen_line = 0
        for m in compares:
            left, right = m.group(1), m.group(2)
            left_attacker = JavaSourceIngestor._is_attacker(
                left, attacker_vars, config_vars, var_to_urlarg, var_to_param
            )
            right_attacker = JavaSourceIngestor._is_attacker(
                right, attacker_vars, config_vars, var_to_urlarg, var_to_param
            )
            if left_attacker and right_attacker:
                bypassable = True
                chosen_operands = [f"{left}.getHost()", f"{right}.getHost()"]
                chosen_attacker = [left, right]
                chosen_line = _line_of(text, m.start())
                break
        if not chosen_operands:
            first = compares[0]
            chosen_operands = [f"{first.group(1)}.getHost()", f"{first.group(2)}.getHost()"]
            chosen_line = _line_of(text, first.start())

        return Guard(
            symbol=symbol,
            kind="host_match",
            operands=chosen_operands,
            attacker_controlled_operands=chosen_attacker,
            gating_config=gating_config,
            bypassable_by_default=bypassable,
            file=file,
            line=chosen_line,
        )

    @staticmethod
    def _is_attacker(
        var: str,
        attacker_vars: set[str],
        config_vars: set[str],
        var_to_urlarg: dict[str, str],
        var_to_param: dict[str, str],
    ) -> bool:
        """Whether *var* traces to attacker-controlled request data (not config)."""
        if var in config_vars:
            return False
        if var in attacker_vars or var in var_to_param:
            return True
        # ``requestUrl = new URL(requestString)`` where requestString is attacker-controlled.
        if var in var_to_urlarg:
            arg = var_to_urlarg[var]
            if arg in attacker_vars or arg in var_to_param:
                return True
            if arg in config_vars:
                return False
        return False

    @staticmethod
    def _config_flag_name(text: str, config_vars: set[str]) -> str | None:
        """Human-readable config flag that would make the guard real (ProxyBaseUrl)."""
        m = re.search(r"getProxyBaseUrl|getProxyBaseURL", text)
        if m:
            return "ProxyBaseUrl"
        return next(iter(sorted(config_vars)), None)
