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

It stays deliberately shallow: single-language (Java), pattern-based, bounded —
not a whole-program analyzer. Cross-function / cross-service reachability beyond
the wrapper case remains the next slice.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

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

# --- Class / handler shapes -------------------------------------------------
_RE_SERVLET_CLASS = re.compile(r"\bclass\s+(\w+)\s+extends\s+HttpServlet\b")
_RE_ANY_CLASS = re.compile(r"\b(?:class|interface)\s+(\w+)")
_RE_HANDLER = re.compile(
    r"\b(?:protected|public)\s+void\s+(doGet|doPost|service|processRequest)\s*\("
)

# --- Request-parameter reads (the untrusted channel) ------------------------
# A named reference is either a "string literal" or a symbolic Foo.BAR constant.
_NAMEREF = r'(?:"[^"]+"|[A-Za-z_][\w.]*)'
# Servlet: request.getParameter("p")
_RE_GET_PARAM = re.compile(r'getParameter\(\s*"([^"]+)"\s*\)')
# Param-bag scalar read: params.get(NAME) — the String form (NOT getParams()).
_RE_PARAM_BAG_GET = re.compile(rf"\.get\(\s*({_NAMEREF})\s*\)")
# Param-bag array read: params.getParams(NAME) — the String[] form.
_RE_PARAM_BAG_GETPARAMS = re.compile(rf"\.getParams\(\s*({_NAMEREF})\s*\)")
# ``var = ...getParameter("p")`` — a request parameter bound to a local.
_RE_VAR_FROM_PARAM = re.compile(r'(\w+)\s*=\s*[^;]*?getParameter\(\s*"([^"]+)"\s*\)')
# ``var = ...params.get(NAME)`` — scalar bag read bound to a local.
_RE_VAR_FROM_BAG_GET = re.compile(rf"(\w+)\s*=\s*[^;]*?\.get\(\s*({_NAMEREF})\s*\)")
# ``var = ...params.getParams(NAME)`` — array bag read bound to a local.
_RE_VAR_FROM_BAG_GETPARAMS = re.compile(rf"(\w+)\s*=\s*[^;]*?\.getParams\(\s*({_NAMEREF})\s*\)")
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


class JavaSourceIngestor:
    """Ingest a Java source tree into a :class:`SourceModel` (bounded, no eval)."""

    def ingest_path(self, root: str | Path) -> SourceModel:
        """Ingest every ``*.java`` under *root* (bounded), returning a SourceModel.

        Two deterministic passes. Pass 1 builds the cross-file facts an entrypoint
        file may depend on — the constant map (symbolic param names) and the set of
        egress-fetch wrapper types (classes that open a ``URLConnection``). Pass 2
        extracts entrypoints / call sites / guards from each **entrypoint** file
        (a file that reads a request parameter), resolving names and wrappers
        against the pass-1 facts. Non-entrypoint library files (e.g. the wrapper's
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

        saw_servlet = False
        for file, text in texts:
            if self._ingest_text(text, file, model, const_map, wrapper_types):
                if _RE_SERVLET_CLASS.search(text):
                    saw_servlet = True

        model.files_ingested = len(texts)
        if any(c.primitive_class == PrimitiveClass.EGRESS_FETCH for c in model.call_sites):
            model.coverage_grade = CoverageGrade.PARTIAL
        if model.entrypoints:
            model.technologies = ["Java", "Java Servlet"] if saw_servlet else ["Java"]
        logger.info(
            "source ingest: %d files → %d entrypoints, %d call-sites, %d guards "
            "(%d consts, %d wrappers)",
            len(texts),
            len(model.entrypoints),
            len(model.call_sites),
            len(model.guards),
            len(const_map),
            len(wrapper_types),
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

    def _ingest_text(
        self,
        text: str,
        file: str,
        model: SourceModel,
        const_map: dict[str, str],
        wrapper_types: set[str],
    ) -> bool:
        """Extract entrypoint / call sites / guard from one file. Returns ingested?

        A file is an **entrypoint file** only if it reads a request parameter
        (servlet ``getParameter`` or a param-bag ``get``/``getParams``). Files that
        merely *define* a wrapper or constants (Solr's ``ContentStreamBase`` /
        ``CommonParams``) contribute only pass-1 facts and are skipped here.
        """
        has_param_read = bool(
            _RE_GET_PARAM.search(text)
            or _RE_PARAM_BAG_GET.search(text)
            or _RE_PARAM_BAG_GETPARAMS.search(text)
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

        guard = self._extract_guard(
            text, file, attacker_vars, config_vars, var_to_urlarg, var_to_param
        )
        if guard:
            model.guards.append(guard)

        call_sites = self._extract_egress_call_sites(
            text, file, var_to_param, var_to_urlarg, wrapper_types, guard.symbol if guard else None
        )
        model.call_sites.extend(call_sites)

        route = self._resolve_route(text, handler_symbol) if servlet_match else ""
        params = self._ordered_params(text, const_map)
        methods = sorted({m.group(1) for m in _RE_HANDLER.finditer(text)} & {"doGet", "doPost"})
        http_methods: list[str] = []
        if "doGet" in methods:
            http_methods.append("GET")
        if "doPost" in methods:
            http_methods.append("POST")
        if not http_methods:
            # A non-servlet param-bag entrypoint (shared request parser) is reached
            # by a query-carried GET on whatever handler route the operator supplies.
            http_methods = ["GET"]
        model.entrypoints.append(
            Entrypoint(
                route=route,
                http_methods=http_methods,
                handler_symbol=handler_symbol,
                params=params,
                file=file,
                line=_line_of(text, (servlet_match or any_class or _RE_GET_PARAM).start())
                if (servlet_match or any_class)
                else 0,
            )
        )
        return True

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
            rf'getParameter\(\s*"([^"]+)"\s*\)|\.getParams?\(\s*({_NAMEREF})\s*\)'
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
