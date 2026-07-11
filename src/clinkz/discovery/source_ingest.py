"""Source Ingestion → :class:`SourceModel` (§2.2, first vertical slice).

A deterministic, **regex / bounded-scan-only** ingestor (never ``eval``, bounded
file count + bytes, source treated as untrusted data) — the same discipline as
``agents/_route_discovery.py``. This slice targets Java servlets and surfaces
exactly what the GeoServer walkthrough (§10) needs:

  * the ``TestWfsPost`` **entrypoint** (route + request params) a black-box crawl
    misses because the demo servlet is unlinked (§10 gap #1 — the gray-box win),
  * the intra-function ``url → openConnection`` **EGRESS_FETCH call site**, and
  * the **host-check guard** whose two operands are both attacker-controlled
    (``url`` host vs request ``Host`` header) — the fact Intent must read as
    *bypassable*, or Δ under-counts and the vuln is missed (§10 gap #2 / OQ #7).

It is deliberately minimal: a single-language, pattern-based extractor proven on
one real file, not a general whole-program analyzer (that is the next slice).
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

# --- Patterns (Java servlet shapes) -----------------------------------------
_RE_SERVLET_CLASS = re.compile(r"\bclass\s+(\w+)\s+extends\s+HttpServlet\b")
_RE_HANDLER = re.compile(
    r"\b(?:protected|public)\s+void\s+(doGet|doPost|service|processRequest)\s*\("
)
_RE_GET_PARAM = re.compile(r'getParameter\(\s*"([^"]+)"\s*\)')
# ``var = ...getParameter("p")`` — a request parameter bound to a local.
_RE_VAR_FROM_PARAM = re.compile(r'(\w+)\s*=\s*[^;]*?getParameter\(\s*"([^"]+)"\s*\)')
# ``var = new URL(arg)`` — capture the constructor argument (a var or an expr).
_RE_VAR_FROM_NEWURL = re.compile(r"(\w+)\s*=\s*new\s+URL\(\s*([^)]+?)\s*\)")
_RE_OPEN_CONNECTION = re.compile(r"(\w+)\.openConnection\(\s*\)")
# ``static final String NAME = "/path"`` — a servlet-path constant.
_RE_STRING_CONST = re.compile(r'(?:static\s+)?final\s+String\s+(\w+)\s*=\s*"([^"]+)"')
_RE_SERVLET_PATH_CHECK = re.compile(r"getServletPath\(\s*\)\.equals\(\s*(\w+)\s*\)")
# Client-controlled request sources (attacker taint origins).
_RE_VAR_FROM_REQUEST = re.compile(
    r"(\w+)\s*=\s*[^;]*?request\."
    r"(getRequestURL|getHeader|getServerName|getParameter|getQueryString|getRequestURI)\b"
)
# Server-config sources (NOT attacker-controlled) — turn a guard into a real one.
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


class JavaSourceIngestor:
    """Ingest a Java source tree into a :class:`SourceModel` (bounded, no eval)."""

    def ingest_path(self, root: str | Path) -> SourceModel:
        """Ingest every ``*.java`` under *root* (bounded), returning a SourceModel."""
        root = Path(root)
        model = SourceModel()
        if not root.exists():
            logger.warning("source ingest: path does not exist: %s", root)
            return model

        files = sorted(root.rglob("*.java")) if root.is_dir() else [root]
        ingested = 0
        for path in files[:_MAX_FILES]:
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("source ingest: cannot read %s: %s", path, exc)
                continue
            self._ingest_text(text, str(path), model)
            ingested += 1

        model.files_ingested = ingested
        if any(c.primitive_class == PrimitiveClass.EGRESS_FETCH for c in model.call_sites):
            model.coverage_grade = CoverageGrade.PARTIAL
        model.technologies = ["Java", "Java Servlet"] if model.entrypoints else []
        logger.info(
            "source ingest: %d files → %d entrypoints, %d call-sites, %d guards",
            ingested,
            len(model.entrypoints),
            len(model.call_sites),
            len(model.guards),
        )
        return model

    def _ingest_text(self, text: str, file: str, model: SourceModel) -> None:
        """Extract entrypoints / call sites / guards from one Java file."""
        servlet_match = _RE_SERVLET_CLASS.search(text)
        if not servlet_match:
            return  # only servlets in this slice
        servlet_class = servlet_match.group(1)

        var_to_param = {m.group(1): m.group(2) for m in _RE_VAR_FROM_PARAM.finditer(text)}
        var_to_urlarg = {m.group(1): m.group(2).strip() for m in _RE_VAR_FROM_NEWURL.finditer(text)}
        attacker_vars = {m.group(1) for m in _RE_VAR_FROM_REQUEST.finditer(text)}
        config_vars = {m.group(1) for m in _RE_VAR_FROM_CONFIG.finditer(text)}

        guard = self._extract_guard(
            text, file, attacker_vars, config_vars, var_to_urlarg, var_to_param
        )
        if guard:
            model.guards.append(guard)

        call_sites = self._extract_egress_call_sites(
            text, file, var_to_param, var_to_urlarg, guard.symbol if guard else None
        )
        model.call_sites.extend(call_sites)

        route = self._resolve_route(text, servlet_class)
        params = self._ordered_params(text)
        methods = sorted({m.group(1) for m in _RE_HANDLER.finditer(text)} & {"doGet", "doPost"})
        http_methods = []
        if "doGet" in methods:
            http_methods.append("GET")
        if "doPost" in methods:
            http_methods.append("POST")
        model.entrypoints.append(
            Entrypoint(
                route=route,
                http_methods=http_methods or ["POST"],
                handler_symbol=servlet_class,
                params=params,
                file=file,
                line=_line_of(text, servlet_match.start()),
            )
        )

    @staticmethod
    def _ordered_params(text: str) -> list[str]:
        """Distinct request parameters in first-seen order."""
        seen: list[str] = []
        for m in _RE_GET_PARAM.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.append(name)
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
        guard_symbol: str | None,
    ) -> list[CallSite]:
        """Find ``openConnection`` sinks and trace the receiver to a request param."""
        sites: list[CallSite] = []
        for m in _RE_OPEN_CONNECTION.finditer(text):
            receiver = m.group(1)
            tainted_by = JavaSourceIngestor._resolve_taint(receiver, var_to_param, var_to_urlarg)
            sites.append(
                CallSite(
                    primitive_class=PrimitiveClass.EGRESS_FETCH,
                    symbol="openConnection",
                    file=file,
                    line=_line_of(text, m.start()),
                    tainted_by=tainted_by,
                    guard_symbol=guard_symbol,
                )
            )
        return sites

    @staticmethod
    def _resolve_taint(
        var: str, var_to_param: dict[str, str], var_to_urlarg: dict[str, str], _depth: int = 0
    ) -> str | None:
        """Trace *var* through ``new URL(...)`` back to a ``getParameter`` name.

        Bounded intra-function chase: ``u`` → ``new URL(urlString)`` →
        ``urlString = getParameter("url")`` → ``"url"``. Returns the param name or
        ``None`` if the receiver is not attacker-tainted in this function.
        """
        if _depth > 4:
            return None
        if var in var_to_param:
            return var_to_param[var]
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
        bypassable branch (§10 gap #2).
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
