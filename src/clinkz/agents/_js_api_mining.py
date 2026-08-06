"""Mine a served JavaScript bundle for the API contract the frontend declares.

A single-page app's real attack surface is the set of HTTP calls its own
JavaScript makes. Those calls are *in the bundle*: the method, the URL
template, the query parameters and — where the code touches the body's fields —
the body shape. Reading them is strictly better than guessing endpoint names,
and it is the only way to learn a **request body** without a served spec.

This module is the reader. It is pure text analysis over JS source: no
execution, no ``eval``, no network, no target-specific vocabulary. Everything it
reports it read from a call site.

What it recognises (the idiom set, not a framework list):

* ``fetch(url, {method, body})`` — the platform primitive, so React/Vue/Svelte
  and hand-rolled clients all land here.
* ``<x>.get/post/put/patch/delete/request(url, ...)`` — Angular ``HttpClient``,
  axios, jQuery, superagent, ky and every wrapper shaped like them.
* ``axios({url, method, data})`` / ``axios.post(url, data)``.
* ``<xhr>.open("POST", url)`` — XMLHttpRequest.

Two things make it work on **minified production bundles**, which is the only
form a target actually serves:

* **Local binding resolution.** The URL is rarely one literal. Angular emits
  ``host=this.hostServer+"/api/Feedbacks"`` as a class field and then calls
  ``this.http.post(this.host+"/",e)``. Resolving ``host`` from the nearest
  preceding assignment recovers ``/api/Feedbacks/`` — searching *backwards*
  from the call site is what scopes the lookup correctly when a minifier has
  reused the name ``host`` in forty classes.
* **Body-field recovery from member access.** When the body argument is an
  identifier (``post(url, e)``), the field names are not at the call site — but
  the enclosing function usually reads them (``e.current``, ``e.new``). Those
  accesses are the declared body shape. When the function reads nothing, we
  learn nothing and say so: an unknown body is left unknown, never invented.

Bounds (these inputs are attacker-controllable): every scan is byte-capped, the
call-site count is capped, argument scanning is depth- and length-bounded, and
identifier resolution is iteration-bounded. No regex here backtracks over the
whole body.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# --- Bounds (safety: untrusted response bodies) ----------------------------
MAX_SOURCE_BYTES = 8_000_000  # bytes of one bundle scanned for call sites
_MAX_CALL_SITES = 4000  # call sites examined in one bundle
_MAX_ARG_CHARS = 4000  # chars scanned for one balanced argument list
_MAX_BINDING_PASSES = 4  # fixed-point passes when resolving an identifier
_BINDING_LOOKBACK = 20_000  # chars searched backwards for a binding
_BODY_SCOPE_CHARS = 1200  # chars around a call site read for member accesses
_MAX_OBJECT_DEPTH = 4  # nesting depth read from an object literal
_MAX_FIELDS = 40  # body field names recorded per call site
_MAX_EVIDENCE_CHARS = 240  # source excerpt kept per call site

_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# Method-named invocation: ``.post(``, ``.get(``, … . ``request`` and ``ajax``
# carry their method in an options object, so they map to None here.
_METHOD_CALL_RE = re.compile(
    r"\.\s*(get|post|put|patch|delete|del|head|options|request|ajax)\s*\(",
    re.IGNORECASE,
)
# ``fetch(`` / ``axios(`` — bare callee, method (if any) in an options object.
_BARE_CALL_RE = re.compile(r"(?<![.\w$])(fetch|axios)\s*\(")
# XMLHttpRequest: ``.open("POST", url``.
_XHR_OPEN_RE = re.compile(
    r"\.\s*open\s*\(\s*[\"'`](" + "|".join(_HTTP_METHODS) + r")[\"'`]\s*,",
    re.IGNORECASE,
)
# Browser NAVIGATION to a server URL: ``location.replace(u)``,
# ``location.assign(u)``, ``window.open(u)``. A page the application sends the
# browser to is part of its server surface just as much as one it fetches —
# ``/redirect?to=`` is reached this way and never through an XHR. This is the
# general replacement for the list of literal route words that used to be
# hardcoded here: it recognises the *idiom*, so it finds such a route on any
# application without knowing any application's vocabulary.
_NAVIGATION_CALL_RE = re.compile(
    r"(?:^|[^\w$.])(?:window\s*\.\s*)?(?:location\s*\.\s*(?:replace|assign)|window\s*\.\s*open)\s*\("
)
# ``location.href = <expr>`` / ``location = <expr>`` — assignment form.
_NAVIGATION_ASSIGN_RE = re.compile(
    r"(?:^|[^\w$.])(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*(?!=)"
)

# ``name = <expr>`` / ``name: <expr>`` — a candidate binding for URL resolution.
# The value side is captured loosely and parsed by the expression resolver.
_ASSIGN_TEMPLATE = r"(?:^|[^\w$.]){name}\s*[=:]\s*([^;,}}\n]{{0,300}})"

# A string literal, a template literal, or an identifier/member expression.
_STRING_RE = re.compile(r"""(["'])((?:\\.|(?!\1)[^\\])*)\1""")
_TEMPLATE_RE = re.compile(r"`((?:\\.|[^\\`])*)`")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*")
_TEMPLATE_HOLE_RE = re.compile(r"\$\{([^{}]{0,120})\}")

# Object-literal key: ``key:`` / ``"key":`` / ``'key':``.
_OBJECT_KEY_RE = re.compile(
    r"""(?:^|[,{])\s*(?:["']([^"']{1,64})["']|([A-Za-z_$][\w$]{0,63}))\s*:"""
)

# ``ident.prop`` member access, used to recover a body shape from a parameter.
_MEMBER_ACCESS_TEMPLATE = r"(?<![\w$.]){ident}\s*\.\s*([A-Za-z_$][\w$]{{0,63}})"

# Where response handling begins. Everything after this in a statement reads the
# RESPONSE, so it says nothing about the request body — and a minifier reuses
# the same one-letter name for both.
_RESPONSE_CHAIN_RE = re.compile(r"\.\s*(?:pipe|then|subscribe|catch|finally|toPromise)\s*\(")

# Property names that are request *metadata*, never body fields, when read off
# the body identifier. Generic HTTP/JS vocabulary — no application names.
_NON_BODY_MEMBERS = frozenset(
    {
        "then", "catch", "finally", "pipe", "subscribe", "toPromise", "map",
        "length", "constructor", "prototype", "hasOwnProperty", "toString",
        "valueOf", "call", "apply", "bind", "forEach", "filter", "reduce",
        "push", "pop", "slice", "splice", "concat", "join", "indexOf",
        "headers", "observe", "responseType", "withCredentials", "reportProgress",
        "append", "set", "has", "keys", "values", "entries", "next", "complete",
    }
)  # fmt: skip

# Options-object keys that carry the method / body / query of a call.
_OPT_METHOD_RE = re.compile(r"""(?:^|[,{])\s*["']?method["']?\s*:\s*["'`]([A-Za-z]{3,7})["'`]""")
_OPT_BODY_RE = re.compile(r"""(?:^|[,{])\s*["']?(?:body|data)["']?\s*:""")
_OPT_PARAMS_RE = re.compile(r"""(?:^|[,{])\s*["']?(?:params|query|searchParams)["']?\s*:""")
_OPT_CT_RE = re.compile(
    r"""["']content-type["']\s*:\s*["']([^"']{3,80})["']""",
    re.IGNORECASE,
)
_JSON_STRINGIFY_RE = re.compile(r"JSON\s*\.\s*stringify\s*\(")

# A resolved URL must look like a path or an absolute http URL. This is the
# ONLY filter separating a real call site from ``map.get(k)`` — it is a property
# of what resolution produced, not an allowlist of route names.
_URL_SHAPED_RE = re.compile(r"^(?:https?://[^\s\"'`]+|/[^\s\"'`]*)$")


@dataclass(frozen=True)
class ApiCallSite:
    """One HTTP call the frontend makes, as read from its own source.

    ``url_template`` uses ``:name`` for a path segment the code interpolates,
    matching the shape the Exploit-side request builder substitutes into.
    ``body_fields`` holds dotted paths for nested object fields (``a.b``); it is
    empty when the source did not reveal the body's shape, which is a fact
    about our knowledge and is never filled in with a guess.
    """

    method: str
    url_template: str
    query_params: tuple[str, ...] = ()
    body_fields: tuple[str, ...] = ()
    content_type: str | None = None
    evidence: str = ""

    @property
    def path_params(self) -> tuple[str, ...]:
        """Names of the ``:name`` placeholders in the URL template."""
        return tuple(
            seg[1:] for seg in self.url_template.split("/") if len(seg) > 1 and seg.startswith(":")
        )


@dataclass
class _Args:
    """A parsed argument list: the raw text of each top-level argument."""

    args: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Balanced scanning primitives
# ---------------------------------------------------------------------------


def _scan_arguments(source: str, open_paren: int) -> _Args:
    """Split the argument list starting at *open_paren* into top-level args.

    A depth-aware scan that understands string, template and regex-ish literals
    so a ``,`` or ``)`` inside a quoted URL never ends an argument early. The
    scan is bounded by :data:`_MAX_ARG_CHARS`; an unterminated list yields
    whatever was parsed rather than running to the end of a 2 MB bundle.
    """
    out: list[str] = []
    depth = 0
    current: list[str] = []
    i = open_paren
    limit = min(len(source), open_paren + _MAX_ARG_CHARS)
    quote: str | None = None
    while i < limit:
        ch = source[i]
        if quote is not None:
            current.append(ch)
            if ch == "\\":
                if i + 1 < limit:
                    current.append(source[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            current.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
            if depth == 1 and ch == "(":
                i += 1
                continue
            current.append(ch)
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            if depth == 0 and ch == ")":
                out.append("".join(current))
                return _Args(args=[a.strip() for a in out])
            current.append(ch)
            i += 1
            continue
        if ch == "," and depth == 1:
            out.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    if current:
        out.append("".join(current))
    return _Args(args=[a.strip() for a in out])


# ---------------------------------------------------------------------------
# URL expression resolution
# ---------------------------------------------------------------------------


def _split_concat(expr: str) -> list[str]:
    """Split a ``a+"b"+c`` expression into its top-level ``+`` terms."""
    terms: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote is not None:
            current.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                current.append(expr[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            current.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            terms.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    terms.append("".join(current))
    return [t.strip() for t in terms if t.strip()]


def _resolve_binding(name: str, source: str, before: int, _depth: int = 0) -> str | None:
    """Resolve identifier *name* to a path string from its nearest binding.

    Searches **backwards** from *before* for ``name = <expr>`` / ``name: <expr>``
    and resolves that expression recursively. Backwards is what makes this safe
    on a minified bundle where one short name is rebound in every class: the
    nearest preceding definition is the one lexically in scope at the call.

    Returns ``None`` when nothing resolves — the caller then treats the term as
    an unknown host prefix rather than inventing a path.
    """
    if _depth >= _MAX_BINDING_PASSES:
        return None
    leaf = name.rsplit(".", 1)[-1].strip()
    if not leaf:
        return None
    window_start = max(0, before - _BINDING_LOOKBACK)
    window = source[window_start:before]
    pattern = re.compile(_ASSIGN_TEMPLATE.format(name=re.escape(leaf)))
    best: str | None = None
    for match in pattern.finditer(window):
        best = match.group(1)
    if best is None:
        return None
    resolved, _holes = _resolve_url_expression(best, source, window_start, _depth + 1)
    return resolved or None


def _resolve_url_expression(
    expr: str,
    source: str,
    position: int,
    _depth: int = 0,
) -> tuple[str, list[str]]:
    """Resolve a URL expression to a template string plus its hole names.

    String and template literals contribute their static text; an interpolation
    (``${x}`` or a ``+ident+`` term) contributes a hole, named after the
    identifier when it has one. An identifier that resolves to a path via
    :func:`_resolve_binding` contributes that path; one that does not is a host
    prefix and contributes nothing (the target's origin is supplied by the
    caller, not by the bundle).
    """
    parts: list[str] = []
    holes: list[str] = []

    for term in _split_concat(expr):
        template = _TEMPLATE_RE.fullmatch(term)
        if template is not None:
            raw = template.group(1)
            cursor = 0
            for hole in _TEMPLATE_HOLE_RE.finditer(raw):
                parts.append(raw[cursor : hole.start()])
                inner = hole.group(1).strip()
                nested = _resolve_binding(inner, source, position, _depth + 1) if inner else None
                if nested:
                    parts.append(nested)
                elif not "".join(parts).strip():
                    # An unresolved hole with nothing before it is the ORIGIN
                    # (``${host}/api/x``), not an interpolated path value. Same
                    # rule as the identifier branch below; without it the
                    # commonest template shape resolves to a route that does
                    # not start with "/" and is discarded as not URL-shaped.
                    pass
                else:
                    parts.append("\x00")
                    holes.append(_hole_name(inner))
                cursor = hole.end()
            parts.append(raw[cursor:])
            continue

        literal = _STRING_RE.fullmatch(term)
        if literal is not None:
            parts.append(literal.group(2))
            continue

        ident = _IDENT_RE.fullmatch(term)
        if ident is not None:
            nested = _resolve_binding(term, source, position, _depth + 1)
            if nested:
                parts.append(nested)
            else:
                # An unresolved identifier at the START is the origin (host
                # variable); anywhere else it is an interpolated value.
                if parts and "".join(parts).strip():
                    parts.append("\x00")
                    holes.append(_hole_name(term))
            continue

        # Anything else (a call, a ternary, an encodeURIComponent wrapper) is an
        # interpolated value whose name we may still be able to read.
        parts.append("\x00")
        holes.append(_hole_name(term))

    return "".join(parts), holes


def _hole_name(expr: str) -> str:
    """A parameter name for an interpolated expression, or ``""`` if unnamed.

    ``encodeURIComponent(productId)`` → ``productId``; ``e`` (a minified
    parameter) → ``""``, because a single letter names nothing a report reader
    could act on and would collide across endpoints.
    """
    inner = (expr or "").strip()
    # Unwrap a single call layer: f(x) -> x.
    call = re.fullmatch(r"[A-Za-z_$][\w$]*\s*\(\s*([^()]{0,80})\s*\)", inner)
    if call is not None:
        inner = call.group(1).strip()
    leaf = inner.rsplit(".", 1)[-1].strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", leaf or ""):
        return ""
    return leaf if len(leaf) > 1 else ""


# ---------------------------------------------------------------------------
# Template → URL path + query params
# ---------------------------------------------------------------------------


def _template_to_route(template: str, holes: list[str]) -> tuple[str, list[str]] | None:
    """Turn a resolved template into ``(url_template, query_param_names)``.

    ``\\x00`` marks an interpolated value. A hole in the **path** becomes a
    ``:name`` segment; a hole after ``name=`` in the **query** makes ``name`` a
    query parameter. Returns ``None`` when what resolved is not URL-shaped.
    """
    path_part, sep, query_part = template.partition("?")
    hole_iter = iter(holes)

    # --- path -------------------------------------------------------------
    segments: list[str] = []
    for seg in path_part.split("/"):
        if "\x00" not in seg:
            segments.append(seg)
            continue
        names = [next(hole_iter, "") for _ in range(seg.count("\x00"))]
        chosen = next((n for n in names if n), "")
        segments.append(":" + (chosen or f"p{len(segments)}"))
    url_template = "/".join(segments)

    # --- query ------------------------------------------------------------
    query_params: list[str] = []
    if sep:
        for pair in query_part.split("&"):
            key = pair.split("=", 1)[0].strip()
            # Consume the holes this pair carries so path/query stay aligned.
            for _ in range(pair.count("\x00")):
                next(hole_iter, "")
            if "\x00" in key:
                continue  # a computed KEY names no parameter we can target
            if key:
                query_params.append(key)

    url_template = url_template.replace("\x00", "")
    # A trailing slash is the calling code's own style (``this.host + "/"``),
    # never an implicit collection id — the miner names every interpolation it
    # saw explicitly, so anything it did not name is not a parameter.
    if len(url_template) > 1:
        url_template = url_template.rstrip("/")
    if not _URL_SHAPED_RE.match(url_template):
        return None
    return url_template, query_params


# ---------------------------------------------------------------------------
# Body shape
# ---------------------------------------------------------------------------


def object_literal_fields(expr: str, _depth: int = 0) -> list[str]:
    """Top-level and nested field names of an object literal, as dotted paths.

    ``{a:1,b:{c:2}}`` → ``["a", "b", "b.c"]``. Bounded in depth and count.
    Returns ``[]`` for anything that is not an object literal.

    Only keys at the **current** nesting level are taken here; nested levels are
    reached by recursing into their own balanced block. Scanning the whole text
    for key-shaped tokens instead would report a grandchild's key as a
    top-level field, i.e. propose a request field the endpoint does not have.
    """
    text = (expr or "").strip()
    if not text.startswith("{") or _depth > _MAX_OBJECT_DEPTH:
        return []
    out: list[str] = []
    for name, value in _top_level_entries(text):
        out.append(name)
        if value.startswith("{"):
            for child in object_literal_fields(value, _depth + 1):
                out.append(f"{name}.{child}")
        if len(out) >= _MAX_FIELDS:
            break
    return list(dict.fromkeys(out))[:_MAX_FIELDS]


def _top_level_entries(text: str) -> list[tuple[str, str]]:
    """``(key, value_text)`` for each entry at the top level of ``{...}``."""
    body = _balanced_object(text)
    if len(body) < 2:
        return []
    inner = body[1:-1]
    entries: list[tuple[str, str]] = []
    depth = 0
    quote: str | None = None
    start = 0
    parts: list[str] = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(inner[start:i])
            start = i + 1
        i += 1
    parts.append(inner[start:])

    for part in parts:
        stripped = part.strip()
        if not stripped:
            continue
        match = re.match(
            r"""^(?:["'](?P<q>[^"']{1,64})["']|(?P<b>[A-Za-z_$][\w$]{0,63}))\s*:""", stripped
        )
        if match is None:
            continue
        key = match.group("q") or match.group("b")
        if key:
            entries.append((key, stripped[match.end() :].strip()))
        if len(entries) >= _MAX_FIELDS:
            break
    return entries


def _balanced_expression(text: str) -> str:
    """The leading expression of *text*, stopping at a top-level ``,`` or ``}``.

    Needed because a body value is often a call rather than a literal —
    ``body: JSON.stringify({a:1, b:2})`` — and splitting on the first comma
    truncates it mid-object, which then reads as a one-field body.
    """
    depth = 0
    quote: str | None = None
    i = 0
    limit = min(len(text), _MAX_ARG_CHARS)
    while i < limit:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[:i].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return text[:i].strip()
        i += 1
    return text[:limit].strip()


def _balanced_object(text: str) -> str:
    """The leading balanced ``{...}`` of *text* (quote-aware), or ``""``."""
    if not text.startswith("{"):
        return ""
    depth = 0
    quote: str | None = None
    i = 0
    limit = min(len(text), _MAX_ARG_CHARS)
    while i < limit:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[: i + 1]
        i += 1
    return ""


def _enclosing_block(source: str, position: int) -> tuple[int, int]:
    """Bounds of the innermost ``{...}`` block containing *position*.

    Scoping the body-shape scan to the enclosing function is not a refinement,
    it is the difference between a shape and a fabrication. A fixed character
    window around the call site straddles the neighbouring methods of the same
    minified class, and ``POST /rest/user/login`` came back declaring the
    fields of ``changePassword`` — a body we would then have injected into,
    with siblings the endpoint has never heard of. Falls back to a bounded
    window when no enclosing block is found.
    """
    start = max(0, position - _BODY_SCOPE_CHARS * 4)
    depth = 0
    open_at = -1
    for i in range(position - 1, start - 1, -1):
        ch = source[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                open_at = i
                break
            depth -= 1
    if open_at < 0:
        return max(0, position - _BODY_SCOPE_CHARS), min(len(source), position + _BODY_SCOPE_CHARS)

    depth = 0
    limit = min(len(source), position + _BODY_SCOPE_CHARS * 4)
    close_at = limit
    for i in range(open_at, limit):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                close_at = i + 1
                break
    return open_at, close_at


def _member_access_fields(ident: str, source: str, position: int) -> list[str]:
    """Field names read off *ident* in its enclosing scope — the body's shape.

    When the body argument is a parameter (``post(url, e)``), the field names
    live in the enclosing function's reads of it (``e.current``, ``e.new``).
    Those reads are evidence about the body; a parameter nothing reads leaves
    the shape unknown, and unknown is what we then report.

    Two things bound what counts as such a read:

    * the **enclosing block** (see :func:`_enclosing_block`), so a sibling
      method's parameter of the same minified name contributes nothing; and
    * everything before the **response-handling chain** that follows the call.
      After ``.pipe(`` / ``.then(`` / ``.subscribe(`` the code is reading the
      *response*, and a minifier routinely names that callback's parameter with
      the same letter as the request body — ``put(url,o).pipe(t=>t.data)`` would
      otherwise contribute ``data`` as a request field it never was.
    """
    leaf = (ident or "").strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", leaf):
        return []
    block_start, block_end = _enclosing_block(source, position)
    chain = _RESPONSE_CHAIN_RE.search(source, position, block_end)
    scan_end = chain.start() if chain is not None else block_end
    window = source[block_start:scan_end]
    pattern = re.compile(_MEMBER_ACCESS_TEMPLATE.format(ident=re.escape(leaf)))
    out: list[str] = []
    for match in pattern.finditer(window):
        name = match.group(1)
        if name in _NON_BODY_MEMBERS or name.startswith("_"):
            continue
        out.append(name)
    return list(dict.fromkeys(out))[:_MAX_FIELDS]


def _form_data_fields(ident: str, source: str, position: int) -> list[str]:
    """Field names appended to a ``FormData`` body in the enclosing scope.

    ``f.append("file", blob)`` names its own field, so a multipart body is the
    one case where the shape is fully readable even though the body argument is
    an identifier. Returns ``[]`` when *ident* is not a FormData builder.
    """
    leaf = (ident or "").strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", leaf):
        return []
    block_start, block_end = _enclosing_block(source, position)
    window = source[block_start:block_end]
    if not re.search(r"(?<![\w$.])" + re.escape(leaf) + r"\s*=\s*new\s+FormData\b", window):
        return []
    pattern = re.compile(
        r"(?<![\w$.])"
        + re.escape(leaf)
        + r"""\s*\.\s*(?:append|set)\s*\(\s*["'`]([^"'`]{1,64})["'`]"""
    )
    return list(dict.fromkeys(m.group(1) for m in pattern.finditer(window)))[:_MAX_FIELDS]


def _body_fields_from_expr(expr: str, source: str, position: int) -> tuple[list[str], str | None]:
    """Body field names — and the content type they imply — from a body argument.

    Returns ``([], None)`` when the source does not reveal the shape. That is a
    fact about our knowledge; the caller records the endpoint without a body
    schema rather than inventing one.
    """
    text = (expr or "").strip()
    if not text:
        return [], None
    stringify = _JSON_STRINGIFY_RE.search(text)
    if stringify is not None:
        inner = _scan_arguments(text, stringify.end() - 1)
        if inner.args:
            text = inner.args[0].strip()
        return object_literal_fields(text), "application/json"
    if text.startswith("{"):
        return object_literal_fields(text), "application/json"
    ident = _IDENT_RE.fullmatch(text)
    if ident is not None:
        leaf = text.rsplit(".", 1)[-1]
        multipart = _form_data_fields(leaf, source, position)
        if multipart:
            return multipart, "multipart/form-data"
        return _member_access_fields(leaf, source, position), None
    return [], None


# ---------------------------------------------------------------------------
# Call-site extraction
# ---------------------------------------------------------------------------


def _statement_expression(tail: str) -> str:
    """The expression at the head of *tail*, up to the end of its statement.

    Quote- and depth-aware so a ``;`` or ``,`` inside a URL literal does not
    truncate it. Used for the ``location.href = <expr>`` navigation form, which
    has no argument list to scan.
    """
    depth = 0
    quote: str | None = None
    for i, ch in enumerate(tail):
        if quote is not None:
            if ch == "\\":
                continue
            if ch == quote:
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return tail[:i].strip()
            depth -= 1
        elif ch in ";,\n" and depth == 0:
            return tail[:i].strip()
    return tail.strip()


def _method_for_token(token: str) -> str | None:
    """HTTP method named by an invocation token, or ``None`` if it carries none."""
    lowered = token.lower()
    if lowered in ("request", "ajax"):
        return None
    if lowered == "del":
        return "DELETE"
    return lowered.upper()


def _options_object(args: list[str]) -> str:
    """The first argument that looks like an options/config object literal."""
    for arg in args:
        stripped = arg.strip()
        if stripped.startswith("{") and (
            _OPT_METHOD_RE.search(stripped)
            or _OPT_BODY_RE.search(stripped)
            or _OPT_PARAMS_RE.search(stripped)
            or _OPT_CT_RE.search(stripped)
        ):
            return stripped
    return ""


def _call_site_from_args(
    args: list[str],
    default_method: str | None,
    source: str,
    position: int,
) -> ApiCallSite | None:
    """Build an :class:`ApiCallSite` from a parsed argument list, or ``None``."""
    if not args:
        return None
    resolved, holes = _resolve_url_expression(args[0], source, position)
    route = _template_to_route(resolved, holes)
    if route is None:
        return None
    url_template, query_params = route

    options = _options_object(args[1:])
    method = default_method
    if options:
        opt_method = _OPT_METHOD_RE.search(options)
        if opt_method is not None:
            candidate = opt_method.group(1).upper()
            if candidate in _HTTP_METHODS:
                method = candidate
    if method is None:
        method = "GET"

    content_type: str | None = None
    if options:
        ct = _OPT_CT_RE.search(options)
        if ct is not None:
            content_type = ct.group(1).split(";", 1)[0].strip().lower()

    # Body: an explicit second positional argument for the method-named calls,
    # or the ``body``/``data`` key of an options object.
    body_fields: list[str] = []
    positional_body = ""
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        for arg in args[1:]:
            stripped = arg.strip()
            if not stripped or stripped is options:
                continue
            if stripped.startswith("{") and stripped == options:
                continue
            positional_body = stripped
            break
    if options:
        body_key = _OPT_BODY_RE.search(options)
        if body_key is not None:
            positional_body = _balanced_expression(options[body_key.end() :].lstrip())
    if positional_body:
        body_fields, implied_ct = _body_fields_from_expr(positional_body, source, position)
        if content_type is None:
            content_type = implied_ct

    # Angular/axios ``{params: {...}}`` declares query parameters.
    if options:
        params_key = _OPT_PARAMS_RE.search(options)
        if params_key is not None:
            tail = options[params_key.end() :].lstrip()
            literal = _balanced_object(tail)
            if literal:
                query_params = list(dict.fromkeys([*query_params, *object_literal_fields(literal)]))

    if body_fields and content_type is None:
        content_type = "application/json"

    excerpt = source[max(0, position - 40) : position + _MAX_EVIDENCE_CHARS]
    return ApiCallSite(
        method=method,
        url_template=url_template,
        query_params=tuple(dict.fromkeys(query_params)),
        body_fields=tuple(body_fields),
        content_type=content_type,
        evidence=excerpt[:_MAX_EVIDENCE_CHARS],
    )


def mine_api_call_sites(source: str) -> list[ApiCallSite]:
    """Every HTTP call site this JavaScript source declares.

    Deterministic and order-stable: results follow source order, deduped by
    (method, url_template, params, body fields). Purely textual — nothing here
    executes, fetches or parses the target's code as code.

    Args:
        source: JavaScript source text (a served bundle, typically minified).

    Returns:
        The call sites recognised, bounded by :data:`_MAX_CALL_SITES`.
    """
    text = (source or "")[:MAX_SOURCE_BYTES]
    if not text:
        return []

    found: list[ApiCallSite] = []
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    examined = 0

    def _record(site: ApiCallSite | None) -> None:
        if site is None:
            return
        key = (site.method, site.url_template, site.query_params, site.body_fields)
        if key in seen:
            return
        seen.add(key)
        found.append(site)

    for match in _METHOD_CALL_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        args = _scan_arguments(text, match.end() - 1)
        _record(
            _call_site_from_args(args.args, _method_for_token(match.group(1)), text, match.end())
        )

    for match in _BARE_CALL_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        args = _scan_arguments(text, match.end() - 1)
        first = args.args[0].strip() if args.args else ""
        # ``axios({url:...,method:...})`` — a single config object.
        if first.startswith("{"):
            url_value = re.search(r"""(?:^|[,{])\s*["']?url["']?\s*:\s*(.{0,300})""", first)
            if url_value is None:
                continue
            reshaped = [url_value.group(1).split(",", 1)[0].strip(), first]
            _record(_call_site_from_args(reshaped, None, text, match.end()))
            continue
        _record(_call_site_from_args(args.args, None, text, match.end()))

    for match in _XHR_OPEN_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        args = _scan_arguments(text, text.index("(", match.start()))
        if len(args.args) < 2:
            continue
        _record(_call_site_from_args(args.args[1:], match.group(1).upper(), text, match.end()))

    for match in _NAVIGATION_CALL_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        args = _scan_arguments(text, match.end() - 1)
        if args.args:
            _record(_call_site_from_args(args.args[:1], "GET", text, match.end()))

    for match in _NAVIGATION_ASSIGN_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        # The assigned expression runs to the end of the statement.
        tail = text[match.end() : match.end() + _MAX_ARG_CHARS]
        expression = _statement_expression(tail)
        if expression:
            _record(_call_site_from_args([expression], "GET", text, match.end()))

    logger.debug("Mined %d API call site(s) from %d bytes of JS", len(found), len(text))
    return found[:_MAX_CALL_SITES]
