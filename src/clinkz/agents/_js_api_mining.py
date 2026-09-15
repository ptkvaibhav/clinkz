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
* **The config-object form** — ``$.ajax(cfg)``, ``axios(cfg)``,
  ``client.request(cfg)``, where the whole request description sits at argument
  0 and every other idiom puts the URL. Read inline or resolved from a local a
  bundler hoisted it into.

Two things it reports that are not resolved calls:

* **Calls it could not address** (:class:`UnresolvedCallSite`). A call site
  recognised as HTTP and not turned into a route used to leave no trace at all,
  so a bundle of ``fetch(e,n)`` and an application that makes no HTTP calls
  produced byte-identical output. Only calls that are HTTP by the callee's own
  name or by a config argument's shape count — ``map.get(k)`` is not one.
* **Routes the source DECLARES** (``{path, method}`` manifests: route guards,
  gateway rules, RBAC tables, service-worker lists). A different fact from a call
  the frontend makes, kept in its own field for that reason, and the only thing a
  minified SPA states outright when it builds every URL at runtime.

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
from dataclasses import dataclass, field, replace
from enum import StrEnum

from clinkz.models.scan import MethodEvidence

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

#: How strong each evidence value is, weakest first. Used only to pick the
#: surviving value when two call sites dedupe to one endpoint.
_EVIDENCE_RANK = {
    MethodEvidence.UNREAD: 0,
    MethodEvidence.PLATFORM_DEFAULT: 1,
    MethodEvidence.NAMED: 2,
}

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
# The same key with an UNQUOTED value: ``{method: m}`` after a bundler has
# hoisted the verb into a local. The verb IS in the source, one binding away -
# measured on a synthetic bundler output, ``var m="POST";fetch(u,{method:m})``
# was reported as a GET endpoint, which is not an absence at all but a read the
# miner declined to make.
_OPT_METHOD_IDENT_RE = re.compile(
    r"""(?:^|[,{])\s*["']?method["']?\s*:\s*([A-Za-z_$][\w$.]{0,63})\s*[,}]"""
)
_OPT_BODY_RE = re.compile(r"""(?:^|[,{])\s*["']?(?:body|data)["']?\s*:""")
# The ``url`` key of a config-object call form — ``$.ajax({url, method})``,
# ``axios({url, method, data})``, ``client.request({url, method})``. The VALUE
# is taken by :func:`_balanced_expression`, never by splitting on the next
# comma: a template literal (``url: `${base}/x,y` ``) carries commas of its own
# and a split truncates the URL mid-token.
_OPT_URL_RE = re.compile(r"""(?:^|[,{])\s*["']?url["']?\s*:\s*""")
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

# ``name = {`` / ``name: {`` — an identifier bound to an object literal. Used to
# resolve a config object a bundler hoisted out of the call
# (``const o={url:u,method:"PUT"}; client.request(o)``), the same way
# :func:`_resolve_binding` already resolves a hoisted URL or verb.
_OBJECT_BIND_TEMPLATE = r"(?:^|[^\w$.]){name}\s*[=:]\s*\{{"

#: Config keys that make an object an HTTP *request description* rather than an
#: application payload. ``url`` or ``method`` only — deliberately not ``data``,
#: which is an ordinary application field name: Juice Shop's
#: ``walletService.put({balance, paymentId})`` is a call to the app's OWN
#: service wrapper, and claiming it as a call site would invent a URL for a
#: request whose real call site the miner already reads one layer down.
_CONFIG_SHAPE_RE = re.compile(r"""(?:^|[,{])\s*["']?(?:url|method)["']?\s*:""")

# A route DESCRIPTOR: an object literal pairing a path with a verb, in either
# key order. Route guards, API-gateway rules, RBAC tables, service-worker route
# lists and bot-protection manifests all express a route this way, and unlike a
# call site the verb is stated outright rather than implied by the callee.
#
# This is a declaration, not an invocation, and the difference is the whole
# reason it is read separately: it says the application HAS the route, which is
# exactly the fact a minified SPA never states at a call site it builds at
# runtime. On the live cal.com target this recovers the ONLY same-origin write
# route named anywhere in the bundle — every fetch-shaped write there addresses
# a URL computed at runtime — so without it the target's entire write surface is
# invisible to the seven Tier-1 classes gated on the verb.
_ROUTE_DESCRIPTOR_RE = re.compile(
    r"""["']?path["']?\s*:\s*["']([^"']{1,200})["']\s*,\s*["']?method["']?\s*:\s*["']([A-Za-z]{3,7})["']"""
    r"""|["']?method["']?\s*:\s*["']([A-Za-z]{3,7})["']\s*,\s*["']?path["']?\s*:\s*["']([^"']{1,200})["']"""
)

#: Leading wildcard characters a manifest uses to mean "any host/prefix".
#: ``*/api/book/event`` is one route, not a route named ``*``.
_ROUTE_WILDCARD_PREFIX = "*"


class CallSiteRejection(StrEnum):
    """Why an HTTP call site the miner SAW produced no endpoint.

    A call site we recognised as HTTP and could not read is evidence about
    surface we cannot reach — not the same fact as a route we read and found
    nothing on, and not the same fact as ``.get(k)`` on a ``Map``, which is
    correctly dropped and says nothing about the target at all.
    """

    #: An address expression was present and did not resolve to anything
    #: URL-shaped: a bare minified identifier with no local binding
    #: (``fetch(e,n)``), a call (``q(r)``), or a cross-module import.
    UNRESOLVABLE_URL = "unresolvable_url"
    #: A config object carried the request and named no ``url`` — the address
    #: lives on the client the config is handed to. socket.io's polling
    #: transport is ``this.request({method:"POST",data:a})``, whose URL is
    #: ``this.uri()`` one frame up. A different fact from an address we tried to
    #: read and could not, and the two want different fixes.
    UNNAMED_URL = "unnamed_url"
    #: The call names no argument we could read at all.
    NO_ARGUMENTS = "no_arguments"


@dataclass(frozen=True)
class UnresolvedCallSite:
    """One HTTP call site the miner recognised and could not turn into a route.

    ``method_named`` carries a verb the config DID name even though the URL did
    not resolve — socket.io's polling transport is
    ``this.request({method:"POST",data:a})``, where the verb is right there and
    the URL is ``this.uri()``. Knowing a write call site exists that we cannot
    address is worth more to a reader than a bare count.
    """

    callee: str
    reason: CallSiteRejection
    expression: str = ""
    method_named: str | None = None
    evidence: str = ""

    @property
    def names_a_write(self) -> bool:
        """Whether this unreachable call site declared a state-changing verb."""
        return (self.method_named or "").upper() in ("POST", "PUT", "PATCH", "DELETE")


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
    #: How ``method`` came to be known. ``UNREAD`` is the default because a
    #: construction that has not thought about it has not read a verb. See
    #: :class:`~clinkz.models.scan.MethodEvidence`.
    method_evidence: MethodEvidence = MethodEvidence.UNREAD

    @property
    def path_params(self) -> tuple[str, ...]:
        """Names of the ``:name`` placeholders in the URL template."""
        return tuple(
            seg[1:] for seg in self.url_template.split("/") if len(seg) > 1 and seg.startswith(":")
        )


@dataclass(frozen=True)
class MiningResult:
    """What one bundle yielded, as three separate facts.

    ``call_sites`` and ``unresolvable`` are two halves of one question — of the
    HTTP calls this frontend makes, which can we address — and they are two
    lists rather than one plus a count because the second is a disclosure, and a
    disclosure a reader cannot check is one they have to take on trust.

    ``route_declarations`` answers a DIFFERENT question and is kept apart for
    that reason. A route manifest says the application HAS this route and this
    verb; a call site says the frontend CALLS it. Folding the two together would
    make "89 call sites" include things that are not calls, and the reach
    disclosure counts only calls for the same reason.
    """

    call_sites: tuple[ApiCallSite, ...] = ()
    unresolvable: tuple[UnresolvedCallSite, ...] = ()
    route_declarations: tuple[ApiCallSite, ...] = ()


@dataclass
class _Args:
    """A parsed argument list: the raw text of each top-level argument.

    ``close_paren`` is the index of the ``)`` that ended the list, or ``-1``
    when the scan hit its bound first. The caller needs it to tell a CALL from
    a function DEFINITION, which is decided by what follows the list.
    """

    args: list[str] = field(default_factory=list)
    close_paren: int = -1


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
                return _Args(args=[a.strip() for a in out], close_paren=i)
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


def _resolve_object_binding(name: str, source: str, before: int) -> str:
    """The object-literal text identifier *name* is locally bound to, or ``""``.

    The object-shaped sibling of :func:`_resolve_binding`, and it exists for the
    same reason: a bundler routinely hoists a request config out of the call
    (``const o={url:u,method:"PUT"}; client.request(o)``), and a miner that only
    reads a literal AT the call site reads that as a call with no config at all
    — which is to say, as a ``GET`` to an unknown URL.

    Searches backwards from *before* for the nearest preceding binding, which is
    what scopes the lookup correctly when a minifier has reused ``o`` in forty
    functions.
    """
    leaf = (name or "").rsplit(".", 1)[-1].strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", leaf or ""):
        return ""
    window_start = max(0, before - _BINDING_LOOKBACK)
    window = source[window_start:before]
    pattern = re.compile(_OBJECT_BIND_TEMPLATE.format(name=re.escape(leaf)))
    best: int | None = None
    for match in pattern.finditer(window):
        best = match.end() - 1  # index of the "{"
    if best is None:
        return ""
    return _balanced_object(window[best:])


def _config_object_text(expr: str, source: str, position: int) -> str:
    """*expr* as a config-object literal — written inline or bound nearby.

    Returns ``""`` when *expr* is not a config object. An object that carries
    neither ``url`` nor ``method`` is not one: see :data:`_CONFIG_SHAPE_RE`.
    """
    text = (expr or "").strip()
    if text.startswith("{"):
        literal = _balanced_object(text)
        return literal if literal and _CONFIG_SHAPE_RE.search(literal) else ""
    if _IDENT_RE.fullmatch(text):
        literal = _resolve_object_binding(text, source, position)
        return literal if literal and _CONFIG_SHAPE_RE.search(literal) else ""
    return ""


def _config_url_expression(config: str) -> str:
    """The value expression of a config object's ``url`` key, or ``""``."""
    match = _OPT_URL_RE.search(config)
    if match is None:
        return ""
    return _balanced_expression(config[match.end() :].lstrip())


def _config_method_named(config: str, source: str, position: int) -> str | None:
    """The verb a config object names, resolving a hoisted binding, or ``None``."""
    literal = _OPT_METHOD_RE.search(config)
    if literal is not None:
        candidate = literal.group(1).upper()
        if candidate in _HTTP_METHODS:
            return candidate
    ident = _OPT_METHOD_IDENT_RE.search(config)
    if ident is not None:
        resolved = _resolve_binding(ident.group(1), source, position)
        candidate = (resolved or "").strip().strip("\"'`").upper()
        if candidate in _HTTP_METHODS:
            return candidate
    return None


def _quote_target_text(text: str) -> str:
    """Flatten target-controlled source text so it cannot restructure a document.

    The expression recorded for an unresolvable call site is a fragment of the
    TARGET's own JavaScript, and it is rendered into the client-facing Markdown
    report inside a code span. A fragment carrying a backtick and a newline
    closes that span and writes whatever follows as document structure — a
    malicious bundle can inject a heading reading "No issues found" into its own
    pentest report, observed before this existed.

    Invariant 55's shape with the direction reversed: there the danger is handing
    the target a SUPPRESSION primitive, here a FABRICATION one. Both come from
    treating bytes the target chose as something other than data.

    Flattens rather than escapes: an escape has to be correct for the consumer,
    and this string is stored in ``report.json`` and rendered into Markdown
    today. Angle brackets go too — not for Markdown's sake but for ReportLab's,
    whose ``Paragraph`` interprets a mini-markup and raises on an unbalanced tag.
    The PDF does not render this section yet, and the point of doing it at the
    producer is that whoever adds it does not have to know that.
    """
    flattened = re.sub(r"[\s<>]+", " ", (text or "").replace("`", ""))
    return flattened.strip()[:_MAX_EVIDENCE_CHARS]


def _is_addressable_expression(expr: str) -> bool:
    """Whether *expr* is a JS expression that could denote a URL at runtime.

    A POSITIVE shape test, and it is what keeps the unresolvable-call disclosure
    honest without a whole-bundle parse. ``fetch(`` occurs inside cal.com's own
    error prose — Next.js warns that a route depends on "uncached external data
    (``fetch(...)``, etc...)" — and the argument the scanner then reads is the
    literal text ``...``, which denotes nothing.

    The tempting fix is to pre-compute every string-literal span and skip
    matches inside one. That is unsound on a minified bundle and was measured
    so: a regex character class such as ``/(['"])/`` opens a quote that the
    scanner closes 39 KB later, marking **60%** of Juice Shop's main bundle as
    "inside a literal" and silently hiding 30 of its 88 readable call sites.
    Telling a regex literal from division needs real parsing context, so the
    cheap version of that guard destroys more than it protects.

    Accepts an identifier or member expression, a call, a string or template
    literal, a ``new`` expression, and a parenthesised or concatenated form of
    those — which is every shape a URL argument actually takes, resolvable or
    not.
    """
    text = (expr or "").strip()
    if not text or len(text) > _MAX_ARG_CHARS:
        return False
    if text[0] in "\"'`":
        return True
    if text.startswith(("new ", "(", "await ")):
        return True
    for term in _split_concat(text):
        candidate = term.strip()
        if not candidate:
            continue
        if candidate[0] in "\"'`" or candidate.startswith(("new ", "(", "await ")):
            return True
        if _IDENT_RE.fullmatch(candidate):
            return True
        # ``q(r)``, ``this.uri()``, ``encodeURIComponent(x)`` — a call whose
        # callee is an identifier or member expression.
        if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\(.*\)", candidate, re.S):
            return True
    return False


def _is_function_definition(source: str, close_paren: int) -> bool:
    """Whether the parameter list ending at *close_paren* belongs to a definition.

    ``fetch(e,t){...}`` inside a class body is a METHOD NAMED fetch, not a call
    to the platform's — TanStack Query defines one, and cal.com ships TanStack
    Query. No call expression can be followed directly by ``{``, so the next
    significant character decides it.
    """
    i = close_paren + 1
    limit = min(len(source), i + 8)
    while i < limit and source[i] in " \t\r\n":
        i += 1
    return i < len(source) and source[i] == "{"


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


def _has_top_level_spread(literal: str) -> bool:
    """Whether an object literal spreads another value at its OWN top level.

    ``{...n, headers: h}`` may carry a ``method`` we never see; ``{headers:
    {...h}}`` spreads one level down and its own keys are fully readable. The
    difference decides whether the call site's verb is PLATFORM_DEFAULT or
    UNREAD, so it is worth the depth tracking rather than a substring test:
    treating every nested spread as unreadable would mark most ordinary GETs
    unread, and a disclosure that fires on the common case is one an operator
    learns to skim.
    """
    depth = 0
    quote: str | None = None
    i = 0
    limit = min(len(literal), _MAX_ARG_CHARS)
    while i < limit:
        ch = literal[i]
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
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        elif ch == "." and depth == 1 and literal[i : i + 3] == "...":
            return True
        i += 1
    return False


def _unnamed_method(
    args: list[str],
    options: str,
    source: str,
    position: int,
) -> tuple[str, MethodEvidence]:
    """The verb of a call site whose invocation token named none, and how we know.

    Reached only for ``fetch`` / ``axios`` / ``.request`` / ``.ajax``, where the
    verb lives in a config argument rather than in the callee's name. Three
    outcomes, and the point of the function is that they are three:

    * the config names it in a form we can resolve -> ``NAMED``;
    * every config argument was read in full and none names a verb, so the
      idiom's own default is the verb -> ``PLATFORM_DEFAULT``;
    * a config argument exists that we cannot see into -> ``UNREAD``, and the
      ``"GET"`` returned beside it is a placeholder, not a reading.
    """
    if options:
        ident = _OPT_METHOD_IDENT_RE.search(options)
        if ident is not None:
            resolved = _resolve_binding(ident.group(1), source, position)
            candidate = (resolved or "").strip().strip("\"'`").upper()
            if candidate in _HTTP_METHODS:
                return candidate, MethodEvidence.NAMED
            # The key is there and the value is not resolvable. This is the
            # sharpest case for the third state: the source DOES name a verb and
            # we failed to read it, so calling it GET is not even an absence.
            return "GET", MethodEvidence.UNREAD
    for arg in args[1:]:
        stripped = arg.strip()
        if not stripped:
            continue
        if not stripped.startswith("{") or _has_top_level_spread(stripped):
            return "GET", MethodEvidence.UNREAD
    return "GET", MethodEvidence.PLATFORM_DEFAULT


def _options_object(args: list[str], source: str, position: int) -> str:
    """The first argument that is an options/config object.

    Written inline, or bound to an identifier nearby — the form a bundler leaves
    behind after hoisting a shared config out of the call.

    *source* and *position* are REQUIRED rather than defaulted. A defaulted
    ``source=""`` would silently disable the binding resolution for any caller
    that forgot it, which is invariant 67's law: a control that is an optional
    parameter with a permissive default makes a reader only as thorough as its
    least careful caller.
    """
    for arg in args:
        stripped = arg.strip()
        if stripped.startswith("{") and (
            _OPT_METHOD_RE.search(stripped)
            or _OPT_METHOD_IDENT_RE.search(stripped)
            or _OPT_BODY_RE.search(stripped)
            or _OPT_PARAMS_RE.search(stripped)
            or _OPT_CT_RE.search(stripped)
        ):
            return stripped
        if _IDENT_RE.fullmatch(stripped):
            bound = _resolve_object_binding(stripped, source, position)
            if bound and (
                _OPT_METHOD_RE.search(bound)
                or _OPT_METHOD_IDENT_RE.search(bound)
                or _OPT_BODY_RE.search(bound)
                or _OPT_PARAMS_RE.search(bound)
                or _OPT_CT_RE.search(bound)
            ):
                return bound
    return ""


def _config_call_args(
    args: list[str],
    source: str,
    position: int,
) -> tuple[list[str], str] | None:
    """Reshape a config-object call into ``([url_expr, config], config)``.

    The config-object form — ``$.ajax(cfg)``, ``axios(cfg)``,
    ``client.request(cfg)`` — puts the whole request description at argument 0,
    where every other idiom puts the URL. Reading argument 0 as a URL there is
    reading a request description as a route name, so the call resolves to
    nothing and the site is dropped with its verb unexamined.

    Returns ``None`` when argument 0 is not a config object, so the caller falls
    through to the ordinary URL-at-argument-0 path unchanged.
    """
    if not args:
        return None
    config = _config_object_text(args[0], source, position)
    if not config:
        return None
    url_expr = _config_url_expression(config)
    return [url_expr, config], config


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

    options = _options_object(args[1:], source, position)
    method = default_method
    # The invocation token named the verb (``.post(``, ``open("PUT",``, a
    # navigation), or the XHR literal did. Either way it was READ.
    evidence = MethodEvidence.NAMED if default_method is not None else None
    if options:
        opt_method = _OPT_METHOD_RE.search(options)
        if opt_method is not None:
            candidate = opt_method.group(1).upper()
            if candidate in _HTTP_METHODS:
                method = candidate
                evidence = MethodEvidence.NAMED
    if evidence is None:
        # ``if method is None: method = "GET"`` used to live here, and it spelled
        # an absence as a measurement: a call site whose verb the miner could not
        # read became byte-identical to one it read AS GET. ``GET`` is the value
        # that removes an endpoint from every write-family class, so the absence
        # was not a degraded endpoint but a silently missing one.
        method, evidence = _unnamed_method(args, options, source, position)

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
        method_evidence=evidence,
    )


def _mine_route_declarations(text: str) -> list[ApiCallSite]:
    """Routes the source DECLARES with their verbs, from ``{path, method}`` pairs.

    Held to the same bar as a call site and no lower: the path must survive
    :func:`_template_to_route` as URL-shaped, and the verb must be one of
    :data:`_HTTP_METHODS` written as a literal — so the evidence is
    :attr:`~clinkz.models.scan.MethodEvidence.NAMED`, never a default.

    No body shape is claimed. A manifest names the route and says nothing about
    what it accepts, and inventing a body here would be the fabrication the
    call-site reader is careful never to make.

    **What ``NAMED`` means here, precisely.** The TARGET's own bundle asserted
    this route and this verb. That is the same standing a mined call site has —
    a fabricated ``axios({url, method})`` could already steer which endpoints
    reach the verb-gated classes — and it is a different fact from a verb read
    off an ``Allow`` header, which the target also controls but has to serve
    from the route itself. Nothing downstream is loosened by it: the emitted
    endpoint still passes ``is_state_changing_url`` at the discovery union and
    the destructive vocabulary at dispatch.
    """
    out: list[ApiCallSite] = []
    for match in _ROUTE_DESCRIPTOR_RE.finditer(text):
        path = (match.group(1) or match.group(4) or "").strip()
        verb = (match.group(2) or match.group(3) or "").upper()
        if verb not in _HTTP_METHODS:
            continue
        path = path.lstrip(_ROUTE_WILDCARD_PREFIX)
        if not path.startswith("/"):
            continue
        route = _template_to_route(path, [])
        if route is None:
            continue
        url_template, query_params = route
        excerpt = text[max(0, match.start() - 40) : match.end() + 40]
        out.append(
            ApiCallSite(
                method=verb,
                url_template=url_template,
                query_params=tuple(query_params),
                evidence=excerpt[:_MAX_EVIDENCE_CHARS],
                method_evidence=MethodEvidence.NAMED,
            )
        )
        if len(out) >= _MAX_CALL_SITES:
            break
    return out


def mine_api_call_sites(source: str) -> list[ApiCallSite]:
    """Every HTTP call site this JavaScript source declares.

    The resolved half of :func:`mine_api_surface`, kept as the name every
    existing caller uses. Prefer :func:`mine_api_surface` where the calls that
    did NOT resolve matter — which is anywhere the result feeds a coverage
    claim.
    """
    return list(mine_api_surface(source).call_sites)


def mine_api_surface(source: str) -> MiningResult:
    """Every HTTP call site this source declares, resolved AND unresolvable.

    Deterministic and order-stable: results follow source order, deduped by
    (method, url_template, params, body fields). Purely textual — nothing here
    executes, fetches or parses the target's code as code.

    The second list is the point. A call site the miner recognises as HTTP and
    cannot turn into a route is a statement about **our** reach, not about the
    target's surface, and until now it left no trace at all: ``fetch(e,n)`` in a
    minified bundle simply produced nothing, and a bundle of nothing but such
    calls was indistinguishable from an application that makes none. Only calls
    that are HTTP *by the callee's own name* (``fetch``, ``axios``, XHR) or by
    the *shape of a config argument* are counted, so ``map.get(k)`` — which is
    most of what these regexes match on a real bundle — stays correctly silent.

    Args:
        source: JavaScript source text (a served bundle, typically minified).

    Returns:
        The call sites recognised, the HTTP calls that resolved to nothing, and
        the routes the source DECLARES with their verbs — each bounded by
        :data:`_MAX_CALL_SITES`.
    """
    text = (source or "")[:MAX_SOURCE_BYTES]
    if not text:
        return MiningResult()

    found: list[ApiCallSite] = []
    unresolved: list[UnresolvedCallSite] = []
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    seen_index: dict[tuple[str, str, tuple[str, ...], tuple[str, ...]], int] = {}
    examined = 0

    def _reject(
        callee: str,
        url_expression: str,
        config: str,
        position: int,
    ) -> None:
        """Record an HTTP call site that produced no route.

        *url_expression* is the argument that was supposed to DENOTE the URL —
        which on the config-object form is the config's ``url`` value, not
        argument 0. Passing the config there would test a request description
        for URL-addressability and silently discard the most useful entry the
        disclosure has: a call that names ``POST`` and no address.
        """
        if len(unresolved) >= _MAX_CALL_SITES:
            return
        raw = (url_expression or "").strip()
        if raw and not _is_addressable_expression(raw):
            return
        expression = _quote_target_text(raw)
        if expression:
            reason = CallSiteRejection.UNRESOLVABLE_URL
        elif config:
            reason = CallSiteRejection.UNNAMED_URL
        else:
            reason = CallSiteRejection.NO_ARGUMENTS
        unresolved.append(
            UnresolvedCallSite(
                callee=callee,
                reason=reason,
                expression=expression,
                method_named=(_config_method_named(config, text, position) if config else None),
                evidence=_quote_target_text(
                    text[max(0, position - 40) : position + _MAX_EVIDENCE_CHARS]
                ),
            )
        )

    def _record(site: ApiCallSite | None) -> None:
        if site is None:
            return
        key = (site.method, site.url_template, site.query_params, site.body_fields)
        if key in seen:
            # Same route, same verb, same shape - but possibly different
            # EVIDENCE, and the two directions are not symmetric. A route with
            # one call site we read as GET and another we could not read at all
            # is a route where an unknown verb is still in play, so the weaker
            # claim is the true one and the duplicate must not be dropped
            # silently in favour of the stronger. Downgrading costs an OPTIONS
            # probe and a line of disclosure; keeping the stronger costs the
            # write surface.
            index = seen_index[key]
            if _EVIDENCE_RANK[site.method_evidence] < _EVIDENCE_RANK[found[index].method_evidence]:
                found[index] = replace(found[index], method_evidence=site.method_evidence)
            return
        seen.add(key)
        seen_index[key] = len(found)
        found.append(site)

    for match in _METHOD_CALL_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        token = match.group(1)
        args = _scan_arguments(text, match.end() - 1)
        # ``.request(cfg)`` / ``.ajax(cfg)`` — the whole request description sits
        # where every other idiom puts the URL. Tried first, and only when the
        # argument really is a config object, so ``.post(url, body)`` is
        # untouched.
        reshaped = _config_call_args(args.args, text, match.end())
        if reshaped is not None:
            config_args, config = reshaped
            site = _call_site_from_args(config_args, None, text, match.end())
            if site is None:
                _reject(f".{token.lower()}", config_args[0], config, match.end())
            _record(site)
            continue
        site = _call_site_from_args(args.args, _method_for_token(token), text, match.end())
        # A bare ``.get(k)``/``.set(k,v)`` is a Map, not a route, and its drop is
        # the filter working. Only the config-object form above is HTTP-certain
        # here, so nothing else on this path is disclosed.
        _record(site)

    for match in _BARE_CALL_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        callee = match.group(1).lower()
        args = _scan_arguments(text, match.end() - 1)
        if args.close_paren >= 0 and _is_function_definition(text, args.close_paren):
            # ``fetch(e,t){...}`` is a method NAMED fetch — TanStack Query ships
            # one — not a call to the platform's.
            continue
        # ``axios({url:...,method:...})`` — a single config object, inline or
        # hoisted into a local by the bundler.
        reshaped = _config_call_args(args.args, text, match.end())
        if reshaped is not None:
            config_args, config = reshaped
            site = _call_site_from_args(config_args, None, text, match.end())
            if site is None:
                _reject(callee, config_args[0], config, match.end())
            _record(site)
            continue
        site = _call_site_from_args(args.args, None, text, match.end())
        if site is None:
            _reject(
                callee,
                args.args[0] if args.args else "",
                _options_object(args.args[1:], text, match.end()),
                match.end(),
            )
        _record(site)

    for match in _XHR_OPEN_RE.finditer(text):
        if examined >= _MAX_CALL_SITES:
            break
        examined += 1
        args = _scan_arguments(text, text.index("(", match.start()))
        if len(args.args) < 2:
            continue
        site = _call_site_from_args(args.args[1:], match.group(1).upper(), text, match.end())
        if site is None:
            # The verb is in the literal we matched on, so this is the one
            # rejection that always knows what it could not reach.
            _reject(
                "xhr.open",
                args.args[1],
                f'{{method:"{match.group(1).upper()}"}}',
                match.end(),
            )
        _record(site)

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

    logger.debug(
        "Mined %d API call site(s) and %d unresolvable HTTP call(s) from %d bytes of JS",
        len(found),
        len(unresolved),
        len(text),
    )
    return MiningResult(
        call_sites=tuple(found[:_MAX_CALL_SITES]),
        unresolvable=tuple(unresolved[:_MAX_CALL_SITES]),
        route_declarations=tuple(_mine_route_declarations(text)),
    )
