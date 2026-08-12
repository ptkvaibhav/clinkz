"""The one origin/scheme fence.

Every subsystem that takes a URL from somewhere other than its own code — an
LLM plan, the target's own HTML, a JavaScript bundle, a route literal — has to
answer the same question before acting on it: *does this name the origin we are
engaged against?* The question has two dimensions, and the second one has now
been missed twice in the same week by two different code paths:

  * **Host.** Everybody remembered this one.
  * **Scheme.** ``840ddec`` fixed a planner fence that compared
    ``scheme in ("http", "https")`` *before* checking the destination, so a
    planned ``file://`` / ``ftp://`` / ``gopher://`` URL fell through to the
    relative branch — and :func:`urllib.parse.urljoin` returns a foreign-scheme
    absolute reference UNCHANGED rather than resolving it against the base, so
    the destination the model chose survived the check written to refuse it.
    ``bb21d8f`` then fixed the identical omission in a brand-new route-discovery
    page-seed fetcher, which compared ``netloc`` alone: the target's own HTML can
    offer ``ftp://<same-host>/x``, matching netloc while naming a protocol the
    subsystem never intended to speak.

Two independent instances of one defect in one week is not two mistakes; it is a
missing abstraction. Per-site checks will keep reintroducing it, because the host
comparison is the obvious half and each new call site re-derives only the obvious
half. So there is one helper, and the scheme dimension is not something a caller
can forget to write — it is inside the function they call.

The normalisation matters as much as the fence, because over-refusal costs
coverage and calls it safety:

  * scheme and host are lowercased (``urlparse`` lowercases the scheme but not
    the netloc), so ``http://HOST`` and ``http://host`` are one origin;
  * the scheme's default port is dropped, so ``http://host:80`` and
    ``http://host`` are one origin rather than two;
  * **userinfo is deliberately KEPT** — ``http://target@evil.example`` is the
    attacker's host wearing the target's name and must never compare equal to
    the target;
  * a malformed port (``http://host:notaport``) is not an origin we can reason
    about, so it is refused rather than guessed at.

Only ``http`` and ``https`` are web schemes. :func:`canonical_origin` will
normalise any scheme (the planner's fence needs to *recognise* a ``file://`` URL
in order to refuse it), while :func:`same_origin` and :func:`resolve_same_origin`
— the two a fetcher should reach for — additionally require a web scheme on both
sides.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

#: The only schemes any Clinkz fetcher speaks. A URL naming anything else is out
#: of this engine's protocol surface regardless of whose host it points at.
WEB_SCHEMES: frozenset[str] = frozenset({"http", "https"})

#: Default port per web scheme, dropped during normalisation.
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def canonical_origin(url: str) -> str | None:
    """``scheme://[userinfo@]host[:port]`` for *url*, normalised, or ``None``.

    ``None`` means "not an absolute URL naming an addressable host" — a relative
    reference, ``javascript:alert(1)``, ``file:///etc/passwd``, a ``mailto:``, or
    a URL whose port does not parse. Callers distinguish those two cases
    themselves: a *planner* fence treats an unaddressable absolute URL as
    off-origin (refuse it), while a *resolver* treats a relative reference as
    on-origin (join it against the base).

    Any scheme is normalised here, including non-web ones, so a caller can name
    what it is refusing. Use :func:`is_web_url` when the question is whether the
    fetcher can speak it.

    Args:
        url: The candidate URL, in any spelling.

    Returns:
        The normalised origin, or ``None`` if *url* is not an absolute URL
        naming an addressable host.
    """
    parsed = urlparse((url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return None
    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:  # malformed port — not an origin we can reason about
        return None
    if not host:
        return None
    scheme = parsed.scheme.lower()
    if port is not None and port == _DEFAULT_PORTS.get(scheme):
        port = None
    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    return f"{scheme}://{userinfo}{host}" + (f":{port}" if port is not None else "")


def is_web_url(url: str) -> bool:
    """Whether *url* is an absolute ``http``/``https`` URL naming a real host.

    The scheme half of the fence, on its own, for the callers that need to test
    it separately from the host comparison.
    """
    parsed = urlparse((url or "").strip())
    if parsed.scheme.lower() not in WEB_SCHEMES:
        return False
    return canonical_origin(url) is not None


def same_origin(candidate: str, base_url: str) -> bool:
    """Whether *candidate* resolves to *base_url*'s origin, over a web scheme.

    A relative *candidate* is resolved against *base_url* first, so
    ``same_origin("/api/x", "http://t/")`` is ``True``. A foreign scheme is
    ``False`` even when the host matches, which is the half that keeps getting
    dropped: ``urljoin`` hands back ``ftp://same-host/x`` unchanged, and its
    netloc compares equal to the base's.

    Args:
        candidate: An absolute or relative URL.
        base_url: The origin to compare against. A non-web base is never equal
            to anything — a fetcher with no legitimate origin has nothing to
            admit a candidate to.

    Returns:
        ``True`` only when both sides are web URLs on the same normalised origin.
    """
    base = canonical_origin(base_url)
    if base is None or not is_web_url(base_url):
        return False
    resolved = _resolve(candidate, base_url)
    if resolved is None:
        return False
    return is_web_url(resolved) and canonical_origin(resolved) == base


def resolve_same_origin(candidate: str, base_url: str) -> str | None:
    """Resolve *candidate* against *base_url*, or ``None`` if it leaves the origin.

    The fetcher's form of :func:`same_origin`: one call that both applies the
    fence and hands back the absolute URL to fetch, so a caller cannot fence one
    string and then fetch a differently-resolved one.

    Args:
        candidate: An absolute or relative URL.
        base_url: The origin to resolve against and fence to.

    Returns:
        The absolute URL, or ``None`` when it is off-origin, non-web, or
        unresolvable.
    """
    resolved = _resolve(candidate, base_url)
    if resolved is None:
        return None
    return resolved if same_origin(resolved, base_url) else None


def _resolve(candidate: str, base_url: str) -> str | None:
    """``urljoin`` with the failure modes made explicit.

    ``urljoin`` raises on some malformed inputs and silently returns a
    foreign-scheme reference unchanged on others; both are the caller's problem,
    so both are surfaced here rather than at four separate call sites.
    """
    raw = (candidate or "").strip()
    if not raw:
        return None
    try:
        return urljoin(base_url, raw)
    except ValueError:
        return None


__all__ = [
    "WEB_SCHEMES",
    "canonical_origin",
    "is_web_url",
    "resolve_same_origin",
    "same_origin",
]
