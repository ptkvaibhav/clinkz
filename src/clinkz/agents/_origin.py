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

from ipaddress import ip_address
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


# ---------------------------------------------------------------------------
# One server, two names
# ---------------------------------------------------------------------------


class OriginIdentity:
    """Which normalised origins name the SAME SERVICE, from observed resolutions.

    :func:`canonical_origin` answers "is this the same string", which is right
    for a fence and wrong for a finding's identity. A target reachable as
    ``http://clinkz-juiceshop:3000`` and as ``http://172.20.0.2:3000`` is one
    service with two names, and keying on the URL string that happened to reach
    a class emitted the same missing ``Content-Security-Policy`` twice — once
    per spelling — for one issue. Neither spelling was chosen by the class or
    by the operator: the crawler resolves the host itself and reports the
    address it connected to, so a hostname goes into the plan and an address
    comes back out of the very next component.

    **The alias is OBSERVED, never inferred.** Nothing here reasons that a
    hostname and an address are related; the only thing that collapses two
    origins is a resolution reported by the code that actually connected —
    curl's ``%{remote_ip}`` at the HTTP chokepoint, the one component that
    knows what address it reached. The same rule as ``session_bearing``: the
    producer declares, the consumer reads.

    **Name-based virtual hosting is the confound, and it fails SAFE.** Two
    different hostnames on one address are routinely two different
    applications with different header posture, so an address that has been
    observed under more than one NAME is ambiguous and every origin on it keys
    on itself. Only a name and its own resolved address collapse. Over-merging
    would HIDE a finding, which is a worse failure than emitting one twice, so
    the tie is broken toward the visible error — the same direction as the
    half-open range bounds.

    **Absent an observation, an origin is its own identity**, so a run that
    resolves nothing behaves exactly as it did before this class existed.

    Scheme and port are part of the identity and are never collapsed:
    ``http://host:3000`` and ``https://host:3000`` are different services on one
    machine, and header posture is a property of the service. Only the HOST
    dimension is resolved.
    """

    def __init__(self) -> None:
        #: canonical origin -> the address it was observed to resolve to.
        self._addresses: dict[str, str] = {}
        #: (scheme, address, port) -> the distinct HOST spellings seen on it.
        #: More than one name is virtual hosting, and disqualifies the merge.
        self._names_on_address: dict[tuple[str, str, str], set[str]] = {}

    def observe(self, url: str, address: str) -> None:
        """Record that *url*'s origin was reached at *address*.

        Args:
            url: Any URL on the origin that was fetched.
            address: The peer address the fetcher actually connected to, as the
                fetcher reported it. Empty is ignored — an unobserved address
                must never merge anything.
        """
        origin = canonical_origin(url)
        addr = (address or "").strip().strip("[]").lower()
        if origin is None or not addr:
            return
        self._addresses.setdefault(origin, addr)
        parsed = urlparse(origin)
        host = (parsed.hostname or "").lower()
        if not host or _is_address_literal(host):
            # An address naming itself says nothing about virtual hosting.
            return
        try:
            port = "" if parsed.port is None else str(parsed.port)
        except ValueError:  # pragma: no cover — canonical_origin refused it
            return
        self._names_on_address.setdefault((parsed.scheme.lower(), addr, port), set()).add(host)

    def identity(self, url: str) -> str:
        """A stable key naming the SERVICE *url* lives on.

        A hostname collapses onto its own observed address; an address is
        already its own identity; anything unobserved, and anything on an
        address serving more than one name, keys on itself.

        Args:
            url: Any URL, in any spelling.

        Returns:
            The identity key. Never empty — an unkeyable value keys on its own
            raw text rather than colliding with every other unkeyable value.
        """
        origin = canonical_origin(url)
        if origin is None:
            return (url or "").strip()
        parsed = urlparse(origin)
        host = (parsed.hostname or "").lower()
        if not host or _is_address_literal(host):
            return origin
        address = self._addresses.get(origin)
        if not address:
            return origin
        try:
            port = "" if parsed.port is None else str(parsed.port)
        except ValueError:  # pragma: no cover — canonical_origin refused it
            return origin
        scheme = parsed.scheme.lower()
        if len(self._names_on_address.get((scheme, address, port), ())) > 1:
            # Virtual hosting: several names, one address. Refuse to merge.
            return origin
        return f"{scheme}://{address}" + (f":{port}" if port else "")

    def aliases(self) -> dict[str, str]:
        """Every origin observed, mapped to its identity key. For disclosure."""
        return {origin: self.identity(origin) for origin in sorted(self._addresses)}


def _is_address_literal(host: str) -> bool:
    """Whether *host* is an IP literal rather than a name needing resolution."""
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


__all__ = [
    "WEB_SCHEMES",
    "OriginIdentity",
    "canonical_origin",
    "is_web_url",
    "resolve_same_origin",
    "same_origin",
]
