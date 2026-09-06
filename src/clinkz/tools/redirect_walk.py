"""One hop-walking primitive, for every exchange that must not follow blindly.

A redirect hands the destination of the NEXT request to whoever shaped THIS
response. That is a strictly weaker position than controlling the form's HTML,
and it was enough to move the engagement's plaintext credentials to a host no
scope check had ever seen: a **307** preserves the method and the body, and both
credential arms dispatched with ``-L`` / ``allow_redirects=True``.

The fix was three classifiers, one per transport — aiohttp, curl, and the JSON
arm over :class:`~clinkz.tools.http_client.HTTPClientTool`. Three
implementations of one rule is two opportunities to drift, and the third site was
found by accident rather than by design. So the rule lives here once, and every
arm calls it:

  1. **Observe the 3xx** rather than letting the transport act on it.
  2. **Resolve ``Location`` against the URL that ANSWERED** — not against the URL
     we asked for, which differ the moment a hop has already been taken.
  3. **Scope-check the destination**, and refuse rather than drop. A credential
     POST that vanished into a redirect and one the application rejected read
     identically to every reader downstream.
  4. **Decide re-POST vs bodyless GET by STATUS** — 307/308 preserve the method
     and body, 301/302/303 degrade to a GET. The degrade is one-way: once a hop
     has dropped the body, a later 307 does not get to pick it back up.
  5. **Cap the hops.** A loop is a target misconfiguration, not a reason to keep
     offering credentials.

Rule 3 binds the bodyless hops too. They carry no credential, but they carry the
cookie jar and whatever ``Authorization`` header the caller set, and a session
sent to an out-of-scope host is a session handed over. It also binds a walk that
never carried a body at all — the login page GET, the destination read behind an
authorization boundary — because a request to a host nothing authorised is
outside scope whether or not it carries anything.

``chain`` has ONE meaning here, deliberately: **the absolute destinations a
redirect actually pointed to, in hop order.** The two transports used to disagree
about it — aiohttp recorded the URLs that ANSWERED (``resp.history``) and curl
the raw ``Location`` header values, unresolved — and
:meth:`~clinkz.tools.auth.WebAuthenticator._check_login_success` reads that field
to decide whether a login succeeded. Under the aiohttp meaning a login POST to a
form ``action`` that answers "302 back to /login?error=1" produced a chain whose
one entry was the ACTION path, which differs from the login path, which the
success oracle reads as "redirected away, therefore logged in". A rejected
credential scored as a session.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, NamedTuple
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

#: Statuses that name a next request.
REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

#: The two that PRESERVE the method and the body. A 307/308 answer to a
#: credential POST re-sends the plaintext credentials verbatim to whatever the
#: ``Location`` names — which is why a credential POST may not be dispatched with
#: redirect-following on. The other three degrade the follow-up to a bodyless
#: GET, so they cannot carry a credential; their destination is scope-checked all
#: the same, because the follow-up carries the cookie jar.
BODY_PRESERVING_REDIRECTS: frozenset[int] = frozenset({307, 308})

#: How many hops a walk takes before giving up and reporting the last response it
#: actually got.
MAX_REDIRECT_HOPS = 5

#: What :attr:`RedirectHop.action` can be.
STOP = "stop"
RESEND = "resend"
GET = "get"
REFUSE = "refuse"


class RedirectHop(NamedTuple):
    """What to do with the response in hand.

    ``action`` is one of:

    * :data:`STOP` — not a redirect, or no ``Location``. The response in hand is
      the answer.
    * :data:`RESEND` — a 307/308. The method and body are preserved, so the next
      hop carries whatever this one carried, and it goes to an in-scope
      destination.
    * :data:`GET` — a 301/302/303. The follow-up is a bodyless GET, so no
      credential travels with it; the destination is still scope-checked because
      the session material does.
    * :data:`REFUSE` — the destination is outside the engagement scope. Nothing
      is dispatched to it, and ``reason`` says so in the operator's words.
    """

    action: str
    url: str
    reason: str


class HopResponse(NamedTuple):
    """One response, in the terms the walk needs to classify it.

    Attributes:
        status: The status code.
        headers: The response headers, for ``Location``.
        landed_url: The URL that actually ANSWERED, when the transport can say.
            Empty means "the URL we asked for", which is the same thing for every
            transport this walk drives — none of them follow redirects
            themselves any more.
        payload: Whatever the caller needs handed back — a body, a raw dump, a
            parsed model. The walk never reads it.
        set_cookies: Every ``Set-Cookie`` header this hop carried, one entry per
            header, verbatim. ``headers`` is a ``dict`` and a response that sets
            two cookies sends two headers of the same name, so the dict keeps one
            of them and which one it keeps depends on the transport. The walk
            never reads this either — it exists so the TRANSPORT declares the
            list at the only point it still has it, rather than a consumer
            splitting the joined string on a separator somebody guessed.
    """

    status: int
    headers: dict[str, str]
    landed_url: str = ""
    payload: Any = None
    set_cookies: tuple[str, ...] = ()


class WalkOutcome(NamedTuple):
    """The end of a walk.

    Attributes:
        response: The last response actually received.
        chain: The absolute destinations a redirect pointed to, in hop order.
            Empty when nothing redirected. See the module docstring: this is the
            field's ONE meaning, and a success oracle reads it.
        refusal: The refused hop, when a destination was outside scope. The walk
            stops there and nothing is dispatched to it.
        exhausted: Whether the hop cap ended the walk rather than an answer.
    """

    response: HopResponse
    chain: list[str]
    refusal: RedirectHop | None
    exhausted: bool


def classify_redirect(
    status: int,
    headers: dict[str, str] | None,
    answered_url: str,
    *,
    in_scope: Callable[[str], None],
) -> RedirectHop:
    """Decide the next hop — scope-checked, deliberately.

    Args:
        status: The status of the response in hand.
        headers: Its headers, for ``Location``.
        answered_url: The URL that produced this response. A relative
            ``Location`` resolves against it, which is why it is the URL that
            ANSWERED and not the URL the walk started from.
        in_scope: The engagement's scope gate. Raises on a target outside scope;
            a callable rather than a scope object so each caller passes the gate
            it already passes every other request through, refusal record
            included, instead of a second copy of the containment test.

    Returns:
        The hop to take. See :class:`RedirectHop`.
    """
    if status not in REDIRECT_STATUSES:
        return RedirectHop(STOP, "", "")

    location = ""
    for key, value in (headers or {}).items():
        if key.lower() == "location":
            location = (value or "").strip()
            break
    if not location:
        # A 3xx with nothing to redirect TO. The response in hand is all there
        # is, and reading it as a redirect would invent a chain.
        return RedirectHop(STOP, "", "")

    destination = urljoin(answered_url, location)
    try:
        in_scope(destination)
    except ValueError:
        return RedirectHop(
            REFUSE,
            destination,
            (
                f"answered {status} redirecting to {destination}, which is outside "
                "the engagement scope — the redirect was NOT followed, so nothing "
                "was offered to that host"
            ),
        )

    if status in BODY_PRESERVING_REDIRECTS:
        return RedirectHop(RESEND, destination, "")
    return RedirectHop(GET, destination, "")


async def walk_redirects(
    *,
    start_url: str,
    dispatch: Callable[[str, bool], Awaitable[HopResponse]],
    in_scope: Callable[[str], None],
    carries_body: bool = False,
    max_hops: int = MAX_REDIRECT_HOPS,
    label: str = "",
    log: logging.Logger | None = None,
) -> WalkOutcome:
    """Walk a redirect chain one deliberate request at a time.

    Args:
        start_url: Where the exchange begins. Already scope-checked by the
            caller — this walk checks every destination AFTER it.
        dispatch: Sends one hop. Called as ``dispatch(url, carries_body)`` and
            returns the response; the caller owns the transport, the encoding,
            and any per-hop bookkeeping it needs (accumulating raw dumps, say).
        in_scope: The engagement's scope gate; see :func:`classify_redirect`.
        carries_body: Whether the FIRST hop carries a request body. A credential
            POST does; a login-page GET does not. The flag decays one way: a
            301/302/303 drops the body, and no later 307 restores it. RFC 7231
            says the follow-up to a 307 repeats the method it answered, and that
            method is by then a GET — re-acquiring the body would offer the
            credentials to a third destination the first response never named.
        max_hops: How many redirects to follow before reporting the last
            response instead.
        label: What this walk is, for the exhaustion warning.
        log: Where to warn. Defaults to this module's logger.

    Returns:
        A :class:`WalkOutcome`.
    """
    url = start_url
    carrying = carries_body
    chain: list[str] = []
    response = HopResponse(0, {})

    for _hop in range(max_hops + 1):
        response = await dispatch(url, carrying)
        answered = response.landed_url or url
        hop = classify_redirect(response.status, response.headers, answered, in_scope=in_scope)
        if hop.action == REFUSE:
            return WalkOutcome(response, chain, hop, False)
        if hop.action == STOP:
            return WalkOutcome(response, chain, None, False)
        chain.append(hop.url)
        url = hop.url
        carrying = carrying and hop.action == RESEND

    (log or logger).warning(
        "%s did not settle within %d redirects — reporting the last response "
        "rather than following further",
        label or f"the exchange at {start_url}",
        max_hops,
    )
    return WalkOutcome(response, chain, None, True)
