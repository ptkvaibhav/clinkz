"""The adaptive-auth loop's request path — the engagement's own, not a second one.

:class:`~clinkz.engagement.auth_agent.AuthAgentLoop` takes an injected
:class:`~clinkz.engagement.auth_agent.CredentialDispatcher` for the same reason
:mod:`clinkz.engagement.auth_state` takes an injected probe: the logic has to be
exercisable with no network, and the real path has to be the engagement's real
path rather than a convenient bare client. This module is that real path.

Every request made here goes through :class:`~clinkz.tools.http_client.
HTTPClientTool`, which is what makes a proposal inherit — without this module
restating any of it — the engagement's scope enforcement, the safety governor's
rate limit and concurrency slot, the per-account credential budget, the action
log, the docker/host execution routing and the redirect walk that scope-checks
every hop rather than handing ``-L`` to the transport.

Two decisions are this module's own.

**The episode carries its own cookie jar** (``session_mode='isolated'``). The
loop's first turn is often a read whose only purpose is to be issued a token the
credential POST must then present, so cookies plainly have to persist *across*
the episode. They must equally not leak *out* of it: the engagement's shared jar
may already hold a session from a default-credential sweep, and a proposal
answered by a route that reflects whatever it is sent would then produce a
"session" the engagement handed itself. Isolated is exactly that pair of
properties — explicit cookies go out on the wire, nothing that comes back enters
the shared jar — so the material the assertion is finally run against is
material *this episode* collected.

**A refusal is reported as a refusal.** ``HTTPClientTool`` returns a safety
refusal as an error-shaped response rather than raising, which is right for a
methodology probe and wrong here for the same reason it was wrong in the JSON
auth arm: the caller's next move on a soft failure is to try another
destination, and trying another destination is the thing being refused. The
category is lifted onto :attr:`~clinkz.engagement.auth_agent.DispatchResponse.
refused_by_rails`, the loop stops, and the transcript says the rails stopped it
rather than that the application did.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from clinkz.engagement.auth_agent import DispatchResponse

logger = logging.getLogger(__name__)

#: How the loop's requests declare their session. ``isolated`` sends the
#: episode's own cookies and keeps every ``Set-Cookie`` out of the engagement's
#: shared jar. See the module docstring for why neither ``ambient`` nor ``none``
#: is right here.
EPISODE_SESSION_MODE = "isolated"


class HttpToolDispatcher:
    """A :class:`~clinkz.engagement.auth_agent.CredentialDispatcher` over the real client.

    Stateful by design: the jar it accumulates is the episode, and the loop's
    proof rests on it. Construct one per role, per episode.
    """

    def __init__(
        self,
        scope: Any,
        engagement_id: str,
        *,
        timeout: int = 20,
        control_markers: list[str] | None = None,
    ) -> None:
        self._scope = scope
        self._engagement_id = engagement_id
        self._timeout = timeout
        # The lockout-vocabulary phrases the deterministic pass observed the
        # LOGIN PAGE shipping. Armed on the chokepoint beside the account, for
        # the reason every marker oracle in this engine takes a control: a
        # phrase the target serves whatever it is sent is the application's own
        # vocabulary, not evidence about this response.
        #
        # It matters more here than anywhere else. The deterministic pass has
        # already spent part of the per-account budget when this layer starts,
        # so a false stop does not cost a retry — it costs the entire adaptive
        # episode, and the transcript then records NOT_ATTEMPTED for a reason
        # that was never about the target. Measured on cal.diy, whose login page
        # ships "rate limit" and "try again later" in 383 KB of shell.
        #
        # The phrases rather than the page, because that is the whole of what
        # the comparison uses and the page is large enough to matter.
        self._control_body = " ".join(control_markers or [])
        #: Every cookie this episode has been issued, in the order it was
        #: issued. Presented on each subsequent request and handed to the
        #: assertion at the end; never written to the transcript.
        self._jar: dict[str, str] = {}

    @property
    def jar(self) -> dict[str, str]:
        """The episode's accumulated cookies."""
        return dict(self._jar)

    async def read(self, url: str, method: str) -> DispatchResponse:
        """Issue a safe-method request carrying no credential.

        Args:
            url: Where. Already scope-checked by the proposal gate, and checked
                again by ``validate_input`` — deliberately twice, because the
                gate judges a proposal and the tool judges a request, and only
                the second one is on the path every other request takes.
            method: ``GET`` / ``HEAD`` / ``OPTIONS``, constrained by the gate.

        Returns:
            A :class:`~clinkz.engagement.auth_agent.DispatchResponse`.
        """
        return await self._send(
            {
                "method": method,
                "url": url,
                "headers": {"Accept": "application/json, text/html;q=0.9"},
                "cookies": dict(self._jar),
                "follow_redirects": False,
                "session_mode": EPISODE_SESSION_MODE,
            },
            account="",
        )

    async def post_credentials(
        self,
        url: str,
        *,
        content_type: str,
        fields: dict[str, str],
        account: str,
    ) -> DispatchResponse:
        """POST a credential body, counted against the per-account budget.

        ``account`` is what makes this countable. An unnamed credential POST is
        invisible to the budget that exists to keep this engine from locking a
        client's account (invariant 96), and the whole point of routing the
        adaptive layer through this class rather than a bare client is that its
        proposals are bounded by the same number the deterministic attempt spent
        from.

        The body is encoded here, from the two names the proposal gave and the
        values the engine holds. Nothing a model wrote reaches the wire.
        """
        body, headers = _encode(fields, content_type)
        return await self._send(
            {
                "method": "POST",
                "url": url,
                "headers": headers,
                "body": body,
                "cookies": dict(self._jar),
                "follow_redirects": False,
                "session_mode": EPISODE_SESSION_MODE,
            },
            account=account,
        )

    async def _send(self, request: dict[str, Any], *, account: str) -> DispatchResponse:
        """One request through the engagement's HTTP chokepoint."""
        from clinkz.tools.auth import _cookies_from_set_cookie
        from clinkz.tools.http_client import HTTPClientTool

        http = HTTPClientTool(
            scope=self._scope, engagement_id=self._engagement_id, timeout=self._timeout
        )
        # The chokepoint takes the governor slot and counts the attempt. Naming
        # the account here is what declares the request a login rather than a
        # credential change, and what puts "credential attempt N of M for
        # <account>" in the client-facing action log.
        http.credential_account = account
        http.credential_control_body = self._control_body if account else ""
        # The claim on the reserved share. This layer runs only after the
        # deterministic pass has failed, which means the deterministic pass has
        # already spent from this account — measured at 8 of 8 on cal.diy — so
        # without the claim the loop is starved by construction and records
        # NOT_ATTEMPTED on every target it exists for.
        http.credential_reserve = True
        try:
            parsed = http.parse_output(await http.execute(http.validate_input(request)))
        except Exception as exc:  # noqa: BLE001 — a dispatch failure is an observation
            logger.warning("Adaptive-auth dispatch to %s failed: %s", request["url"], exc)
            return DispatchResponse(error=str(exc))

        issued = _cookies_from_set_cookie(parsed.set_cookie)
        self._jar.update(issued)
        return DispatchResponse(
            status=parsed.status_code,
            headers=parsed.response_headers or {},
            body=parsed.response_body or "",
            set_cookie_names=sorted(issued),
            cookies=dict(self._jar),
            error=parsed.error or "",
            refused_by_rails=parsed.safety_refusal or "",
        )


def _encode(fields: dict[str, str], content_type: str) -> tuple[str, dict[str, str]]:
    """Encode a credential body. The authenticator's own two shapes, and no third.

    Not imported from :mod:`clinkz.tools.auth` because that one is a static
    method on the tool and importing a private member across a package boundary
    to save six lines is how a refactor over there becomes an outage over here.
    The two are held together by
    :data:`~clinkz.engagement.auth_agent.ENCODABLE_CONTENT_TYPES`, which the gate
    enforces and a test asserts is the same set the authenticator negotiates.
    """
    if content_type == "application/json":
        import json

        return json.dumps(fields), {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    return urlencode(fields), {"Content-Type": "application/x-www-form-urlencoded"}


__all__ = ["EPISODE_SESSION_MODE", "HttpToolDispatcher"]
