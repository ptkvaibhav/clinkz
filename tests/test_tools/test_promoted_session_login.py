"""The positive control for the promoted-session login — end to end, and it must authenticate.

**No target this project owns has this shape**, which is the whole reason this
file exists. DVWA sets a fresh ``PHPSESSID`` on the credential POST; Juice Shop
returns a JWT; Meridian sets ``meridian_portal``. All three give the credential
exchange something the POST itself produced, so all three pass whether or not
the deferral branch works at all. A branch nothing reaches is indistinguishable
from a branch that does not work, so the shape is built here.

The shape, and why it is the common one it is:

    ``GET /portal/gateway``   -> 200, ``Set-Cookie: SESSIONID=<id>``, a login form
    ``POST /session`` (GOOD)  -> 200, **no Set-Cookie**, an account page
    ``POST /session`` (BAD)   -> 200, **no Set-Cookie**, the login form again

An application that calls ``session_regenerate_id(False)``, or Django's
``cycle_key`` on a reused key, or any of the frameworks that attach an identity
to the session id they already issued, answers a **successful** login with
exactly nothing new in the ``Set-Cookie`` delta. The delta is the only honest
evidence a credential POST can produce — a cookie the login GET set exists
whatever we send — so on this shape the honest evidence is empty on success.

Reading that as a failure is not a missed finding. It aborts the engagement, and
it tells an operator whose password is correct that their password is wrong.

So the three assertions here are:

1. the GOOD credential reaches :attr:`~clinkz.tools.auth.LoginVerdict.INDETERMINATE`,
   not REFUSED, and carries the promoted cookie forward;
2. :func:`~clinkz.engagement.auth_state.assert_authenticated` — the stronger
   oracle, and the one already running on the next line of
   ``_authenticate_role`` — then **PROVES** the session against an anonymous
   control;
3. the BAD credential on the same origin is **REFUSED**, on an observation
   (``<input type="password">`` in the answer) rather than on a refusal
   sentence. Without (3) the fix would be "call every ambiguous login a
   success", which is the original defect with its sign flipped.
"""

from __future__ import annotations

import socketserver
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from clinkz.engagement.auth_state import assert_authenticated
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import LoginVerdict, WebAuthenticator

_HOST = "127.0.0.1"
_USER = "acct-4417"
_GOOD = "s3cure-passphrase"  # noqa: S105 — a loopback fixture's credential
_BAD = "not-the-passphrase"  # noqa: S105 — likewise

_SESSION_COOKIE = "SESSIONID"

_LOGIN_FORM = (
    "<html><body><h1>Sign in</h1>"
    '<form method="post" action="/session">'
    '<input type="hidden" name="csrf" value="tok">'
    '<input type="text" name="account">'
    '<input type="password" name="password">'
    '<input type="submit" name="submit" value="Sign in">'
    "</form></body></html>"
)

# Deliberately carries none of the eight authenticated-page markers
# ``_login_verdict`` rule 3 looks for, and no refusal keyword either. A fixture a
# body keyword can rescue does not test the branch this file is about.
_ACCOUNT_PAGE = "<html><body><h1>Account overview</h1><p>Balance: 42</p></body></html>"


class _PromotingOrigin(BaseHTTPRequestHandler):
    """An origin that promotes its pre-login session in place.

    One session id, issued on the login page GET and never reissued. The
    credential POST attaches an identity to it server-side; the only thing that
    changes on the wire is what the protected page then returns.
    """

    #: session id -> whether it has been authenticated. Class-level so the
    #: handler instances (one per request) share it.
    sessions: dict[str, bool]

    def _cookie(self) -> str:
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", "") or "")
        return jar[_SESSION_COOKIE].value if _SESSION_COOKIE in jar else ""

    def _send(self, status: int, body: str, extra: tuple[tuple[str, str], ...] = ()) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        path = urlparse(self.path).path
        sid = self._cookie()
        if path == "/portal/gateway":
            if sid:
                # The session already exists. Nothing new is issued — that is
                # the property under test, and it holds on the GET too.
                self._send(200, _LOGIN_FORM)
                return
            new_sid = f"sess-{len(self.sessions) + 1}"
            self.sessions[new_sid] = False
            self._send(
                200,
                _LOGIN_FORM,
                ((("Set-Cookie"), f"{_SESSION_COOKIE}={new_sid}; Path=/"),),
            )
            return
        if path == "/account":
            # The discriminator the assertion needs: a boundary, not a body
            # difference. Anonymous gets 401; the promoted session gets 200.
            if self.sessions.get(sid):
                self._send(200, _ACCOUNT_PAGE)
            else:
                self._send(401, "<html>Sign in required</html>")
            return
        self._send(404, "")

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        self.server.credential_posts.append(body)  # type: ignore[attr-defined]
        if path != "/session":
            self._send(404, "")
            return
        fields = parse_qs(body, keep_blank_values=True)
        account = (fields.get("account") or [""])[0]
        password = (fields.get("password") or [""])[0]
        sid = self._cookie()
        if account == _USER and password == _GOOD and sid in self.sessions:
            # SUCCESS. The identity is attached to the session id we already
            # issued. No Set-Cookie, no redirect, no token — an account page.
            self.sessions[sid] = True
            self._send(200, _ACCOUNT_PAGE)
            return
        # FAILURE, and it looks the same on the wire except for the body: the
        # login form again, with no refusal sentence in it.
        self._send(200, _LOGIN_FORM)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class _Server(ThreadingHTTPServer):
    """Loopback server that skips the reverse-DNS its bind would otherwise do."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


@pytest.fixture()
def origin() -> Any:
    handler = type("_Origin", (_PromotingOrigin,), {"sessions": {}})
    server = _Server((_HOST, 0), handler)
    server.credential_posts = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def local_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """The aiohttp arm, on this host — no tools container in a unit test."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")


def _scope() -> EngagementScope:
    return EngagementScope(
        name="promoted-session",
        targets=[ScopeEntry(type=ScopeType.IP, value=_HOST)],
    )


@pytest.mark.asyncio
async def test_a_good_credential_that_sets_no_cookie_is_indeterminate_not_refused(
    origin: Any,
) -> None:
    """The delta is empty and the login WORKED. That is not a failure."""
    base = f"http://{_HOST}:{origin.server_address[1]}"
    auth = WebAuthenticator(scope=_scope())

    result = await auth.authenticate(f"{base}/portal/gateway", _USER, _GOOD)

    assert result.verdict is LoginVerdict.INDETERMINATE, (
        f"a successful login on a promote-in-place application reached "
        f"{result.verdict.value!r} — {result.verdict_evidence}"
    )
    assert result.success is True, "an indeterminate login is handed forward, not dropped"
    assert result.proven is False, (
        "nothing about this exchange PROVED a session; the deferral must not claim it did"
    )
    # The carriage is the promoted cookie. Without it there would be nothing for
    # the assertion to carry, and the deferral would be empty.
    assert set(result.session_cookies) == {_SESSION_COOKIE}, (
        f"the promoted session cookie was not carried forward: {result.session_cookies}"
    )
    # And the evidence names what was absent rather than asserting anything
    # about the operator's password.
    assert "set no cookie" in result.verdict_evidence
    assert "promotes its pre-login session in place" in result.verdict_evidence


@pytest.mark.asyncio
async def test_the_assertion_then_proves_the_session_the_login_could_not(origin: Any) -> None:
    """The whole point of deferring: the stronger oracle settles it, and it says YES.

    This is the assertion that makes the fix worth making. Everything above is
    "the login did not call it a failure"; this is "the credential actually
    worked, and the engine now knows it".
    """
    from clinkz.orchestrator.orchestrator import _ToolHttpProbe

    base = f"http://{_HOST}:{origin.server_address[1]}"
    auth = WebAuthenticator(scope=_scope())
    result = await auth.authenticate(f"{base}/portal/gateway", _USER, _GOOD)

    assertion = await assert_authenticated(
        _ToolHttpProbe(_scope(), ""),
        [f"{base}/account", f"{base}/portal/gateway"],
        cookies=result.session_cookies,
        headers={},
        username=_USER,
    )

    assert assertion.established, (
        f"the assertion could not prove the session the login deferred to it: "
        f"{assertion.why_unproven}"
    )
    assert assertion.discriminator, "a proven session names the discriminator that proved it"


@pytest.mark.asyncio
async def test_a_bad_credential_on_the_same_shape_is_still_refused(origin: Any) -> None:
    """The negative control, and it is what stops the fix being "believe everything".

    Same origin, same absent ``Set-Cookie``, same 200. The only difference is
    that the answer is the login form again — and that is an OBSERVATION
    (``<input type="password">``, the rule ``_session_survived`` already owns),
    not a refusal sentence this authenticator has to recognise in English.
    """
    base = f"http://{_HOST}:{origin.server_address[1]}"
    auth = WebAuthenticator(scope=_scope())

    result = await auth.authenticate(f"{base}/portal/gateway", _USER, _BAD)

    assert result.verdict is LoginVerdict.REFUSED, (
        f"a rejected credential reached {result.verdict.value!r} — {result.verdict_evidence}"
    )
    assert result.success is False
    # And the failure names absent evidence rather than the operator's password.
    lowered = (result.failure_stage or "").lower()
    assert "password" not in lowered or "input type" in lowered, (
        f"the failure message makes a claim about the credential: {result.failure_stage!r}"
    )
