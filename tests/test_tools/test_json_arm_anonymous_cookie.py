"""A cookie the server hands ANY caller is not evidence that a credential worked.

The JSON arm's success rule was ``2xx and (a token or a Set-Cookie)``, licensed
by this reasoning, which is in the code and is wrong:

    Every cookie this arm can see on THIS response was set after the credentials
    went out — the JSON arm has no login-page GET of its own, so there is no
    pre-credential exchange of its own for one to have come from. The delta rule
    the form arms apply is satisfied here by construction.

"After the credentials went out" is not the delta rule. The delta rule
(:doc:`invariant 11 </invariants>`) is about a cookie the CREDENTIAL caused, and
the reason the form arms compute a delta is that a login-page GET issues one
whatever you send. This arm carries no jar at all, so **every** cookieless
request it makes to a session-starting framework is answered with a fresh
session cookie — on all eight canned routes, for any password, including one
that was rejected.

Measured on DVWA, which is a target this project owns:

    POST /login.php  {"username": "admin", "password": "wrongpass-a"}
    -> 200
       Set-Cookie: security=impossible
       Set-Cookie: PHPSESSID=766d4ae9…
       Set-Cookie: PHPSESSID=08787c34…
       <the login form>

Two wrong passwords for ``admin`` reached ``LoginVerdict.PROVEN`` on that shape.
A PROVEN verdict is not put to any further oracle:
``_attempt_login`` re-proves only an INDETERMINATE one, so the
default-credential sweep would have marked those passwords **valid**, stored a
session for them and reported a default-credential finding built on nothing.
That is the pre-credential cookie merged into the treatment, one arm over.

The fix reuses ``_session_survived`` — the same rule both form arms and both
verification arms already run, and the one this arm was missing. Two tests,
because a guard is only as good as its other direction: an API that answers a
JSON login with a session cookie and no token is a real shape and must still
authenticate.
"""

from __future__ import annotations

import socketserver
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import LoginVerdict, WebAuthenticator

_HOST = "127.0.0.1"
_USER = "admin"
_WRONG = "wrongpass-a"  # noqa: S105 — a loopback fixture's credential

#: The body a session-starting framework serves a caller it has not authenticated.
#: It carries an ``<input type="password">`` and that is the whole observation —
#: no refusal sentence, because a guard that needed one would be back to reading
#: English the target chose.
_LOGIN_FORM = (
    "<html><body><h1>Login</h1>"
    '<form method="post" action="/login.php">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    '<input type="submit" name="Login" value="Login">'
    "</form></body></html>"
)


class _SessionStartingOrigin(BaseHTTPRequestHandler):
    """DVWA's shape: a fresh session cookie for any cookieless caller, on any route.

    Every path answers the same way, because that is what the canned-route walk
    actually meets — the arm offers the same credentials at up to eight routes on
    one origin and each of them starts a session.
    """

    def _send(self, status: int, body: str, extra: tuple[tuple[str, str], ...] = ()) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._send(
            200,
            _LOGIN_FORM,
            (("Set-Cookie", f"PHPSESSID={uuid.uuid4().hex}; path=/; HttpOnly"),),
        )

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.credential_posts.append(self.path)  # type: ignore[attr-defined]
        # 200, a fresh session cookie, and the login form back. The credential
        # was rejected; the cookie has nothing to do with it.
        self._send(
            200,
            _LOGIN_FORM,
            (("Set-Cookie", f"PHPSESSID={uuid.uuid4().hex}; path=/; HttpOnly"),),
        )

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class _CookieApiOrigin(BaseHTTPRequestHandler):
    """The shape the cookie branch was ADDED for — a same-site API, no token.

    The negative control for the guard. It answers the JSON login ``200`` with a
    session cookie and a JSON body that is not a login surface, and it must
    still authenticate: a fix that refuses this one has traded a false positive
    for a false negative on the commoner shape.
    """

    def _send(self, status: int, body: str, extra: tuple[tuple[str, str], ...] = ()) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._send(404, '{"error": "not found"}')

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.credential_posts.append(self.path)  # type: ignore[attr-defined]
        self._send(
            200,
            '{"status": "ok", "user": {"id": 7}}',
            (("Set-Cookie", "api_session=live-session-id; path=/; HttpOnly"),),
        )

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class _Server(ThreadingHTTPServer):
    """Loopback server that skips the reverse-DNS its bind would otherwise do."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


def _serve(handler: type[BaseHTTPRequestHandler]) -> Any:
    server = _Server((_HOST, 0), handler)
    server.credential_posts = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture()
def session_starting() -> Any:
    server = _serve(_SessionStartingOrigin)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def cookie_api() -> Any:
    server = _serve(_CookieApiOrigin)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def local_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """The aiohttp path, on this host — no tools container in a unit test."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")


def _scope() -> EngagementScope:
    return EngagementScope(
        name="json-arm-anonymous-cookie",
        targets=[ScopeEntry(type=ScopeType.IP, value=_HOST)],
    )


@pytest.mark.asyncio
async def test_an_anonymous_session_cookie_on_a_login_page_is_not_a_login(
    session_starting: Any,
) -> None:
    """The measured DVWA defect, as a shape.

    The password is wrong and every route answers ``200`` with a fresh cookie.
    Success here is a claim the sweep would publish.
    """
    base = f"http://{_HOST}:{session_starting.server_address[1]}"
    auth = WebAuthenticator(scope=_scope())

    result = await auth._try_api_login(f"{base}/login.php", _USER, _WRONG)

    assert session_starting.credential_posts, "the arm never dispatched — vacuous test"
    assert result.success is False, (
        f"a rejected credential authenticated on a cookie the origin issues to "
        f"anyone: {result.verdict_evidence!r}"
    )
    assert result.verdict is not LoginVerdict.PROVEN
    assert not result.session_cookies


@pytest.mark.asyncio
async def test_a_json_api_that_answers_with_a_session_cookie_still_authenticates(
    cookie_api: Any,
) -> None:
    """The other direction, and the shape the cookie branch exists for.

    A same-site API returning ``Set-Cookie`` and no token is common, and it was a
    reported failure before the cookie branch was added. The guard must not take
    that back.
    """
    base = f"http://{_HOST}:{cookie_api.server_address[1]}"
    auth = WebAuthenticator(scope=_scope())

    result = await auth._try_api_login(f"{base}/rest/user/login", _USER, "correct-horse")

    assert result.success is True, result.error
    assert result.session_cookies == {"api_session": "live-session-id"}
