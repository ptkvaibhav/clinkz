"""A credential POST does not follow a redirect it has not scope-checked.

Both form credential POSTs were dispatched with ``-L`` / ``allow_redirects=True``
and the JSON arm with ``follow_redirects=True``. A **307** preserves the method
and the body, so the transport re-sent the engagement's plaintext credentials to
whatever the ``Location`` named — a destination ``_resolve_post_url`` had never
seen, chosen by anything able to shape one response rather than by anything able
to control the form's HTML.

The control here is the seeded-leak discipline: stand up a real out-of-scope
collector that WOULD receive the credentials, prove it works by handing it one
directly, then run the login and observe that it received nothing at all.

``127.0.0.2`` is the out-of-scope host and ``127.0.0.1`` is the in-scope one.
They are both loopback, both bindable everywhere pytest runs here, and
:meth:`EngagementScope.contains` separates them: the literal strings differ and
their address sets do not overlap, so the second is genuinely outside a scope
naming only the first. That is what makes the collector reachable and refused at
the same time — a destination that merely fails to resolve would prove nothing,
because nothing can reach it either way.
"""

from __future__ import annotations

import json
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, NamedTuple
from urllib.parse import urlparse

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import CredentialRedirectRefusedError, WebAuthenticator
from clinkz.tools.redirect_walk import RedirectHop

#: The engagement's target. In scope.
_APP_HOST = "127.0.0.1"

#: Somewhere else entirely. Reachable, and not in the scope below.
_COLLECTOR_HOST = "127.0.0.2"

_USERNAME = "acct-4417"
_PASSWORD = "s3cure-passphrase"  # noqa: S105 — a loopback fixture's credential

_LOGIN_HTML = (
    "<!doctype html><html><body><h1>Sign in</h1>"
    '<form method=post action="/session">'
    "<input type=text name=account><input type=password name=password>"
    "<input type=submit name=submit value='Sign in'></form></body></html>"
)


class _Seen(NamedTuple):
    """One request a fixture server received, and what it was carrying."""

    method: str
    path: str
    body: str
    cookie: str
    authorization: str


class _Collector(BaseHTTPRequestHandler):
    """The out-of-scope host. Records everything, and must record nothing.

    A ``list`` on the server object rather than the handler: a
    ``ThreadingHTTPServer`` builds one handler per request, so the handler is
    the wrong place to accumulate anything.
    """

    protocol_version = "HTTP/1.0"

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        # Session material is recorded alongside the body because it is the
        # second thing a followed redirect hands over. A bodyless GET carries no
        # credential and still carries the jar, and a cookie sent to a host the
        # operator never authorised is a session handed over.
        self.server.received.append(  # type: ignore[attr-defined]
            _Seen(
                self.command,
                self.path,
                body,
                self.headers.get("Cookie", ""),
                self.headers.get("Authorization", ""),
            )
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._record()

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._record()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


def _app_handler(collector_url: str, status: int) -> type[BaseHTTPRequestHandler]:
    """A login page whose credential POST is answered with *status* off-scope."""

    class _App(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:
            body = _LOGIN_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            self.server.received.append(  # type: ignore[attr-defined]
                _Seen(self.command, self.path, body, self.headers.get("Cookie", ""), "")
            )
            self.send_response(status)
            self.send_header("Location", collector_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
            return

    return _App


class _Server(ThreadingHTTPServer):
    """A loopback server that does not reverse-resolve its own bind address.

    ``HTTPServer.server_bind`` calls ``socket.getfqdn(host)``, and on an
    unnamed loopback alias like ``127.0.0.2`` that is a five-second DNS timeout
    per fixture. The name it computes is used for nothing here.
    """

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


def _serve(handler: type[BaseHTTPRequestHandler], host: str) -> ThreadingHTTPServer:
    server = _Server((host, 0), handler)
    server.received = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _url(server: ThreadingHTTPServer, path: str = "") -> str:
    host, port = server.server_address[0], server.server_address[1]
    return f"http://{host}:{port}{path}"


@pytest.fixture()
def collector() -> Iterator[ThreadingHTTPServer]:
    server = _serve(_Collector, _COLLECTOR_HOST)
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def scope() -> EngagementScope:
    """Names the app host and nothing else."""
    return EngagementScope(
        name="credential-redirect",
        targets=[ScopeEntry(type=ScopeType.IP, value=_APP_HOST)],
    )


@pytest.fixture(autouse=True)
def local_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """The in-process HTTP path; there is no tools container here."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")


# ---------------------------------------------------------------------------
# The collector works. Without this, "it received nothing" proves nothing.
# ---------------------------------------------------------------------------


def test_the_collector_records_a_credential_handed_to_it(
    collector: ThreadingHTTPServer,
) -> None:
    """The positive control: the leak is observable when it happens."""
    import urllib.request

    body = f"account={_USERNAME}&password={_PASSWORD}".encode()
    request = urllib.request.Request(  # noqa: S310 — loopback, literal scheme
        _url(collector, "/collect"),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=5) as resp:  # noqa: S310
        assert resp.status == 200

    assert len(collector.received) == 1  # type: ignore[attr-defined]
    seen = collector.received[0]  # type: ignore[attr-defined]
    assert (seen.method, seen.path) == ("POST", "/collect")
    assert _PASSWORD in seen.body, "the collector can see a credential body"


def test_the_collector_is_out_of_scope_and_the_app_is_in_it(
    collector: ThreadingHTTPServer, scope: EngagementScope
) -> None:
    """The premise the whole file rests on, asserted rather than assumed."""
    assert scope.contains(f"http://{_APP_HOST}:8080/login")
    assert not scope.contains(_url(collector, "/collect"))


# ---------------------------------------------------------------------------
# The defect, over a real 307
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.asyncio
async def test_a_body_preserving_redirect_off_scope_sends_no_credential(
    collector: ThreadingHTTPServer, scope: EngagementScope, status: int
) -> None:
    """The credentials reach the app's own action, and stop there.

    307 and 308 both preserve the method and the body, which is what makes them
    the shape that matters: the transport following one of these re-sends the
    plaintext credentials verbatim.
    """
    app = _serve(_app_handler(_url(collector, "/collect"), status), _APP_HOST)
    try:
        result = await WebAuthenticator(scope=scope).authenticate(
            _url(app, "/login"), _USERNAME, _PASSWORD
        )
    finally:
        app.shutdown()
        app.server_close()

    assert collector.received == [], (  # type: ignore[attr-defined]
        "the engagement's credentials left for an out-of-scope host"
    )

    # The credentials DID reach the app's own action — that request was in
    # scope and is not what this refuses.
    posted = [r for r in app.received if r.method == "POST"]  # type: ignore[attr-defined]
    assert posted, "the credential POST to the in-scope action still happens"
    assert _PASSWORD in posted[0].body

    assert not result.success
    assert result.scope_refusal == _url(collector, "/collect")
    assert result.posted_to == _url(app, "/session")
    assert "outside the engagement scope" in result.failure_stage
    assert _url(collector, "/collect") in result.failure_stage


@pytest.mark.asyncio
async def test_the_refusal_is_terminal_and_never_a_silent_drop(
    collector: ThreadingHTTPServer, scope: EngagementScope
) -> None:
    """``authenticate()`` stops rather than running the JSON arm next.

    The JSON arm would POST the same credentials at up to six more routes on the
    same target and then report "no API login route returned an auth token" — a
    true sentence that says nothing about the redirect, which is the only thing
    the operator needs to know.
    """
    app = _serve(_app_handler(_url(collector, "/collect"), 307), _APP_HOST)
    try:
        result = await WebAuthenticator(scope=scope).authenticate(
            _url(app, "/login"), _USERNAME, _PASSWORD
        )
    finally:
        app.shutdown()
        app.server_close()

    posted = [r for r in app.received if r.method == "POST"]  # type: ignore[attr-defined]
    assert len(posted) == 1, (
        f"one credential POST, then the attempt ends: {[p.path for p in posted]}"
    )
    assert result.scope_refusal
    assert "no API login route" not in result.error


@pytest.mark.asyncio
async def test_an_in_scope_redirect_is_still_followed(
    scope: EngagementScope,
) -> None:
    """The guard refuses a destination, not the mechanism.

    A 307 inside scope is an ordinary thing for a login to do, and dispatching
    to it deliberately has to reach the same place following it did.
    """
    landing = _serve(_Collector, _APP_HOST)
    app = _serve(_app_handler(_url(landing, "/collect"), 307), _APP_HOST)
    try:
        result = await WebAuthenticator(scope=scope).authenticate(
            _url(app, "/login"), _USERNAME, _PASSWORD
        )
    finally:
        app.shutdown()
        app.server_close()
        landing.shutdown()
        landing.server_close()

    assert not result.scope_refusal
    assert landing.received, "an in-scope 307 destination still receives the POST"  # type: ignore[attr-defined]
    seen = landing.received[0]  # type: ignore[attr-defined]
    assert (seen.method, seen.path) == ("POST", "/collect")
    assert _PASSWORD in seen.body, "307 preserves the body, and we preserve it too"


# ---------------------------------------------------------------------------
# The curl (docker) path — the same rule, observed on the argv
# ---------------------------------------------------------------------------


class TestTheCurlPathRefusesTheSameWay:
    """Docker mode reaches the same verdict, and never builds the leaking argv.

    There is no tools container in the keyless gate, so the observation is made
    where the request is CONSTRUCTED rather than where it would be received:
    every ``curl`` command line the authenticator produced, and whether any of
    them names the out-of-scope host or carries the password anywhere but the
    app's own action.
    """

    @staticmethod
    def _dumps(status: int, headers: dict[str, str], body: str = "") -> str:
        head = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        return f"HTTP/1.1 {status} X\r\n{head}\r\n{body}"

    @pytest.mark.asyncio
    async def test_no_curl_command_is_built_for_the_off_scope_destination(
        self, scope: EngagementScope, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        collector = f"http://{_COLLECTOR_HOST}:9/collect"
        commands: list[list[str]] = []

        async def _fake_subprocess(cmd: list[str], **_kw: Any) -> tuple[str, str, int]:
            commands.append(list(cmd))
            if "POST" in cmd:
                return self._dumps(307, {"Location": collector}), "", 0
            return self._dumps(200, {"Content-Type": "text/html"}, _LOGIN_HTML), "", 0

        auth = WebAuthenticator(scope=scope)
        monkeypatch.setattr(auth, "_run_subprocess", _fake_subprocess)
        raw = await auth.execute(
            auth.validate_input(
                {
                    "login_url": f"http://{_APP_HOST}:8080/login",
                    "username": _USERNAME,
                    "password": _PASSWORD,
                }
            )
        )
        result = auth.parse_output(raw).auth_result

        assert not any(_COLLECTOR_HOST in arg for cmd in commands for arg in cmd), (
            f"a curl command was built for the out-of-scope host: {commands}"
        )
        for cmd in commands:
            if any(_PASSWORD in arg for arg in cmd):
                assert cmd[-1] == f"http://{_APP_HOST}:8080/session"

        assert not result.success
        assert result.scope_refusal == collector
        assert result.posted_to == f"http://{_APP_HOST}:8080/session"

    @pytest.mark.asyncio
    async def test_the_dash_l_flag_is_gone_from_the_credential_post(
        self, scope: EngagementScope, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``-L`` is curl choosing where a credential-bearing request goes."""
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        commands: list[list[str]] = []

        async def _fake_subprocess(cmd: list[str], **_kw: Any) -> tuple[str, str, int]:
            commands.append(list(cmd))
            if "POST" in cmd:
                return self._dumps(200, {"Set-Cookie": "sid=abc; Path=/"}, "Welcome"), "", 0
            return self._dumps(200, {"Content-Type": "text/html"}, _LOGIN_HTML), "", 0

        auth = WebAuthenticator(scope=scope)
        monkeypatch.setattr(auth, "_run_subprocess", _fake_subprocess)
        await auth.execute(
            auth.validate_input(
                {
                    "login_url": f"http://{_APP_HOST}:8080/login",
                    "username": _USERNAME,
                    "password": _PASSWORD,
                }
            )
        )
        assert commands, "the flow ran"
        assert not any("-L" in cmd for cmd in commands)


# ---------------------------------------------------------------------------
# The JSON arm carries credentials too
# ---------------------------------------------------------------------------


class TestTheJsonArmRefusesTheSameWay:
    """``_api_post_json`` was the third site, and its caller swallows exceptions.

    ``_try_api_login`` catches ``Exception`` per route and moves to the next
    one, so a refusal that arrived as a plain exception would be dropped and the
    same credentials offered at five more routes.
    """

    @pytest.mark.asyncio
    async def test_the_json_credential_post_refuses_an_off_scope_redirect(
        self, collector: ThreadingHTTPServer, scope: EngagementScope
    ) -> None:
        app = _serve(_json_app_handler(_url(collector, "/collect")), _APP_HOST)
        try:
            auth = WebAuthenticator(scope=scope)
            with pytest.raises(CredentialRedirectRefusedError) as excinfo:
                await auth._api_post_json(
                    _url(app, "/rest/user/login"),
                    {"email": _USERNAME, "password": _PASSWORD},
                )
        finally:
            app.shutdown()
            app.server_close()

        assert collector.received == []  # type: ignore[attr-defined]
        assert excinfo.value.destination == _url(collector, "/collect")

    @pytest.mark.asyncio
    async def test_the_refusal_ends_the_route_walk(
        self, collector: ThreadingHTTPServer, scope: EngagementScope
    ) -> None:
        """One route tried, not seven — and the result names the refusal."""
        app = _serve(_json_app_handler(_url(collector, "/collect")), _APP_HOST)
        try:
            auth = WebAuthenticator(scope=scope)
            result = await auth._try_api_login(_url(app, "/rest/user/login"), _USERNAME, _PASSWORD)
        finally:
            app.shutdown()
            app.server_close()

        assert collector.received == []  # type: ignore[attr-defined]
        posted = [r for r in app.received if r.method == "POST"]  # type: ignore[attr-defined]
        assert len(posted) == 1, f"the walk continued past the refusal: {posted}"
        assert not result.success
        assert result.scope_refusal == _url(collector, "/collect")
        assert "No API login route" not in result.error


def _json_app_handler(collector_url: str) -> type[BaseHTTPRequestHandler]:
    """A JSON login route that answers the credential POST with a 307 off-scope."""

    class _JsonApp(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            self.server.received.append(  # type: ignore[attr-defined]
                _Seen(self.command, self.path, body, self.headers.get("Cookie", ""), "")
            )
            self.send_response(307)
            self.send_header("Location", collector_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
            return

    return _JsonApp


# ---------------------------------------------------------------------------
# The classifier itself
# ---------------------------------------------------------------------------


class TestTheHopClassifier:
    @staticmethod
    def _auth() -> WebAuthenticator:
        return WebAuthenticator(
            scope=EngagementScope(
                name="scoped",
                targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.example.com")],
            )
        )

    @pytest.mark.parametrize("status", [200, 201, 400, 401, 415, 500])
    def test_a_non_redirect_stops(self, status: int) -> None:
        hop = self._auth()._classify_credential_redirect(
            status, {"Location": "https://attacker.tld/x"}, "http://app.example.com/session"
        )
        assert hop.action == "stop"

    def test_a_3xx_with_no_location_stops(self) -> None:
        """Reading it as a redirect would invent a chain that never happened."""
        hop = self._auth()._classify_credential_redirect(
            302, {"Content-Length": "0"}, "http://app.example.com/session"
        )
        assert hop == RedirectHop("stop", "", "")

    @pytest.mark.parametrize("status", [307, 308])
    def test_a_body_preserving_redirect_in_scope_resends(self, status: int) -> None:
        hop = self._auth()._classify_credential_redirect(
            status, {"Location": "/v2/session"}, "http://app.example.com/session"
        )
        assert hop.action == "resend"
        assert hop.url == "http://app.example.com/v2/session"

    @pytest.mark.parametrize("status", [301, 302, 303])
    def test_a_body_dropping_redirect_in_scope_gets(self, status: int) -> None:
        """RFC semantics: the follow-up is a GET, so no credential travels."""
        hop = self._auth()._classify_credential_redirect(
            status, {"location": "/dashboard"}, "http://app.example.com/session"
        )
        assert hop.action == "get"
        assert hop.url == "http://app.example.com/dashboard"

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_every_redirect_status_is_scope_checked(self, status: int) -> None:
        """A 302's GET carries the cookie jar, so its destination is checked too."""
        hop = self._auth()._classify_credential_redirect(
            status, {"Location": "https://attacker.tld/collect"}, "http://app.example.com/session"
        )
        assert hop.action == "refuse"
        assert hop.url == "https://attacker.tld/collect"
        assert "outside the engagement scope" in hop.reason

    def test_a_relative_location_is_resolved_before_it_is_checked(self) -> None:
        """A scheme-relative ``Location`` leaves the origin without looking like it."""
        hop = self._auth()._classify_credential_redirect(
            307, {"Location": "//attacker.tld/collect"}, "http://app.example.com/session"
        )
        assert hop.action == "refuse"
        assert urlparse(hop.url).hostname == "attacker.tld"


def test_the_refusal_is_recorded_in_the_scope_refusal_log() -> None:
    """The refusal reaches the run's scope-refusal record, not just the log line."""
    from clinkz.safety.scope_refusals import (
        ScopeRefusalLog,
        set_active_scope_refusal_log,
    )

    auth = TestTheHopClassifier._auth()
    record = ScopeRefusalLog()
    set_active_scope_refusal_log(record)
    try:
        auth._classify_credential_redirect(
            307, {"Location": "https://attacker.tld/collect"}, "http://app.example.com/session"
        )
    finally:
        set_active_scope_refusal_log(None)

    assert [r.target for r in record.refusals()] == ["https://attacker.tld/collect"]
    assert json.dumps(record.to_dict())


# ---------------------------------------------------------------------------
# The session-bearing hops. No credential body, and still not free to leave.
# ---------------------------------------------------------------------------

_SESSION_COOKIE = "portal_session=7f1c3a9b2e4d"


def _login_get_redirect_handler(
    destination: str, status: int = 302
) -> type[BaseHTTPRequestHandler]:
    """A login page that sets a cookie and redirects the GET to *destination*."""

    class _App(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:
            self.server.received.append(  # type: ignore[attr-defined]
                _Seen("GET", self.path, "", self.headers.get("Cookie", ""), "")
            )
            self.send_response(status)
            self.send_header("Set-Cookie", f"{_SESSION_COOKIE}; Path=/")
            self.send_header("Location", destination)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
            return

    return _App


def test_the_collector_records_session_material_handed_to_it(
    collector: ThreadingHTTPServer,
) -> None:
    """The positive control for the jar half.

    "The collector received nothing" is only evidence if the collector would
    have recorded a cookie had one arrived. This is the same seeded-leak
    discipline the credential half already uses, applied to the other thing a
    followed redirect hands over.
    """
    import urllib.request

    request = urllib.request.Request(  # noqa: S310 — loopback, literal scheme
        _url(collector, "/collect"),
        headers={"Cookie": _SESSION_COOKIE, "Authorization": "Bearer tok-9931"},
    )
    with urllib.request.urlopen(request, timeout=5) as resp:  # noqa: S310
        assert resp.status == 200

    seen = collector.received[0]  # type: ignore[attr-defined]
    assert seen.cookie == _SESSION_COOKIE, "the collector can see a session cookie"
    assert seen.authorization == "Bearer tok-9931"


class TestTheLoginPageGetIsWalkedToo:
    """The GET that starts every form arm follows redirects, and carried no rule.

    It is dispatched before any credential exists, so nothing of ours can be in
    its body. What it carries is the cookie jar and the engagement's willingness
    to make a request, and it is where the form — the field names, the hidden
    CSRF token, the ``action`` the credentials are then POSTed to — is read
    from. aiohttp followed it by default and curl did not, so the two execution
    modes disagreed about a login page behind a redirect: authenticated on the
    host, failed in the container.
    """

    @pytest.mark.asyncio
    async def test_an_off_scope_login_page_redirect_sends_nothing(
        self, collector: ThreadingHTTPServer, scope: EngagementScope
    ) -> None:
        app = _serve(_login_get_redirect_handler(_url(collector, "/collect")), _APP_HOST)
        try:
            result = await WebAuthenticator(scope=scope).authenticate(
                _url(app, "/login"), _USERNAME, _PASSWORD
            )
        finally:
            app.shutdown()
            app.server_close()

        assert collector.received == [], (  # type: ignore[attr-defined]
            "the login-page GET followed a redirect off-scope"
        )
        assert result.scope_refusal == _url(collector, "/collect")
        assert not result.success
        # No credential POST was dispatched at all, and the message may not
        # claim one was: three auth failures wore one message once already.
        assert result.posted_to == ""
        assert "credential POST" not in result.failure_stage
        assert "outside the engagement scope" in result.failure_stage

    @pytest.mark.asyncio
    async def test_an_in_scope_login_page_redirect_is_followed_and_reads_the_form_there(
        self, scope: EngagementScope
    ) -> None:
        """The guard refuses a destination, not the mechanism — and the base moves.

        A relative form ``action`` resolves against the URL that SERVED the
        form, which is the redirect's destination and not the URL we asked for.
        Resolving against the URL we asked for POSTs the credentials at a path
        the application does not have.
        """
        app = _serve(_RelocatedLogin, _APP_HOST)
        try:
            result = await WebAuthenticator(scope=scope).authenticate(
                _url(app, "/login"), _USERNAME, _PASSWORD
            )
        finally:
            app.shutdown()
            app.server_close()

        posted = [r for r in app.received if r.method == "POST"]  # type: ignore[attr-defined]
        assert [p.path for p in posted] == ["/app/session"], (
            "the relative action resolved against the URL we asked for, not the "
            f"one that served the form: {[p.path for p in posted]}"
        )
        assert _PASSWORD in posted[0].body
        assert result.posted_to == _url(app, "/app/session")


class _RelocatedLogin(BaseHTTPRequestHandler):
    """``/login`` redirects into ``/app/portal``, whose form action is relative."""

    protocol_version = "HTTP/1.0"

    _FORM = (
        '<!doctype html><html><body><form method=post action="session">'
        "<input type=text name=account><input type=password name=password>"
        "</form></body></html>"
    )

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        self.server.received.append(  # type: ignore[attr-defined]
            _Seen("GET", self.path, "", self.headers.get("Cookie", ""), "")
        )
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Location", "/app/portal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = self._FORM.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self.server.received.append(  # type: ignore[attr-defined]
            _Seen("POST", self.path, body, self.headers.get("Cookie", ""), "")
        )
        self.send_response(200)
        self.send_header("Set-Cookie", f"{_SESSION_COOKIE}; Path=/")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class TestTheAuthProbeRefusesTheSameWay:
    """``_ToolHttpProbe`` handed ``follow_redirects`` straight to the transport.

    Two probes use it — the login-candidate walk in ``detect_auth_mechanism``
    and the destination read behind an established boundary — and both are
    reached with a target-supplied URL. ``validate_input`` scope-checks the URL
    it is given and nothing checks the ``Location`` that URL answers with, so
    ``-L`` / ``allow_redirects`` sent the engagement wherever a target named.
    """

    @staticmethod
    def _probe(scope: EngagementScope) -> Any:
        from clinkz.orchestrator.orchestrator import _ToolHttpProbe

        return _ToolHttpProbe(scope, "")

    @pytest.mark.asyncio
    async def test_a_session_bearing_probe_does_not_leave_for_an_off_scope_host(
        self, collector: ThreadingHTTPServer, scope: EngagementScope
    ) -> None:
        app = _serve(_login_get_redirect_handler(_url(collector, "/collect")), _APP_HOST)
        try:
            response = await self._probe(scope).get(
                _url(app, "/portal"),
                cookies={"portal_session": "7f1c3a9b2e4d"},
                follow_redirects=True,
            )
        finally:
            app.shutdown()
            app.server_close()

        assert collector.received == [], (  # type: ignore[attr-defined]
            "the engagement's session cookie left for an out-of-scope host"
        )
        assert response.status == 302, "the 3xx itself is still the answer in hand"
        assert "outside the engagement scope" in response.error

    @pytest.mark.asyncio
    async def test_an_in_scope_redirect_is_still_walked(self, scope: EngagementScope) -> None:
        """The refusal is about the destination; an in-scope hop still happens."""
        landing = _serve(_Collector, _APP_HOST)
        app = _serve(_login_get_redirect_handler(_url(landing, "/dashboard")), _APP_HOST)
        try:
            response = await self._probe(scope).get(_url(app, "/portal"), follow_redirects=True)
        finally:
            app.shutdown()
            app.server_close()
            landing.shutdown()
            landing.server_close()

        assert [r.path for r in landing.received] == ["/dashboard"]  # type: ignore[attr-defined]
        assert response.status == 200
        assert not response.error


# ---------------------------------------------------------------------------
# redirect_chain means one thing
# ---------------------------------------------------------------------------


class _RejectingLogin(BaseHTTPRequestHandler):
    """A login that REJECTS, in the shape that scored as a success.

    The form's ``action`` is not the login URL, the POST is answered ``302``
    back to the login page, and no cookie is ever set. Under the aiohttp arm's
    old ``redirect_chain`` — the URLs that ANSWERED — the chain held the ACTION
    path, which differs from the login path, which
    :meth:`WebAuthenticator._check_login_success` reads as "redirected away,
    therefore logged in".
    """

    protocol_version = "HTTP/1.0"

    _FORM = (
        '<!doctype html><html><body><form method=post action="/session">'
        "<input type=text name=account><input type=password name=password>"
        "</form></body></html>"
    )

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        body = self._FORM.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.received.append(_Seen("POST", self.path, "", "", ""))  # type: ignore[attr-defined]
        self.send_response(302)
        self.send_header("Location", "/portal/gateway?error=1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class TestRedirectChainHasOneMeaning:
    """One field, one fact: the absolute destinations a redirect pointed to.

    It used to carry two, and which one you got depended on the transport.
    aiohttp recorded the URLs that ANSWERED (``resp.history``); curl recorded
    the raw ``Location`` header values, unresolved, so ``urlparse("index.php")``
    was compared against ``/login.php``. ``_check_login_success`` reads this
    field to decide whether a login succeeded.
    """

    @staticmethod
    def _spy(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
        """Capture the ``redirect_chain`` the success oracle is handed."""
        captured: list[list[str]] = []
        original = WebAuthenticator._check_login_success

        def _wrapped(
            response_body: str,
            status_code: int,
            final_url: str,
            login_url: str,
            redirect_chain: list[str],
            session_cookies: dict[str, str] | None = None,
        ) -> bool:
            captured.append(list(redirect_chain))
            return original(
                response_body,
                status_code,
                final_url,
                login_url,
                redirect_chain,
                session_cookies,
            )

        monkeypatch.setattr(WebAuthenticator, "_check_login_success", staticmethod(_wrapped))
        return captured

    @staticmethod
    def _dump(status: int, headers: dict[str, str], body: str = "") -> str:
        head = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        return f"HTTP/1.1 {status} X\r\n{head}\r\n{body}"

    @pytest.mark.asyncio
    async def test_a_rejected_login_that_redirects_back_is_not_a_success(
        self, scope: EngagementScope, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The false positive, verbatim: no cookie, no token, and a 302 home."""
        captured = self._spy(monkeypatch)
        app = _serve(_RejectingLogin, _APP_HOST)
        try:
            auth = WebAuthenticator(scope=scope)
            raw = await auth.execute(
                auth.validate_input(
                    {
                        "login_url": _url(app, "/portal/gateway"),
                        "username": _USERNAME,
                        "password": _PASSWORD,
                    }
                )
            )
            base = _url(app)
        finally:
            app.shutdown()
            app.server_close()

        assert captured[0] == [f"{base}/portal/gateway?error=1"], (
            "the chain must be where the redirect POINTED, absolute — not the "
            f"URL that answered it: {captured[0]}"
        )
        assert not auth.parse_output(raw).auth_result.success, (
            "a rejected credential scored as a session"
        )

    @pytest.mark.asyncio
    async def test_both_execution_modes_hand_the_oracle_the_same_chain(
        self, scope: EngagementScope, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A target that authenticates in one mode and not the other is a defect."""
        from clinkz.config import settings

        captured = self._spy(monkeypatch)
        app = _serve(_RejectingLogin, _APP_HOST)
        try:
            base = _url(app)
            auth = WebAuthenticator(scope=scope)
            await auth.execute(
                auth.validate_input(
                    {
                        "login_url": f"{base}/portal/gateway",
                        "username": _USERNAME,
                        "password": _PASSWORD,
                    }
                )
            )
        finally:
            app.shutdown()
            app.server_close()
        local_chain = captured[0]

        # The same target, through the curl arm, serving the same bytes.
        monkeypatch.setattr(settings, "tool_exec_mode", "docker")

        async def _fake_subprocess(cmd: list[str], **_kw: Any) -> tuple[str, str, int]:
            url = cmd[-1]
            if "POST" in cmd:
                return (
                    self._dump(302, {"Location": "/portal/gateway?error=1"}),
                    "",
                    0,
                )
            if url.endswith("?error=1"):
                return self._dump(200, {"Content-Type": "text/html"}, "denied"), "", 0
            return (
                self._dump(200, {"Content-Type": "text/html"}, _RejectingLogin._FORM),
                "",
                0,
            )

        docker_auth = WebAuthenticator(scope=scope)
        monkeypatch.setattr(docker_auth, "_run_subprocess", _fake_subprocess)
        await docker_auth.execute(
            docker_auth.validate_input(
                {
                    "login_url": f"{base}/portal/gateway",
                    "username": _USERNAME,
                    "password": _PASSWORD,
                }
            )
        )
        docker_chain = captured[-1]

        assert local_chain == docker_chain == [f"{base}/portal/gateway?error=1"], (
            f"the two modes disagree about the chain: {local_chain} vs {docker_chain}"
        )
