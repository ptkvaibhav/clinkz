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
from typing import Any
from urllib.parse import urlparse

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import (
    CredentialRedirectRefusedError,
    WebAuthenticator,
    _RedirectHop,
)

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
        self.server.received.append((self.command, self.path, body))  # type: ignore[attr-defined]
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
            self.server.received.append((self.command, self.path, body))  # type: ignore[attr-defined]
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
    method, path, seen = collector.received[0]  # type: ignore[attr-defined]
    assert (method, path) == ("POST", "/collect")
    assert _PASSWORD in seen, "the collector can see a credential body"


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
    posted = [r for r in app.received if r[0] == "POST"]  # type: ignore[attr-defined]
    assert posted, "the credential POST to the in-scope action still happens"
    assert _PASSWORD in posted[0][2]

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

    posted = [r for r in app.received if r[0] == "POST"]  # type: ignore[attr-defined]
    assert len(posted) == 1, f"one credential POST, then the attempt ends: {[p[1] for p in posted]}"
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
    method, path, body = landing.received[0]  # type: ignore[attr-defined]
    assert (method, path) == ("POST", "/collect")
    assert _PASSWORD in body, "307 preserves the body, and we preserve it too"


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
        posted = [r for r in app.received if r[0] == "POST"]  # type: ignore[attr-defined]
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
            self.server.received.append((self.command, self.path, body))  # type: ignore[attr-defined]
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
        assert hop == _RedirectHop("stop", "", "")

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
