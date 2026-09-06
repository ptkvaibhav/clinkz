"""One authenticator, two transports, one verdict — asserted, not inspected.

``WebAuthenticator`` has two credential arms that must behave identically:
``_execute_aiohttp`` on the host and ``_execute_curl`` inside the tools
container. Every divergence between them has been found the same way — a target
authenticated in one mode and failed in the other, and the mode was blamed for a
defect it was only hiding. The list so far: curl did not follow the login-page
GET's redirect and aiohttp did; the two filled ``redirect_chain`` with different
things; the curl session check threw the response body away and the aiohttp one
read it; ``Set-Cookie`` on a multi-cookie response lost the FIRST cookie on one
arm and the LAST on the other.

Every one of those was found by reading the two implementations side by side.
This file is the other half: the equality IS the test, and it has a domain where
inspection does not. Each scenario is served by ONE scripted origin, replayed
once per transport, and three things are compared —

* the **verdict tuple**: success, status, where the credential POST went, the
  content type negotiated, any scope refusal;
* the **surviving cookie set**: exactly which cookies the result carries;
* the **attempt count**: how many credential-bearing POSTs the origin received.

The attempt count is where the two arms legitimately differ today, and a
declared number per transport is what makes that visible instead of averaged
away: the aiohttp arm retries a failed login once with a fresh GET for a new CSRF
token and the curl arm does not. Where the two numbers differ, the scenario must
say why, in the scenario. Where they agree, a reason is refused — a divergence
note nobody can point at is how a real one gets absorbed.

Both arms are driven directly (``_execute_aiohttp`` / ``_execute_curl``) rather
than through ``_dispatch``, because ``_dispatch`` picks one by execution mode and
the point here is to run both against the same bytes. ``TOOL_EXEC_MODE`` stays
``local`` so ``_run_subprocess`` runs the real curl on this host instead of
``docker exec``.
"""

from __future__ import annotations

import json
import shutil
import socketserver
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import WebAuthenticator

_HOST = "127.0.0.1"
_USERNAME = "acct-4417"
_PASSWORD = "s3cure-passphrase"  # noqa: S105 — a loopback fixture's credential

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None,
    reason=("the curl arm needs a real curl on PATH — the same binary the tools container ships"),
)


# ---------------------------------------------------------------------------
# The scripted origin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Reply:
    """One response the origin will make."""

    status: int
    body: str = ""
    headers: tuple[tuple[str, str], ...] = ()


@dataclass
class Scenario:
    """One target behaviour, and what BOTH arms must conclude about it.

    Attributes:
        name: Test id.
        login_path: What the authenticator is pointed at.
        script: ``(METHOD, path)`` -> the replies to make, in order. The last
            reply repeats once the list is exhausted, so a retry sees the same
            answer unless the scenario says otherwise.
        success: The verdict both arms must reach.
        cookies: The cookie set both arms must carry, exactly.
        posted_to_path: The path the credential POST must have gone to.
        negotiated: The content type a 415 named and was retried under.
        aiohttp_attempts: Credential-bearing POSTs the aiohttp arm must send.
        curl_attempts: The same for the curl arm.
        divergence: Required when the two counts differ, refused when they agree.
        posted_fields: When set, the exact field names the credential POST must
            carry — no more and no fewer.
    """

    name: str
    login_path: str
    script: dict[tuple[str, str], list[Reply]]
    success: bool
    cookies: dict[str, str]
    posted_to_path: str
    aiohttp_attempts: int
    curl_attempts: int
    negotiated: str = ""
    divergence: str = ""
    posted_fields: frozenset[str] | None = field(default=None)


class _Origin(BaseHTTPRequestHandler):
    """Serves one :class:`Scenario` and records every request it receives."""

    scenario: Scenario

    def _reply(self, method: str) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        self.server.received.append((method, path, body))  # type: ignore[attr-defined]

        replies = self.scenario.script.get((method, path))
        if not replies:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        index = min(
            self.server.served.get((method, path), 0),  # type: ignore[attr-defined]
            len(replies) - 1,
        )
        self.server.served[(method, path)] = index + 1  # type: ignore[attr-defined]
        reply = replies[index]

        payload = reply.body.encode()
        self.send_response(reply.status)
        for name, value in reply.headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._reply("GET")

    def do_POST(self) -> None:  # noqa: N802 — stdlib dispatch name
        self._reply("POST")

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 — stdlib signature
        return


class _Server(ThreadingHTTPServer):
    """Loopback server that skips the reverse-DNS its bind would otherwise do."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


def _serve(scenario: Scenario) -> ThreadingHTTPServer:
    handler = type("_ScenarioOrigin", (_Origin,), {"scenario": scenario})
    server = _Server((_HOST, 0), handler)
    server.received = []  # type: ignore[attr-defined]
    server.served = {}  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ---------------------------------------------------------------------------
# The corpus — one entry per target behaviour the seven auth suites cover
# ---------------------------------------------------------------------------

_HTML = "text/html; charset=utf-8"
_JSON = "application/json"

_DVWA_FORM = (
    "<!doctype html><html><body>"
    '<form action="login.php" method="post">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    '<input type="submit" name="Login" value="Login">'
    '<input type="hidden" name="user_token" value="d4f1e8a2b3c4">'
    "</form></body></html>"
)

_PORTAL_FORM = (
    "<!doctype html><html><body><h1>Sign in</h1>"
    '<form method="post" action="/session">'
    '<input type="text" name="account">'
    '<input type="password" name="password">'
    '<input type="submit" name="submit" value="Sign in">'
    "</form></body></html>"
)

_TWO_FORMS = (
    "<!doctype html><html><body>"
    '<form method="get" action="/search">'
    '<input type="hidden" name="search_token" value="NOT-THE-LOGIN-TOKEN">'
    '<input type="text" name="q">'
    "</form>"
    '<form method="post" action="/session">'
    '<input type="hidden" name="csrf" value="login-token">'
    '<input type="text" name="account">'
    '<input type="password" name="password">'
    "</form>"
    '<form method="post" action="/newsletter">'
    '<input type="hidden" name="list_id" value="42">'
    '<input type="email" name="email">'
    "</form>"
    "</body></html>"
)

SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="dvwa_form_302_to_index",
        login_path="/login.php",
        script={
            ("GET", "/login.php"): [
                Reply(
                    200,
                    _DVWA_FORM,
                    (("Content-Type", _HTML), ("Set-Cookie", "PHPSESSID=abc123; Path=/")),
                )
            ],
            ("POST", "/login.php"): [Reply(302, "", (("Location", "/index.php"),))],
            ("GET", "/index.php"): [
                Reply(200, "<html>Welcome — logout</html>", (("Content-Type", _HTML),))
            ],
        },
        success=True,
        cookies={"PHPSESSID": "abc123"},
        posted_to_path="/login.php",
        aiohttp_attempts=1,
        curl_attempts=1,
    ),
    Scenario(
        name="rejected_credential_redirects_back_to_the_login_page",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
            ("POST", "/session"): [Reply(302, "", (("Location", "/portal/gateway?error=1"),))],
            ("GET", "/portal/gateway?error=1"): [],
        },
        success=False,
        cookies={},
        posted_to_path="/session",
        aiohttp_attempts=2,
        curl_attempts=1,
        divergence=(
            "The aiohttp arm retries a failed login once with a fresh GET for a new "
            "CSRF token; the curl arm is a single shot. Two behaviours for one rule, "
            "and the report on this branch counts what they sum to against one role."
        ),
    ),
    Scenario(
        name="pre_credential_cookie_and_the_login_page_served_back",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [
                Reply(
                    200,
                    _PORTAL_FORM,
                    (
                        ("Content-Type", _HTML),
                        ("Set-Cookie", "SESSIONID=pre-credential; Path=/"),
                    ),
                )
            ],
            # 200 with the login form again. No failure keyword anywhere: the
            # only thing that could have made this a success is the cookie the
            # GET set, and that cookie exists whatever we send.
            ("POST", "/session"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
        },
        success=False,
        cookies={"SESSIONID": "pre-credential"},
        posted_to_path="/session",
        aiohttp_attempts=2,
        curl_attempts=1,
        divergence=(
            "Same retry asymmetry as the rejected-credential scenario: the aiohttp "
            "arm takes a second attempt on failure and the curl arm does not."
        ),
    ),
    Scenario(
        name="multi_cookie_set_cookie_survives_intact",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
            ("POST", "/session"): [
                Reply(
                    200,
                    '{"status":"ok"}',
                    (
                        ("Content-Type", _JSON),
                        ("Set-Cookie", "sid=session-value; Path=/; HttpOnly"),
                        ("Set-Cookie", "csrf=csrf-value; Path=/"),
                    ),
                )
            ],
        },
        success=True,
        cookies={"sid": "session-value", "csrf": "csrf-value"},
        posted_to_path="/session",
        aiohttp_attempts=1,
        curl_attempts=1,
    ),
    Scenario(
        name="a_415_names_the_encoding_and_the_retry_authenticates",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
            ("POST", "/session"): [
                Reply(
                    415,
                    json.dumps({"status": "error", "expects": {"content_type": _JSON}}),
                    (("Content-Type", _JSON),),
                ),
                Reply(
                    200,
                    '{"status":"ok"}',
                    (("Content-Type", _JSON), ("Set-Cookie", "meridian_portal=xyz; Path=/")),
                ),
            ],
        },
        success=True,
        cookies={"meridian_portal": "xyz"},
        posted_to_path="/session",
        negotiated=_JSON,
        aiohttp_attempts=2,
        curl_attempts=2,
    ),
    Scenario(
        name="a_415_naming_an_encoding_we_cannot_produce_is_not_retried",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
            ("POST", "/session"): [
                Reply(415, "", (("Accept-Post", "application/xml"),)),
            ],
        },
        success=False,
        cookies={},
        posted_to_path="/session",
        aiohttp_attempts=2,
        curl_attempts=1,
        divergence=(
            "The 415 is not renegotiated on either arm — the type is one neither can "
            "encode — so what is left is the ordinary failure retry the aiohttp arm "
            "takes and the curl arm does not."
        ),
    ),
    Scenario(
        name="the_login_page_sits_behind_a_redirect",
        login_path="/login",
        script={
            ("GET", "/login"): [Reply(302, "", (("Location", "/portal/gateway"),))],
            ("GET", "/portal/gateway"): [Reply(200, _PORTAL_FORM, (("Content-Type", _HTML),))],
            ("POST", "/session"): [
                Reply(
                    200,
                    '{"status":"ok"}',
                    (("Content-Type", _JSON), ("Set-Cookie", "sid=behind-a-redirect; Path=/")),
                )
            ],
        },
        success=True,
        cookies={"sid": "behind-a-redirect"},
        posted_to_path="/session",
        aiohttp_attempts=1,
        curl_attempts=1,
    ),
    Scenario(
        name="only_the_login_forms_fields_are_sent",
        login_path="/portal/gateway",
        script={
            ("GET", "/portal/gateway"): [Reply(200, _TWO_FORMS, (("Content-Type", _HTML),))],
            ("POST", "/session"): [
                Reply(
                    200,
                    '{"status":"ok"}',
                    (("Content-Type", _JSON), ("Set-Cookie", "sid=one-form-only; Path=/")),
                )
            ],
        },
        success=True,
        cookies={"sid": "one-form-only"},
        posted_to_path="/session",
        posted_fields=frozenset({"csrf", "account", "password"}),
        aiohttp_attempts=1,
        curl_attempts=1,
    ),
)


# ---------------------------------------------------------------------------
# Running one scenario through one transport
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """What one transport concluded, in the terms the two must agree on."""

    verdict: tuple[bool, int, str, str, str]
    cookies: dict[str, str]
    attempts: int
    credential_bodies: tuple[str, ...]


@pytest.fixture(autouse=True)
def local_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """No tools container here — curl runs on this host."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")


@pytest.fixture()
def scope() -> EngagementScope:
    return EngagementScope(
        name="transport-equivalence",
        targets=[ScopeEntry(type=ScopeType.IP, value=_HOST)],
    )


async def _run(
    scenario: Scenario,
    transport: str,
    scope: EngagementScope,
    jar_dir: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Outcome:
    server = _serve(scenario)
    try:
        base = f"http://{_HOST}:{server.server_address[1]}"
        auth = WebAuthenticator(scope=scope)
        # The one genuinely container-specific thing about the curl arm. The
        # jar's PATH is not part of what the two arms must agree about; that it
        # carries the login GET's cookies into the credential POST is, and this
        # is what lets the real curl do that on a host.
        monkeypatch.setattr(
            auth,
            "_cookie_jar_path",
            lambda: str(jar_dir / f"{scenario.name}_{transport}_cookies.txt"),
        )
        args = auth.validate_input(
            {
                "login_url": f"{base}{scenario.login_path}",
                "username": _USERNAME,
                "password": _PASSWORD,
            }
        )
        runner = auth._execute_aiohttp if transport == "aiohttp" else auth._execute_curl
        result = auth.parse_output(await runner(args)).auth_result
        received = list(server.received)  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()

    credential_posts = [
        (path, body) for method, path, body in received if method == "POST" and body
    ]
    return Outcome(
        verdict=(
            result.success,
            result.status_code,
            urlparse(result.posted_to).path,
            result.negotiated_content_type,
            result.scope_refusal,
        ),
        cookies=dict(result.session_cookies),
        attempts=len(credential_posts),
        credential_bodies=tuple(body for _path, body in credential_posts),
    )


def _field_names(body: str) -> frozenset[str]:
    """The field names a credential body carries, whichever encoding it used."""
    try:
        parsed = json.loads(body)
    except ValueError:
        from urllib.parse import parse_qsl

        return frozenset(name for name, _ in parse_qsl(body, keep_blank_values=True))
    return frozenset(parsed) if isinstance(parsed, dict) else frozenset()


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
async def test_both_transports_reach_the_same_verdict(
    scenario: Scenario,
    scope: EngagementScope,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same origin, same bytes, same conclusion — and the same cookies survive."""
    aiohttp_outcome = await _run(scenario, "aiohttp", scope, tmp_path, monkeypatch)
    curl_outcome = await _run(scenario, "curl", scope, tmp_path, monkeypatch)

    expected = (
        scenario.success,
        aiohttp_outcome.verdict[1],
        scenario.posted_to_path,
        scenario.negotiated,
        "",
    )
    assert aiohttp_outcome.verdict == expected, (
        f"the aiohttp arm reached {aiohttp_outcome.verdict}, expected {expected}"
    )
    assert curl_outcome.verdict == aiohttp_outcome.verdict, (
        f"the two arms disagree about {scenario.name}: "
        f"aiohttp={aiohttp_outcome.verdict} curl={curl_outcome.verdict}"
    )
    assert aiohttp_outcome.cookies == scenario.cookies, (
        f"the aiohttp arm carried {aiohttp_outcome.cookies}, expected {scenario.cookies}"
    )
    assert curl_outcome.cookies == aiohttp_outcome.cookies, (
        f"the two arms carried different cookies for {scenario.name}: "
        f"aiohttp={aiohttp_outcome.cookies} curl={curl_outcome.cookies}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
async def test_the_attempt_count_is_the_declared_one_on_each_arm(
    scenario: Scenario,
    scope: EngagementScope,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """How many times the target was offered a credential, per transport.

    Not asserted equal — they are not, and averaging that away is how the
    divergence stayed invisible. Asserted against a number the scenario declares,
    so any change to either arm's retry behaviour lands here.
    """
    aiohttp_outcome = await _run(scenario, "aiohttp", scope, tmp_path, monkeypatch)
    curl_outcome = await _run(scenario, "curl", scope, tmp_path, monkeypatch)

    assert aiohttp_outcome.attempts == scenario.aiohttp_attempts, (
        f"the aiohttp arm offered the credential {aiohttp_outcome.attempts} times, "
        f"declared {scenario.aiohttp_attempts}"
    )
    assert curl_outcome.attempts == scenario.curl_attempts, (
        f"the curl arm offered the credential {curl_outcome.attempts} times, "
        f"declared {scenario.curl_attempts}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [s for s in SCENARIOS if s.posted_fields is not None],
    ids=lambda s: s.name,
)
async def test_both_transports_send_the_login_forms_fields_and_no_others(
    scenario: Scenario,
    scope: EngagementScope,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A page's other forms do not contribute to the credential body.

    ``_FormFieldParser._in_form`` was set and cleared and gated nothing, so every
    ``<input>`` on the page landed in one bucket: a search form's hidden token
    and a newsletter form's ``list_id`` were POSTed to the login endpoint, and a
    rejection caused by fields the login form never declared would have been
    reported as "the credentials were wrong".
    """
    for transport in ("aiohttp", "curl"):
        outcome = await _run(scenario, transport, scope, tmp_path, monkeypatch)
        assert outcome.credential_bodies, f"{transport} sent no credential body"
        for body in outcome.credential_bodies:
            assert _field_names(body) == scenario.posted_fields, (
                f"the {transport} arm POSTed {sorted(_field_names(body))}, "
                f"expected exactly {sorted(scenario.posted_fields)}"
            )


def test_a_declared_divergence_is_required_exactly_where_the_arms_differ() -> None:
    """A divergence note nobody can point at is how a real one gets absorbed."""
    for scenario in SCENARIOS:
        differs = scenario.aiohttp_attempts != scenario.curl_attempts
        if differs:
            assert len(scenario.divergence.split()) >= 12, (
                f"{scenario.name}: the arms send a different number of credential "
                f"POSTs and the scenario does not say why"
            )
        else:
            assert not scenario.divergence, (
                f"{scenario.name}: declares a divergence while both arms send "
                f"{scenario.aiohttp_attempts} credential POSTs"
            )


def test_the_corpus_covers_every_shape_the_arms_have_diverged_on() -> None:
    """The domain of this pin, stated so a gap is visible rather than assumed.

    Each name is a shape one of the two arms once handled differently from the
    other. A scenario removed without replacing its shape fails here.
    """
    covered = {s.name for s in SCENARIOS}
    required = {
        "dvwa_form_302_to_index",  # a redirect that IS a success
        "rejected_credential_redirects_back_to_the_login_page",  # and one that is not
        "pre_credential_cookie_and_the_login_page_served_back",  # the delta rule
        "multi_cookie_set_cookie_survives_intact",  # the lossy header dict
        "a_415_names_the_encoding_and_the_retry_authenticates",  # negotiation
        "a_415_naming_an_encoding_we_cannot_produce_is_not_retried",
        "the_login_page_sits_behind_a_redirect",  # the GET walk
        "only_the_login_forms_fields_are_sent",  # the per-form gate
    }
    assert required <= covered, f"uncovered shapes: {sorted(required - covered)}"
