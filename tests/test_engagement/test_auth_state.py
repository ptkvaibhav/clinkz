"""The authenticated-state assertion: proven, never assumed.

The failure this guards is the one that produces an empty report and a false
all-clear, with nothing in the run looking wrong. So the assertion is built like
every other oracle in this codebase: a control, a deterministic discriminator,
and an explicit refusal to accept a correlate.
"""

from __future__ import annotations

import pytest

from clinkz.engagement.auth_state import (
    AuthMechanism,
    ProbeResponse,
    SessionSentinel,
    assert_authenticated,
    detect_auth_mechanism,
    looks_unauthenticated,
)

pytestmark = pytest.mark.asyncio

_LOGIN_HTML = '<html><form><input type="password" name="pw"></form></html>'


class _FakeProbe:
    """Serves canned responses keyed on ``(url, authenticated)``.

    ``authenticated`` is derived the same way the real adapter derives it: the
    caller either passed session material or deliberately did not.
    """

    def __init__(
        self,
        responses: dict[tuple[str, bool], ProbeResponse],
        default: ProbeResponse | None = None,
        json_routes: dict[str, ProbeResponse] | None = None,
    ) -> None:
        self._responses = responses
        self._default = default or ProbeResponse(status=404)
        self._json_routes = json_routes or {}
        self.gets: list[tuple[str, bool]] = []

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> ProbeResponse:
        authed = bool(headers or cookies)
        self.gets.append((url, authed))
        return self._responses.get((url, authed), self._default)

    async def post_json(self, url: str, payload: dict[str, str]) -> ProbeResponse:
        return self._json_routes.get(url, ProbeResponse(status=404))


# ---------------------------------------------------------------------------
# Mechanism detection — detect, do not assume
# ---------------------------------------------------------------------------


async def test_html_login_form_is_detected_by_a_password_input() -> None:
    probe = _FakeProbe({("http://t/login.php", False): ProbeResponse(status=200, body=_LOGIN_HTML)})
    detection = await detect_auth_mechanism(probe, "http://t")
    assert detection.mechanism is AuthMechanism.FORM
    assert detection.login_url == "http://t/login.php"
    assert detection.evidence


async def test_json_api_login_route_is_detected_by_its_rejection() -> None:
    """A route that 4xx's an empty credential POST exists and rejected it.

    404/405 would mean the route does not exist; a 401 means it does.
    """
    probe = _FakeProbe({}, json_routes={"http://t/rest/user/login": ProbeResponse(status=401)})
    detection = await detect_auth_mechanism(probe, "http://t")
    assert detection.mechanism is AuthMechanism.BEARER
    assert detection.login_url == "http://t/rest/user/login"


async def test_no_auth_surface_reports_none() -> None:
    probe = _FakeProbe({}, default=ProbeResponse(status=404))
    detection = await detect_auth_mechanism(probe, "http://t")
    assert detection.mechanism is AuthMechanism.NONE
    assert detection.probed, "a wrong answer has to be diagnosable from what was probed"


# ---------------------------------------------------------------------------
# The assertion — each accepted discriminator
# ---------------------------------------------------------------------------


async def _assert_at(url: str, authed: ProbeResponse, anon: ProbeResponse, **kwargs):
    probe = _FakeProbe({(url, True): authed, (url, False): anon})
    return await assert_authenticated(probe, [url], cookies={"sid": "x"}, **kwargs)


async def test_login_redirect_discriminator() -> None:
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="dashboard"),
        ProbeResponse(status=302, headers={"Location": "http://t/login"}),
    )
    assert result.established
    assert result.discriminator == "login_redirect"
    assert result.evidence


async def test_status_class_discriminator() -> None:
    result = await _assert_at(
        "http://t/api/user",
        ProbeResponse(status=200, body="{}"),
        ProbeResponse(status=401, body=""),
    )
    assert result.established
    assert result.discriminator == "status_class"


async def test_login_form_discriminator() -> None:
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="<html>welcome back</html>"),
        ProbeResponse(status=200, body=_LOGIN_HTML),
    )
    assert result.established
    assert result.discriminator == "login_form"


async def test_session_marker_discriminator() -> None:
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="<a href=/logout>Logout</a>"),
        ProbeResponse(status=200, body="<a href=/signup>Sign up</a>"),
    )
    assert result.established
    assert result.discriminator == "session_marker"


async def test_identity_echo_discriminator() -> None:
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="Hello alice@app.test"),
        ProbeResponse(status=200, body="Hello guest"),
        username="alice@app.test",
    )
    assert result.established
    assert result.discriminator == "identity_echo"


# ---------------------------------------------------------------------------
# The assertion — what it must REFUSE to accept
# ---------------------------------------------------------------------------


async def test_a_body_length_delta_alone_proves_nothing() -> None:
    """The correlate this codebase refuses everywhere else.

    Page chrome, a CSRF token, a timestamp all move the length without any
    authorization boundary existing. Accepting it would let an anonymous scan
    pass for an authenticated one — the exact failure the assertion exists to
    prevent.
    """
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="x" * 5000),
        ProbeResponse(status=200, body="x" * 120),
    )
    assert not result.established
    assert result.why_unproven
    assert result.attempted, "a failure must show what was compared"


async def test_a_marker_present_in_both_responses_proves_nothing() -> None:
    result = await _assert_at(
        "http://t/",
        ProbeResponse(status=200, body="<a href=/logout>Logout</a> hello"),
        ProbeResponse(status=200, body="<a href=/logout>Logout</a>"),
    )
    assert not result.established


async def test_identical_responses_prove_nothing() -> None:
    same = ProbeResponse(status=200, body="<html>public page</html>")
    result = await _assert_at("http://t/", same, same)
    assert not result.established


async def test_no_session_material_is_refused_before_any_request() -> None:
    probe = _FakeProbe({})
    result = await assert_authenticated(probe, ["http://t/"])
    assert not result.established
    assert not probe.gets, "there is nothing to assert; do not touch the target"


async def test_the_first_discriminating_candidate_wins() -> None:
    probe = _FakeProbe(
        {
            ("http://t/public", True): ProbeResponse(status=200, body="same"),
            ("http://t/public", False): ProbeResponse(status=200, body="same"),
            ("http://t/private", True): ProbeResponse(status=200, body="ok"),
            ("http://t/private", False): ProbeResponse(status=401, body=""),
        }
    )
    result = await assert_authenticated(
        probe, ["http://t/public", "http://t/private"], cookies={"sid": "x"}
    )
    assert result.established
    assert result.url == "http://t/private"
    assert len(result.attempted) == 2


# ---------------------------------------------------------------------------
# Session maintenance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "headers", "body"),
    [
        (401, {}, ""),
        (302, {"Location": "https://app.test/login?next=/x"}, ""),
        (200, {}, _LOGIN_HTML),
    ],
)
def test_session_loss_signals(status: int, headers: dict[str, str], body: str) -> None:
    assert looks_unauthenticated(status, headers, body)


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (403, "Forbidden"),
        (200, "<html>content</html>"),
        (404, "not found"),
        (500, "server error"),
    ],
)
def test_a_bare_403_is_not_session_loss(status: int, body: str) -> None:
    """403 is the correct answer to an authorization probe.

    The IDOR class produces them deliberately; treating one as session loss
    would trigger pointless re-authentication in the middle of the class that
    depends on seeing it.
    """
    assert not looks_unauthenticated(status, {}, body)


def test_the_sentinel_needs_a_streak_before_it_raises_the_flag() -> None:
    sentinel = SessionSentinel(threshold=3)
    for _ in range(2):
        sentinel.observe(401, {}, "")
    assert not sentinel.reauth_needed
    sentinel.observe(401, {}, "")
    assert sentinel.reauth_needed
    assert sentinel.losses_detected == 3


def test_a_healthy_response_resets_the_sentinel() -> None:
    sentinel = SessionSentinel(threshold=2)
    sentinel.observe(401, {}, "")
    sentinel.observe(200, {}, "ok")
    sentinel.observe(401, {}, "")
    assert not sentinel.reauth_needed


def test_clearing_counts_the_reauthentication() -> None:
    sentinel = SessionSentinel(threshold=1)
    sentinel.observe(401, {}, "")
    assert sentinel.reauth_needed
    sentinel.clear()
    assert not sentinel.reauth_needed
    assert sentinel.reauths_triggered == 1
