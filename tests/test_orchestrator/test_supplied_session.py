"""An operator-supplied session: supplied is not trusted.

For an application whose login this engine cannot perform — a separate-origin
identity provider (``docker/spa-keycloak``), MFA, a CAPTCHA — the operator signs
in in a browser and supplies the session. These tests pin the four properties
the feature is defined by:

1. it is verified by ``assert_authenticated`` UNCHANGED, and refused like any
   other unproven session;
2. no credential is ever sent for a role that supplied only a session;
3. the report says the operator supplied it, by NAME, never by value;
4. an expiry mid-run is detected and HALTS the engagement, because nothing here
   can renew it — and it is counted as unresolved, never as a false alarm.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from clinkz.agents.report import ReportAgent
from clinkz.engagement.auth_state import SEATED_BY_SUPPLIED, AuthAssertion
from clinkz.engagement.secrets import (
    clear_secrets,
    redact,
    register_credential_set,
)
from clinkz.llm.base import LLMClient
from clinkz.models.engagement import CredentialSet, RoleCredential, SafetyPolicy, SuppliedSession
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.safety.governor import (
    HALT_SUPPLIED_SESSION_EXPIRED,
    EngagementGovernor,
    set_active_governor,
)
from tests.authorization_fixtures import TEST_AUTHORIZATION

SCOPE = EngagementScope(
    name="supplied-session",
    targets=[ScopeEntry(value="http://spa-app:8000", type=ScopeType.URL)],
    authorization=TEST_AUTHORIZATION,
)
_COOKIE = "nw-session-6f2b9c1d8e7a"
_TOKEN = "eyJhbGciOiJSUzI1NiJ9.supplied-token-body.signature-part"


class _NullLLM(LLMClient):
    async def reason(self, messages, tools=None):
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _proven() -> AuthAssertion:
    return AuthAssertion(
        established=True,
        url="http://spa-app:8000/api/me",
        discriminator="status_class",
        authenticated_status=200,
        anonymous_status=401,
    )


def _refused() -> AuthAssertion:
    return AuthAssertion(
        established=False,
        attempted=["http://spa-app:8000/api/me: 401 with and without the session"],
        why_unproven="no candidate URL behaved differently with and without the session",
    )


def _supplied(*, password: str = "") -> RoleCredential:
    return RoleCredential(
        role="user",
        password=password,
        session=SuppliedSession(cookies={"nw_session": _COOKIE}),
    )


def _orchestrator(cred: RoleCredential) -> OrchestratorAgent:
    orch = OrchestratorAgent(llm=_NullLLM(), db_path=":memory:")
    orch._engagement_id = "eng-supplied"
    orch._scope = SCOPE
    orch._credentials = CredentialSet(credentials=[cred])
    orch._primary_target_url = lambda: "http://spa-app:8000"  # type: ignore[method-assign]
    return orch


def _no_login(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    import clinkz.tools.auth as auth_module
    from clinkz.tools.auth import AuthResult

    result = AuthResult(success=False, error="the login form was not found")
    constructed = MagicMock()
    constructed.authenticate = AsyncMock(return_value=result)
    factory = MagicMock(return_value=constructed)
    monkeypatch.setattr(auth_module, "WebAuthenticator", factory)
    return factory


# --------------------------------------------------------------------------
# Intake
# --------------------------------------------------------------------------


def test_a_session_only_role_is_an_authenticating_role_with_no_username() -> None:
    creds = CredentialSet(credentials=[_supplied()])
    assert [c.role for c in creds.authenticating] == ["user"]
    assert creds.primary() is not None


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"headers": {"Cookie": "a=b"}},
        {"headers": {"Host": "evil.example"}},
        {"cookies": {"bad name": "x"}},
        {"cookies": {"sid": ""}},
    ],
)
def test_malformed_supplied_sessions_are_refused_at_intake(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SuppliedSession(**kwargs)


def test_values_never_dump_and_names_do() -> None:
    dumped = str(_supplied().model_dump())
    assert _COOKIE not in dumped
    assert "nw_session" in dumped


def test_supplied_values_are_registered_for_redaction_including_a_bare_token() -> None:
    clear_secrets()
    try:
        cred = RoleCredential(
            role="user",
            session=SuppliedSession(
                cookies={"nw_session": _COOKIE}, headers={"Authorization": f"Bearer {_TOKEN}"}
            ),
        )
        register_credential_set(CredentialSet(credentials=[cred]))
        leaked = f"cookie={_COOKIE} jwt={_TOKEN}"
        out = redact(leaked)
        assert _COOKIE not in out
        assert _TOKEN not in out, "the token without its scheme must be redacted too"
    finally:
        clear_secrets()


def test_a_supplied_value_that_spells_schema_is_registered_like_a_password() -> None:
    """Register R30: the intake refusal is gone for supplied sessions too."""
    clear_secrets()
    try:
        cred = RoleCredential(role="user", session=SuppliedSession(cookies={"sid": "password"}))
        register_credential_set(CredentialSet(credentials=[cred]))
        assert redact("sid=password") == "sid=[REDACTED]"
    finally:
        clear_secrets()


# --------------------------------------------------------------------------
# Verification: the same oracle, and no credential sent
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_supplied_session_is_proven_by_the_unchanged_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred = _supplied()
    orch = _orchestrator(cred)
    assert_mock = AsyncMock(return_value=_proven())
    monkeypatch.setattr(orch, "_assert_role_session", assert_mock)
    factory = _no_login(monkeypatch)

    await orch._authenticate_role(cred, "http://spa-app:8000")

    assert not factory.called, "a session-only role must never reach the login path"
    (call,) = assert_mock.await_args_list
    assert call.args[1] == {"nw_session": _COOKIE}, "the assertion ran on the supplied jar"
    session = orch._role_sessions["user"]
    assert session["established"] is True
    assert session["seated_by"] == SEATED_BY_SUPPLIED
    assert session["login_verdict"] == "not_attempted"
    assert orch._reauth_credential is cred
    assert orch._reauth_login_url == "", "there is nothing to re-log-in with"


@pytest.mark.asyncio
async def test_a_refused_supplied_session_sends_no_credential_and_aborts_honestly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred = _supplied()
    orch = _orchestrator(cred)
    monkeypatch.setattr(orch, "_assert_role_session", AsyncMock(return_value=_refused()))
    factory = _no_login(monkeypatch)

    await orch._authenticate_role(cred, "http://spa-app:8000")

    assert not factory.called
    session = orch._role_sessions["user"]
    assert session["established"] is False
    assert session["cookies"] == {}, "an unproven session is not handed forward"

    message = orch._auth_failure_message("http://spa-app:8000", MagicMock(mechanism="none"))
    assert "SUPPLIED did not pass" in message
    assert "No credential was sent" in message
    assert "credentials are wrong" not in message
    assert "login URL is wrong" not in message, "no login ran, so no login remedy applies"


@pytest.mark.asyncio
async def test_a_refused_supplied_session_with_a_password_falls_back_to_the_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred = _supplied(password="Quartz-Meadow-2291")
    orch = _orchestrator(cred)
    monkeypatch.setattr(orch, "_assert_role_session", AsyncMock(return_value=_refused()))
    monkeypatch.setattr(orch, "_adaptive_auth", AsyncMock())
    factory = _no_login(monkeypatch)

    await orch._authenticate_role(cred, "http://spa-app:8000")

    assert factory.called, "a password was supplied too, so the ordinary login runs next"


# --------------------------------------------------------------------------
# Expiry mid-run
# --------------------------------------------------------------------------


def _flagged(orch: OrchestratorAgent, cred: RoleCredential) -> None:
    orch._reauth_credential = cred
    orch._reauth_login_url = ""
    orch._role_sessions["user"] = {
        "established": True,
        "username": "",
        "cookies": {"nw_session": _COOKIE},
        "headers": {},
        "assertion": _proven(),
        "seated_by": SEATED_BY_SUPPLIED,
        "supplied_cookie_names": ["nw_session"],
        "supplied_header_names": [],
    }
    orch._session_sentinel.arm()
    for _ in range(3):
        orch._session_sentinel.observe(401, {}, "", session_bearing=True)
    assert orch._session_sentinel.reauth_needed


@pytest.mark.asyncio
async def test_an_expired_supplied_session_halts_and_is_never_a_false_alarm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cred = _supplied()
    orch = _orchestrator(cred)
    _flagged(orch, cred)
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=False))
    factory = _no_login(monkeypatch)
    governor = EngagementGovernor("eng-supplied", SafetyPolicy(), outputs_root=tmp_path)
    set_active_governor(governor)
    try:
        await orch._reauthenticate_running_agents()
    finally:
        set_active_governor(None)

    assert not factory.called
    assert governor.halted
    assert governor.halt_reason == HALT_SUPPLIED_SESSION_EXPIRED
    assert "UNTESTED, not clean" in governor.halt_detail
    sentinel = orch._session_sentinel
    assert (sentinel.unresolved, sentinel.false_alarms, sentinel.reauths_triggered) == (1, 0, 0)

    summary = orch._authentication_summary()
    record = summary["supplied_sessions"]["user"]
    assert record["expired_at"]
    assert record["cookie_names"] == ["nw_session"]
    assert _COOKIE not in str(summary["supplied_sessions"])


@pytest.mark.asyncio
async def test_a_supplied_session_that_re_proves_itself_is_a_false_alarm_and_runs_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cred = _supplied()
    orch = _orchestrator(cred)
    _flagged(orch, cred)
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=True))
    governor = EngagementGovernor("eng-supplied", SafetyPolicy(), outputs_root=tmp_path)
    set_active_governor(governor)
    try:
        await orch._reauthenticate_running_agents()
    finally:
        set_active_governor(None)

    assert not governor.halted
    assert orch._session_sentinel.false_alarms == 1


# --------------------------------------------------------------------------
# Disclosure
# --------------------------------------------------------------------------


def test_the_report_names_the_supplied_session_and_its_expiry() -> None:
    auth = {
        "seated_by": {"user": SEATED_BY_SUPPLIED},
        "supplied_sessions": {
            "user": {
                "proven": True,
                "cookie_names": ["nw_session"],
                "header_names": [],
                "expired_at": "2026-10-09T12:00:00+00:00",
            }
        },
        "adaptive_auth": [{"role": "user", "outcome": "not_engaged"}],
    }
    lines = "\n".join(ReportAgent._render_supplied_sessions(auth))
    assert "Session supplied by the operator (user)" in lines
    assert "`nw_session`" in lines
    assert "Expired mid-run" in lines and "HALTED" in lines

    adaptive = "\n".join(ReportAgent._render_adaptive_auth(auth))
    assert "deterministic login path" not in adaptive, (
        "a supplied session must not be credited to a login the engine never ran"
    )
    assert "supplied by the operator" in adaptive
