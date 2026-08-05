"""Session maintenance: the flag is a hypothesis, the assertion is the oracle.

A live authenticated run reported ``session_losses_detected=15`` and
``reauthentications=0``. Both numbers were wrong, in opposite directions:

  * every one of the fifteen signals came from a request deliberately sent
    with no session (auth-mechanism detection, and the anonymous control whose
    401 IS the proof the session works) — covered in
    ``tests/test_engagement/test_auth_state.py``;
  * the zero was structural. The flag needed three CONSECUTIVE signals through
    a sentinel fed by three concurrent phases, so any interleaved success reset
    it, and nothing downstream ever ran.

These tests cover the Orchestrator half: what happens once the flag IS raised.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from clinkz.engagement.auth_state import AuthAssertion
from clinkz.llm.base import LLMClient
from clinkz.models.engagement import RoleCredential
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from tests.authorization_fixtures import TEST_AUTHORIZATION

SCOPE = EngagementScope(
    name="session-maintenance",
    targets=[ScopeEntry(value="app.test", type=ScopeType.DOMAIN)],
    authorization=TEST_AUTHORIZATION,
)


class _NullLLM(LLMClient):
    async def reason(self, messages, tools=None):
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _orchestrator_with_a_flagged_session() -> OrchestratorAgent:
    """An orchestrator holding a session the sentinel has just flagged."""
    orch = OrchestratorAgent(llm=_NullLLM(), db_path=":memory:")
    orch._engagement_id = "eng-session"
    orch._scope = SCOPE
    orch._reauth_credential = RoleCredential(
        role="admin", username="admin@app.test", password="correct-horse-battery"
    )
    orch._reauth_login_url = "http://app.test/rest/user/login"
    orch._role_sessions["admin"] = {
        "cookies": {"sid": "old-session-value"},
        "headers": {"Authorization": "Bearer old-token"},
        "username": "admin@app.test",
        "established": True,
        "assertion": AuthAssertion(
            established=True,
            url="http://app.test/api/users",
            discriminator="status_class",
            authenticated_status=200,
            anonymous_status=401,
        ),
    }
    orch._session_sentinel.arm()
    for _ in range(3):
        orch._session_sentinel.observe(401, {}, "")
    assert orch._session_sentinel.reauth_needed
    return orch


def _fake_authenticator(monkeypatch: pytest.MonkeyPatch, *, success: bool) -> MagicMock:
    """Patch WebAuthenticator where the orchestrator imports it from."""
    import clinkz.tools.auth as auth_module

    result = MagicMock()
    result.success = success
    result.session_cookies = {"sid": "fresh-session-value"} if success else {}
    result.bearer_token = "fresh-token" if success else ""

    constructed = MagicMock()
    constructed.authenticate = AsyncMock(return_value=result)
    factory = MagicMock(return_value=constructed)
    monkeypatch.setattr(auth_module, "WebAuthenticator", factory)
    return factory


@pytest.mark.asyncio
async def test_a_verified_dead_session_actually_triggers_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The half that never ran: flag raised, session proven dead, re-login happens."""
    orch = _orchestrator_with_a_flagged_session()
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=False))
    factory = _fake_authenticator(monkeypatch, success=True)
    orch._lifecycle = MagicMock()
    orch._lifecycle.get_running_agents.return_value = []

    await orch._reauthenticate_running_agents()

    assert factory.called, "a session proven dead did not trigger re-authentication"
    assert orch._session_sentinel.reauths_triggered == 1
    assert orch._session_sentinel.false_alarms == 0
    assert not orch._session_sentinel.reauth_needed
    assert orch._role_sessions["admin"]["cookies"] == {"sid": "fresh-session-value"}
    assert orch._role_sessions["admin"]["headers"] == {"Authorization": "Bearer fresh-token"}


@pytest.mark.asyncio
async def test_a_session_that_re_proves_itself_is_a_false_alarm_not_a_relogin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic oracle decides, not the heuristic that raised the flag.

    A run of 401s from an authorization boundary the scan legitimately walked
    into is indistinguishable from a dead session at the response level. Only
    the with-session/without-session assertion can tell them apart, and
    re-logging-in on a working session rotates a live token mid-phase.
    """
    orch = _orchestrator_with_a_flagged_session()
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=True))
    factory = _fake_authenticator(monkeypatch, success=True)

    await orch._reauthenticate_running_agents()

    assert not factory.called, "a live session was needlessly re-authenticated"
    assert orch._session_sentinel.reauths_triggered == 0
    assert orch._session_sentinel.false_alarms == 1
    assert not orch._session_sentinel.reauth_needed
    assert orch._role_sessions["admin"]["cookies"] == {"sid": "old-session-value"}


@pytest.mark.asyncio
async def test_a_failed_relogin_is_not_reported_as_a_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The counter records what happened, not what was attempted."""
    orch = _orchestrator_with_a_flagged_session()
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=False))
    _fake_authenticator(monkeypatch, success=False)

    await orch._reauthenticate_running_agents()

    assert orch._session_sentinel.reauths_triggered == 0
    assert orch._session_sentinel.false_alarms == 1
    summary = orch._authentication_summary()
    assert summary["reauthentications"] == 0
    assert summary["session_checks_performed"] == 1


@pytest.mark.asyncio
async def test_no_credential_means_the_flag_is_cleared_without_a_false_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orch = _orchestrator_with_a_flagged_session()
    orch._reauth_credential = None
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=False))

    await orch._reauthenticate_running_agents()

    assert orch._session_sentinel.reauths_triggered == 0
    assert not orch._session_sentinel.reauth_needed


@pytest.mark.asyncio
async def test_concurrent_phases_do_not_re_authenticate_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scan, Research and Exploit poll the same sentinel in parallel.

    Two simultaneous re-logins would race to write ``_role_sessions`` and push
    the loser's token to the agents.
    """
    import asyncio

    orch = _orchestrator_with_a_flagged_session()
    monkeypatch.setattr(orch, "_session_still_proven", AsyncMock(return_value=False))
    factory = _fake_authenticator(monkeypatch, success=True)
    orch._lifecycle = MagicMock()
    orch._lifecycle.get_running_agents.return_value = []

    await asyncio.gather(*(orch._reauthenticate_running_agents() for _ in range(3)))

    assert factory.call_count == 1, "concurrent phases each re-authenticated"
    assert orch._session_sentinel.reauths_triggered == 1


@pytest.mark.asyncio
async def test_the_summary_separates_losses_from_controls() -> None:
    """The report must not print two numbers that contradict each other."""
    orch = OrchestratorAgent(llm=_NullLLM(), db_path=":memory:")
    orch._session_sentinel.arm()
    for _ in range(15):
        orch._session_sentinel.observe(401, {}, "", session_bearing=False)

    summary: dict[str, Any] = orch._authentication_summary()

    assert summary["session_losses_detected"] == 0
    assert summary["control_responses_ignored"] == 15
    assert summary["reauthentications"] == 0


@pytest.mark.asyncio
async def test_nothing_before_the_first_session_can_be_a_session_loss() -> None:
    """You cannot lose what you never had.

    Observed live: nine login and mechanism-detection responses raised the flag
    six seconds BEFORE the assertion first proved a session. The oracle caught
    it, but the sentinel should never have fired — every request before
    establishment is unauthenticated by definition.
    """
    orch = OrchestratorAgent(llm=_NullLLM(), db_path=":memory:")
    for _ in range(12):
        orch._session_sentinel.observe(401, {}, "")

    assert not orch._session_sentinel.reauth_needed
    summary = orch._authentication_summary()
    assert summary["session_losses_detected"] == 0
    assert summary["pre_session_signals"] == 12
    assert summary["session_checks_performed"] == 0

    # Once armed, the same signals count.
    orch._session_sentinel.arm()
    for _ in range(3):
        orch._session_sentinel.observe(401, {}, "")
    assert orch._session_sentinel.reauth_needed
    assert orch._session_sentinel.losses_detected == 3
