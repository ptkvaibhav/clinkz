"""Who gets a browser: an engagement does, a directly-invoked agent does not.

``CLIENT_ORACLE_MODE`` used to be a two-state switch defaulting to ``disabled``,
which meant a real ``clinkz scan`` never confirmed DOM-XSS, client-rendered XSS
or CSP — the oracle was reachable only from a driver that set the variable
itself. Turning it simply on would have cost the other half: the unit suites
would launch a real browser on any machine with Playwright installed and not on
CI, which is the host-divergence that made a keyless gate report a different
number than CI (LESSONS #35), and which took those suites from 1.8 s to 21 s.

So the switch is on WHO IS ASKING. These tests hold both halves at once, because
either one alone is a regression of the other.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.browser.oracle import PlaywrightExecutionOracle
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="p7-wiring",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.get_new_endpoints = AsyncMock(return_value=[])
    return ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="p7-wiring",
        resolver=ToolResolver(),
        persistent_kb=None,
    )


class _FakeMatch:
    def __init__(self, available: bool = True) -> None:
        self.name = "playwright_chromium"
        self.available = available
        self.tool_class = PlaywrightExecutionOracle


class _FakeResolver:
    def __init__(self, match: Any) -> None:
        self._match = match

    def find_tool(self, capability: str) -> Any:
        assert capability == "client_side_execution", (
            "the oracle is found by capability, never by name"
        )
        return self._match


class TestTheDefaultGivesAnEngagementABrowser:
    def test_auto_provisions_the_oracle_for_an_engagement(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "auto")
        orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
        orchestrator._logger = __import__("logging").getLogger("test")
        orchestrator._engagement_id = "p7-wiring"

        oracle = orchestrator._provision_client_oracle(_FakeResolver(_FakeMatch()), SCOPE)
        assert isinstance(oracle, PlaywrightExecutionOracle)

    def test_auto_does_not_self_resolve_on_a_direct_invocation(self, monkeypatch) -> None:
        """The 1.8 s unit floor: no browser is resolved outside an engagement."""
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "auto")
        assert _agent()._p7_oracle() is None


class TestTheOptInStillWorksForADriver:
    def test_playwright_mode_self_resolves(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "playwright")
        agent = _agent()

        monkeypatch.setattr(
            agent._resolver, "find_tool", lambda capability: _FakeMatch(), raising=False
        )
        assert isinstance(agent._p7_oracle(), PlaywrightExecutionOracle)


class TestDisabledIsStillAnEscapeHatch:
    def test_disabled_gives_an_engagement_no_oracle(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "disabled")
        orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
        orchestrator._logger = __import__("logging").getLogger("test")
        orchestrator._engagement_id = "p7-wiring"

        assert orchestrator._provision_client_oracle(_FakeResolver(_FakeMatch()), SCOPE) is None

    def test_disabled_gives_a_direct_invocation_no_oracle(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "disabled")
        assert _agent()._p7_oracle() is None


class TestAnAbsentBrowserIsACoverageGapNotAnError:
    def test_an_unavailable_tool_leaves_the_engagement_without_an_oracle(self, monkeypatch) -> None:
        """Absent, broken or out-of-budget ⇒ the unproven lead stands unchanged."""
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "auto")
        orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
        orchestrator._logger = __import__("logging").getLogger("test")
        orchestrator._engagement_id = "p7-wiring"

        resolver = _FakeResolver(_FakeMatch(available=False))
        assert orchestrator._provision_client_oracle(resolver, SCOPE) is None

    def test_no_registered_tool_at_all_is_survivable(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.client_oracle_mode", "auto")
        orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
        orchestrator._logger = __import__("logging").getLogger("test")
        orchestrator._engagement_id = "p7-wiring"

        assert orchestrator._provision_client_oracle(_FakeResolver(None), SCOPE) is None


class TestTheCapabilityChainIsHowItIsFound:
    def test_the_oracle_registers_the_capability_the_orchestrator_asks_for(self) -> None:
        assert "client_side_execution" in PlaywrightExecutionOracle.capabilities

    @pytest.mark.parametrize("mode", ["auto", "playwright", "disabled"])
    def test_every_documented_mode_is_accepted_by_settings(self, mode: str) -> None:
        from clinkz.config import Settings

        assert Settings(client_oracle_mode=mode).client_oracle_mode == mode
