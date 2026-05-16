"""Unit tests for the adaptive weak-session methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — session-generation trigger detection
    Phase 2 (observation)  — 8-sample cookie collection + flag inspection
    Phase 3 (analysis)     — LLM JSON parsing + deterministic fallback
    Phase 4 (finding)      — Finding evidence chain
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    SessionWeaknessType,
    WeakSessionMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-weak-session-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _ScriptedLLM(LLMClient):
    def __init__(self, answers: list[str] | None = None) -> None:
        self.prompts: list[str] = []
        self.answers: list[str] = list(answers or [])

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            return ""
        return self.answers.pop(0)


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


def _make_agent(llm: LLMClient | None = None) -> ExploitAgent:
    agent = ExploitAgent(
        llm=llm or _ScriptedLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="methodology-weak-session-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _generate_form() -> dict[str, Any]:
    return {
        "method": "POST",
        "action": "/weak_id/",
        "fields": [
            {"name": "Generate", "type": "submit", "value": "Generate"},
        ],
    }


# ===========================================================================
# Phase 1 — Hypothesis
# ===========================================================================


class TestPhase1Hypothesis:
    def test_generate_button_qualifies(self) -> None:
        agent = _make_agent()
        ok, _ev = agent._weak_session_phase1_hypothesis(_generate_form())
        assert ok is True

    def test_action_with_new_session_qualifies(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/api/new_session",
            "fields": [{"name": "x", "type": "submit", "value": ""}],
        }
        ok, _ev = agent._weak_session_phase1_hypothesis(form)
        assert ok is True

    def test_no_submit_no_trigger_skipped(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/search",
            "fields": [{"name": "q", "type": "text"}],
        }
        ok, _ev = agent._weak_session_phase1_hypothesis(form)
        assert ok is False


# ===========================================================================
# Phase 2 — Observation
# ===========================================================================


class TestPhase2Observation:
    @pytest.mark.asyncio
    async def test_collects_eight_cookie_samples(self) -> None:
        agent = _make_agent()
        counter = {"i": 0}

        async def fake_post(_url: str, _data: dict[str, str]) -> _HTTPResponse:
            counter["i"] += 1
            return _HTTPResponse(
                status=200,
                body="",
                headers={"Set-Cookie": f"dvwaSession={counter['i']}; Path=/"},
            )

        agent._http_post = fake_post  # type: ignore[method-assign]
        samples, flags = await agent._weak_session_phase2_observation(
            "http://example.com/weak_id/",
            _generate_form(),
        )
        assert "dvwaSession" in samples
        assert samples["dvwaSession"] == ["1", "2", "3", "4", "5", "6", "7", "8"]
        assert flags["dvwaSession"]["httponly"] is False

    @pytest.mark.asyncio
    async def test_no_set_cookie_returns_empty(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        samples, _f = await agent._weak_session_phase2_observation(
            "http://example.com/x",
            _generate_form(),
        )
        assert samples == {}


# ===========================================================================
# Phase 3 — Analysis
# ===========================================================================


class TestPhase3Analysis:
    @pytest.mark.asyncio
    async def test_llm_classification_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=['{"weakness_types": ["sequential"], "weak": true, "rationale": "arithmetic"}']
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, rationale = await agent._weak_session_phase3_analyze(
            "dvwaSession",
            ["1", "2", "3", "4"],
            {"httponly": False, "secure": False, "samesite": False},
        )
        assert SessionWeaknessType.SEQUENTIAL in types
        assert weak is True
        assert "arithmetic" in rationale

    @pytest.mark.asyncio
    async def test_sequential_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(
            "dvwaSession",
            ["1", "2", "3", "4", "5", "6", "7", "8"],
            {"httponly": True, "secure": False, "samesite": True},
        )
        assert SessionWeaknessType.SEQUENTIAL in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_low_entropy_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(
            "sid",
            ["aa", "ab", "ba", "bb"],
            {"httponly": True, "secure": False, "samesite": True},
        )
        assert SessionWeaknessType.LOW_ENTROPY in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_missing_flags_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        # Strong, rotating tokens but no HttpOnly/SameSite.
        types, weak, _r = await agent._weak_session_phase3_analyze(
            "session",
            [
                "Z9q3xQv6dFrK4mWyL2hN8aB1Cs",
                "U7t1xQv6dFrK4mWyL2hN8aB1Df",
                "V8u2xQv6dFrK4mWyL2hN8aB1Eg",
            ],
            {"httponly": False, "secure": False, "samesite": False},
        )
        assert SessionWeaknessType.MISSING_FLAGS in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_constant_value_not_weak(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(
            "sid",
            ["same", "same", "same"],
            {"httponly": True, "secure": True, "samesite": True},
        )
        assert types == []
        assert weak is False


# ===========================================================================
# Phase 4 — Finding
# ===========================================================================


class TestPhase4Finding:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = WeakSessionMethodologyResult(
            phases_completed=4,
            trigger_url="http://example.com/weak_id/",
            cookie_name="dvwaSession",
            observations=["1", "2", "3", "4"],
            cookie_flags={"httponly": False, "secure": False, "samesite": False},
            weakness_types=[SessionWeaknessType.SEQUENTIAL],
            weak=True,
            rationale="arithmetic",
        )
        finding = agent._weak_session_phase4_emit(result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=4" in joined
        assert "weak=True" in joined
        assert finding.severity.value == "high"


# ===========================================================================
# Integration — full _test_weak_session driving all four phases
# ===========================================================================


class TestWeakSessionMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_style_sequential_id_emits_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        # No session cookies, so the flag-inspection path is skipped.
        counter = {"i": 0}

        async def fake_post(_url: str, _data: dict[str, str]) -> _HTTPResponse:
            counter["i"] += 1
            return _HTTPResponse(
                status=200,
                body="",
                headers={"Set-Cookie": f"dvwaSession={counter['i']}; Path=/"},
            )

        agent._http_post = fake_post  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/weak_id/",
            body="",
            status=200,
            forms=[_generate_form()],
        )
        findings = await agent._test_weak_session(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "weak=True" in joined
        assert "phases_completed=4" in joined
