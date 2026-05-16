"""Unit tests for the adaptive brute-force methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — auth-endpoint detection
    Phase 2 (observation)  — 8 failed-auth attempts, response signatures
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
    BruteForceMethodologyResult,
    BruteForceObservation,
    BruteForceProtectionType,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-brute-force-test",
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
        engagement_id="methodology-brute-force-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _login_form(method: str = "POST") -> dict[str, Any]:
    return {
        "method": method,
        "action": "/login",
        "fields": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
            {"name": "Login", "type": "submit", "value": "Login"},
        ],
    }


# ===========================================================================
# Phase 1 — Hypothesis
# ===========================================================================


class TestPhase1Hypothesis:
    def test_login_form_shape_qualifies(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/", body="", status=200)
        ok, _ev = agent._brute_force_phase1_hypothesis(page, _login_form())
        assert ok is True

    def test_path_match_alone_qualifies(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/rest/user/login", body="", status=200)
        # An API endpoint may not expose a login-shape HTML form, but the
        # path alone is enough to qualify.
        form = {"method": "POST", "action": "/rest/user/login", "fields": []}
        ok, _ev = agent._brute_force_phase1_hypothesis(page, form)
        assert ok is True

    def test_unrelated_form_skipped(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/search", body="", status=200)
        form = {
            "method": "GET",
            "action": "/search",
            "fields": [{"name": "q", "type": "text"}],
        }
        ok, _ev = agent._brute_force_phase1_hypothesis(page, form)
        assert ok is False


# ===========================================================================
# Phase 2 — Observation
# ===========================================================================


class TestPhase2Observation:
    @pytest.mark.asyncio
    async def test_collects_eight_observations(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Username and/or password incorrect.")
        )
        observations, evidence = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            "POST",
            _login_form(),
            {},
        )
        assert len(observations) == 8
        assert all(o.status == 200 for o in observations)
        assert evidence["username_field"] == "username"

    @pytest.mark.asyncio
    async def test_rate_limit_short_circuits(self) -> None:
        agent = _make_agent()
        responses = iter(
            [
                _HTTPResponse(status=200, body="invalid"),
                _HTTPResponse(status=200, body="invalid"),
                _HTTPResponse(
                    status=429,
                    body="too many requests",
                    headers={"Retry-After": "60"},
                ),
            ]
        )

        async def fake_post(_url: str, _data: dict[str, str]) -> _HTTPResponse:
            return next(responses)

        agent._http_post = fake_post  # type: ignore[method-assign]
        observations, _ev = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            "POST",
            _login_form(),
            {},
        )
        assert len(observations) == 3
        assert observations[-1].status == 429
        assert observations[-1].retry_after == "60"

    @pytest.mark.asyncio
    async def test_no_password_field_returns_empty(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/login",
            "fields": [{"name": "username", "type": "text"}],
        }
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        observations, _ev = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            "POST",
            form,
            {},
        )
        assert observations == []


# ===========================================================================
# Phase 3 — Analysis
# ===========================================================================


def _obs(
    n: int,
    *,
    status: int = 200,
    length: int = 1024,
    time_ms: float = 50.0,
    body_marker: str = "",
    retry_after: str = "",
) -> BruteForceObservation:
    return BruteForceObservation(
        attempt=n,
        status=status,
        length=length,
        time_ms=time_ms,
        body_marker=body_marker,
        retry_after=retry_after,
    )


class TestPhase3Analysis:
    @pytest.mark.asyncio
    async def test_llm_classification_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "rate_limit", "protected": true, '
                '"observed_at_attempt": 3, "rationale": "429 at attempt 3"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(8)]
        ptype, protected, attempt, rationale = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.RATE_LIMIT
        assert protected is True
        assert attempt == 3
        assert "429" in rationale

    @pytest.mark.asyncio
    async def test_no_protection_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(8)]
        ptype, protected, attempt, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.NONE
        assert protected is False
        assert attempt is None

    @pytest.mark.asyncio
    async def test_retry_after_fallback_detects_rate_limit(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(3)] + [
            _obs(3, status=429, retry_after="30"),
        ]
        ptype, protected, attempt, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.RATE_LIMIT
        assert protected is True
        assert attempt == 3

    @pytest.mark.asyncio
    async def test_captcha_marker_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(4)] + [
            _obs(4, body_marker="captcha required"),
        ]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.CAPTCHA
        assert protected is True

    @pytest.mark.asyncio
    async def test_delay_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [
            _obs(0, time_ms=50.0),
            _obs(1, time_ms=80.0),
            _obs(2, time_ms=120.0),
            _obs(3, time_ms=200.0),
            _obs(4, time_ms=400.0),
            _obs(5, time_ms=800.0),
            _obs(6, time_ms=1200.0),
            _obs(7, time_ms=1600.0),
        ]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.DELAY
        assert protected is True


# ===========================================================================
# Phase 4 — Finding
# ===========================================================================


class TestPhase4Finding:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = BruteForceMethodologyResult(
            phases_completed=4,
            login_url="http://example.com/login",
            method="POST",
            observations=[_obs(i) for i in range(8)],
            protection_type=BruteForceProtectionType.NONE,
            protected=False,
            rationale="all responses identical",
        )
        finding = agent._brute_force_phase4_emit(_login_form(), result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=4" in joined
        assert "protection_type=none" in joined
        assert finding.severity.value == "medium"


# ===========================================================================
# Integration — full _test_brute_force driving all four phases
# ===========================================================================


class TestBruteForceMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_unprotected_login_emits_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Username and/or password incorrect.")
        )
        page = PageAnalysis(
            url="http://example.com/login",
            body="",
            status=200,
            forms=[_login_form()],
        )
        findings = await agent._test_brute_force(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "protection_type=none" in joined
        assert "phases_completed=4" in joined

    @pytest.mark.asyncio
    async def test_rate_limited_login_no_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=429,
                body="too many requests",
                headers={"Retry-After": "60"},
            )
        )
        page = PageAnalysis(
            url="http://example.com/login",
            body="",
            status=200,
            forms=[_login_form()],
        )
        findings = await agent._test_brute_force(page)
        assert findings == []
