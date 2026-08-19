"""Unit tests for the adaptive weak-session methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — session-generation trigger detection
    Phase 2 (observation)  — 8-sample cookie collection + flag inspection
    Phase 3 (analysis)     — deterministic classification (no LLM on this path)
    Phase 4 (finding)      — Finding evidence chain
"""

from __future__ import annotations

import hashlib
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _deterministic_session_weaknesses,
    _HTTPResponse,
)
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

    async def generate_text(self, prompt: str, **_kw: object) -> str:
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
    async def test_the_llm_is_never_consulted(self) -> None:
        """The model is not asked — asserted on the CALL, not on the answer.

        The verdict was already deterministic; what the model still produced was
        an advisory rationale that phase 4 copies verbatim into the finding's
        evidence. Model prose sitting in an evidence field beside measurements
        is a claim nobody made, so the call is gone. Only the absence of the
        call establishes that — a test comparing verdicts passes just as
        happily against a version that asks and discards the answer.
        """
        llm = _ScriptedLLM(
            answers=['{"weakness_types": ["sequential"], "weak": true, "rationale": "arithmetic"}']
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        types, weak, rationale = await agent._weak_session_phase3_analyze(["1", "2", "3", "4"])

        assert llm.prompts == []
        assert llm.answers, "the scripted answer must still be unconsumed"
        assert SessionWeaknessType.SEQUENTIAL in types
        assert weak is True
        # The rationale is the deterministic evidence line. The advisory marker
        # the model's prose used to be appended under is gone with the call.
        assert "LLM advisory" not in rationale
        assert "integer arithmetic sequence" in rationale

    @pytest.mark.asyncio
    async def test_sequential_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(
            ["1", "2", "3", "4", "5", "6", "7", "8"]
        )
        assert SessionWeaknessType.SEQUENTIAL in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_low_entropy_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(["aa", "ab", "ba", "bb"])
        assert SessionWeaknessType.LOW_ENTROPY in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_strong_token_missing_flags_not_weak(self) -> None:
        """FIX 1: a strong, rotating, high-entropy token is NOT a weak session ID
        even when HttpOnly/SameSite are absent — missing flags are a
        cookie-hardening note, never a HIGH 'weak session' finding."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(
            [
                "Z9q3xQv6dFrK4mWyL2hN8aB1Cs",
                "U7t1xQv6dFrK4mWyL2hN8aB1Df",
                "V8u2xQv6dFrK4mWyL2hN8aB1Eg",
            ]
        )
        assert types == []
        assert weak is False

    @pytest.mark.asyncio
    async def test_high_entropy_random_token_not_weak_despite_llm(self) -> None:
        """FIX 1 (the DVWA-impossible phantom): a 160-bit random token
        (bin2hex(random_bytes(20))) is NEVER predictable. The prose that used to
        say otherwise is now unreachable — kept as a regression because the
        scripted answer proves the model is not asked at all."""
        llm = _ScriptedLLM(
            answers=[
                '{"weakness_types": ["predictable_format"], "weak": true, '
                '"rationale": "DVWA is known to generate SHA-1 of predictable inputs"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        # HttpOnly+Secure, missing SameSite — exactly the impossible cookie shape.
        types, weak, _r = await agent._weak_session_phase3_analyze(
            [
                "558435b215ef0d8329d92ba1ec1e85b9d1f0a8c1",
                "3a3479869209db45a91b2cf0e1d6f7a8b9c0d1e2",
                "49964a0a53432bd1f3b6c7d8e9f0a1b2c3d4e5f6",
            ]
        )
        assert weak is False
        assert SessionWeaknessType.PREDICTABLE_FORMAT not in types
        assert llm.prompts == []

    @pytest.mark.asyncio
    async def test_md5_of_sequential_int_is_predictable_format(self) -> None:
        """FIX 1 (MUST keep DVWA-high): md5 of a sequential counter cracks to a
        bounded preimage → predictable_format → weak, regardless of LLM prose."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        values = [hashlib.md5(str(i).encode()).hexdigest() for i in range(1, 9)]
        types, weak, _r = await agent._weak_session_phase3_analyze(values)
        assert SessionWeaknessType.PREDICTABLE_FORMAT in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_time_correlated_unix_timestamps_weak(self) -> None:
        """FIX 1 (MUST keep DVWA-medium): tokens that are recent unix timestamps
        (PHP time()) confirm via the timestamp-window check."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        now = int(time.time())
        values = [str(now), str(now), str(now + 1), str(now + 1), str(now + 2)]
        types, weak, _r = await agent._weak_session_phase3_analyze(values)
        assert SessionWeaknessType.TIME_CORRELATED in types
        assert weak is True

    @pytest.mark.asyncio
    async def test_constant_value_not_weak(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        types, weak, _r = await agent._weak_session_phase3_analyze(["same", "same", "same"])
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


# ===========================================================================
# FIX 1 — deterministic predictability gate (LLM-proof ground truth)
# ===========================================================================


class TestDeterministicPredictabilityGate:
    """Direct unit tests of the gate that decides emission, independent of the
    LLM. The DVWA matrix in one place: low/medium/high confirm, impossible does
    not."""

    def test_low_sequential_integer(self) -> None:
        types, _lines = _deterministic_session_weaknesses(["1", "2", "3", "4", "5"])
        assert SessionWeaknessType.SEQUENTIAL in types

    def test_medium_unix_timestamps(self) -> None:
        now = int(time.time())
        types, _lines = _deterministic_session_weaknesses(
            [str(now), str(now + 1), str(now + 1), str(now + 2)]
        )
        assert SessionWeaknessType.TIME_CORRELATED in types

    def test_medium_constant_current_timestamp_same_second(self) -> None:
        """Fast sampling can return the SAME current-epoch value for all 8 PHP
        time() reads; a token equal to 'now' is still time-correlated."""
        now = str(int(time.time()))
        types, _lines = _deterministic_session_weaknesses([now] * 8)
        assert SessionWeaknessType.TIME_CORRELATED in types

    def test_constant_static_numeric_id_not_weak(self) -> None:
        """A constant numeric session ID that is NOT a current timestamp is just
        a static cookie — not a generator weakness."""
        types, _lines = _deterministic_session_weaknesses(["12345"] * 8)
        assert types == set()

    def test_high_md5_of_counter(self) -> None:
        values = [hashlib.md5(str(i).encode()).hexdigest() for i in range(1, 9)]
        types, _lines = _deterministic_session_weaknesses(values)
        assert SessionWeaknessType.PREDICTABLE_FORMAT in types

    def test_high_sha1_of_counter(self) -> None:
        values = [hashlib.sha1(str(i).encode()).hexdigest() for i in range(1, 9)]
        types, _lines = _deterministic_session_weaknesses(values)
        assert SessionWeaknessType.PREDICTABLE_FORMAT in types

    def test_impossible_random_160bit_token_not_predictable(self) -> None:
        # bin2hex(random_bytes(20)) — 40 hex chars, 160 bits, no preimage.
        values = [
            "558435b215ef0d8329d92ba1ec1e85b9d1f0a8c1",
            "3a3479869209db45a91b2cf0e1d6f7a8b9c0d1e2",
            "49964a0a53432bd1f3b6c7d8e9f0a1b2c3d4e5f6",
            "9e4fa3df63b8b0641122334455667788990aabbc",
        ]
        types, _lines = _deterministic_session_weaknesses(values)
        assert types == set()

    def test_constant_value_not_weak(self) -> None:
        types, _lines = _deterministic_session_weaknesses(["same", "same", "same"])
        assert types == set()

    def test_too_few_samples_not_weak(self) -> None:
        types, _lines = _deterministic_session_weaknesses(["1", "2"])
        assert types == set()
