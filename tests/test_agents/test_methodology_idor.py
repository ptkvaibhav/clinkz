"""Unit tests for the adaptive IDOR methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (reference-point mapping)  — candidacy by lexical signal +
                                         response-shape evidence
    Phase 2 (authz-model fingerprint)  — id format, predictability,
                                         authz-check presence
    Phase 3 (exploitation-type ranking) — LLM JSON parsing + fallback
    Phase 4 (reference synthesis)       — LLM JSON parsing + fallback
    Phase 5 (verification)              — response-shape divergence
    Phase 6 (finding emission)          — evidence chain on the Finding
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    IDORExploitationType,
    IDORMethodologyResult,
    IDORPrimitives,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-idor-test",
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
        engagement_id="methodology-idor-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(
    url: str = "http://example.com/account?id=1", params: list[str] | None = None
) -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=params or ["id"])


# ===========================================================================
# Phase 1 — Reference point mapping
# ===========================================================================


class TestPhase1ReferencePointMapping:
    @pytest.mark.asyncio
    async def test_name_signal_alone_marks_candidate(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="some content")
        )
        is_candidate, ev = await agent._idor_phase1_reference_point(_make_page(), "id", "1")
        assert is_candidate is True
        assert ev["name_signal"] is True

    @pytest.mark.asyncio
    async def test_no_name_signal_but_increment_diverges_is_candidate(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("q", "")
            if val == "1":
                return _HTTPResponse(
                    status=200,
                    body=(
                        "user: alice email: alice@x.example role: user dob: 1990-01-01 region: us"
                    ),
                )
            # Much longer response so divergence threshold (10 bytes) clears.
            return _HTTPResponse(
                status=200,
                body=(
                    "user: bob email: bob@x.example role: admin "
                    "dob: 1985-02-02 region: eu phone: +44-12345"
                ),
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(url="http://example.com/?q=1", body="", status=200, input_params=["q"])
        is_candidate, ev = await agent._idor_phase1_reference_point(page, "q", "1")
        assert is_candidate is True
        assert ev["name_signal"] is False

    @pytest.mark.asyncio
    async def test_no_signal_and_scalar_body_not_a_candidate(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="OK")
        )
        page = PageAnalysis(
            url="http://example.com/?q=hello", body="", status=200, input_params=["q"]
        )
        is_candidate, _ev = await agent._idor_phase1_reference_point(page, "q", "hello")
        assert is_candidate is False


# ===========================================================================
# Phase 2 — Authz model fingerprint
# ===========================================================================


class TestPhase2AuthzModelFingerprint:
    @pytest.mark.asyncio
    async def test_numeric_id_sequential_no_authz(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val in ("1", "2", "11"):
                return _HTTPResponse(
                    status=200,
                    body=f"user: u{val} email: u{val}@x role: user",
                )
            return _HTTPResponse(status=200, body="user: u? email: ? role: user")

        agent._http_get = fake_get  # type: ignore[method-assign]
        phase1_ev = {"increment_diverged": True, "baseline_body": "user: u1 email: u1@x"}
        primitives, _ev = await agent._idor_phase2_fingerprint(_make_page(), "id", "1", phase1_ev)
        assert primitives.id_format == "numeric"
        assert primitives.predictability == "sequential"
        assert primitives.authz_check_present is False

    @pytest.mark.asyncio
    async def test_uuid_format_random(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="resource")
        )
        primitives, _ev = await agent._idor_phase2_fingerprint(
            _make_page(),
            "id",
            "550e8400-e29b-41d4-a716-446655440000",
            {"increment_diverged": False, "baseline_body": "resource"},
        )
        assert primitives.id_format == "uuid"
        assert primitives.predictability == "random_uuid"

    @pytest.mark.asyncio
    async def test_authz_check_present_when_unauthorized(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val == "99999999":
                return _HTTPResponse(status=403, body="forbidden")
            return _HTTPResponse(status=200, body="user resource")

        agent._http_get = fake_get  # type: ignore[method-assign]
        primitives, _ev = await agent._idor_phase2_fingerprint(
            _make_page(),
            "id",
            "1",
            {"increment_diverged": True, "baseline_body": "user resource"},
        )
        assert primitives.authz_check_present is True


# ===========================================================================
# Phase 3 — Exploitation type ranking
# ===========================================================================


class TestPhase3ExploitationTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "horizontal", "rationale": "peer"},'
                '{"type": "vertical", "rationale": "fallback"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            {},
        )
        assert ranked[0] == IDORExploitationType.HORIZONTAL
        assert ranked[1] == IDORExploitationType.VERTICAL

    @pytest.mark.asyncio
    async def test_fallback_sequential_ranks_horizontal_first(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(
                id_format="numeric",
                predictability="sequential",
                increment_diverged=True,
            ),
            {},
        )
        assert ranked[0] == IDORExploitationType.HORIZONTAL

    @pytest.mark.asyncio
    async def test_fallback_authz_present_ranks_pollution(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(
                id_format="numeric",
                predictability="opaque",
                authz_check_present=True,
            ),
            {},
        )
        assert IDORExploitationType.PARAMETER_POLLUTION in ranked


# ===========================================================================
# Phase 4 — Reference synthesis
# ===========================================================================


class TestPhase4ReferenceSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(answers=['{"reference": "42", "rationale": "next-id peer"}'])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.HORIZONTAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "41",
        )
        assert synth is not None
        assert synth["reference"] == "42"

    @pytest.mark.asyncio
    async def test_fallback_horizontal_numeric_increments(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.HORIZONTAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "5",
        )
        assert synth is not None
        assert synth["reference"] == "6"

    @pytest.mark.asyncio
    async def test_fallback_vertical_numeric_uses_id_1(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.VERTICAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "5",
        )
        assert synth is not None
        assert synth["reference"] == "1"


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_different_content_same_shape_verifies(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="user: bob email: bob@x.example role: user dob: 1985-01-01",
            )
        )
        phase1_ev = {
            "baseline_status": 200,
            "baseline_body": "user: alice email: alice@x.example role: user dob: 1990-01-01",
        }
        verified, observed = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            phase1_ev,
        )
        assert verified is True
        assert observed is not None

    @pytest.mark.asyncio
    async def test_identical_response_does_not_verify(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="same exact body")
        )
        phase1_ev = {"baseline_status": 200, "baseline_body": "same exact body"}
        verified, _observed = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            phase1_ev,
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_403_does_not_verify(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=403, body="forbidden")
        )
        phase1_ev = {"baseline_status": 200, "baseline_body": "user: alice"}
        verified, _observed = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            phase1_ev,
        )
        assert verified is False


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = IDORMethodologyResult(
            phases_completed=6,
            primitives=IDORPrimitives(
                id_format="numeric",
                predictability="sequential",
                increment_diverged=True,
            ),
            exploitation_type=IDORExploitationType.HORIZONTAL,
            synthesized_reference="2",
            rationale="peer-resource increment",
            indicator_observed="response shape matched baseline with different content",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._idor_phase6_emit("http://example.com/account", "id", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "exploitation_type=horizontal" in joined
        assert "reference=2" in joined
        assert finding.severity.value == "high"


# ===========================================================================
# Integration — full _test_idor driving all six phases
# ===========================================================================


class TestIDORMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_authbypass_style_horizontal_idor(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val == "1":
                return _HTTPResponse(
                    status=200,
                    body=(
                        "user: alice email: alice@x.example role: user dob: 1990-01-01 region: us"
                    ),
                )
            if val == "2":
                return _HTTPResponse(
                    status=200,
                    body=(
                        "user: bob email: bob@x.example role: user "
                        "dob: 1985-02-02 region: eu phone: +44-12345 city: london"
                    ),
                )
            if val == "99999999":
                return _HTTPResponse(status=404, body="not found")
            return _HTTPResponse(
                status=200,
                body=("user: other email: other@x.example role: user dob: 1992-03-03 region: ap"),
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        findings = await agent._test_idor(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "exploitation_type=" in joined


# ===========================================================================
# Deterministic divergence gate — no LLM, no finding on identical responses
# ===========================================================================


class TestIDORDeterministicGate:
    @pytest.mark.asyncio
    async def test_identical_response_emits_nothing_and_makes_no_llm_call(self) -> None:
        """Every reference probe byte-identical to baseline ⇒ not an IDOR.

        The deterministic gate must short-circuit *before* the phase-3 LLM
        checkpoint: emit nothing and make zero LLM calls. This is the
        false-positive shape where IDOR claimed divergence on an identical
        response (length 5390 → 5390)."""
        llm = _ScriptedLLM(answers=["SHOULD-NOT-BE-USED"] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        # Param named "id" → lexical name-signal candidate, but every probe
        # returns the same body, so there is no divergence to confirm.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="X" * 5390)
        )
        page = _make_page()  # url ...?id=1, params ["id"]
        findings = await agent._test_idor(page)

        assert findings == []
        assert llm.prompts == [], "gate must fire before any LLM checkpoint"

    @pytest.mark.asyncio
    async def test_status_change_probe_passes_gate(self) -> None:
        """A status change on a probe is divergence — the gate lets it through
        to the LLM checkpoints (here the scripted-empty LLM falls back)."""
        llm = _ScriptedLLM(answers=[""] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            if params.get("id") == "99999999":
                return _HTTPResponse(status=403, body="forbidden")
            return _HTTPResponse(status=200, body="user: alice role: user " * 10)

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        await agent._test_idor(page)
        # The gate did not short-circuit: at least the phase-3 ranking prompt
        # was issued.
        assert llm.prompts, "diverged probe should reach the LLM checkpoint"
