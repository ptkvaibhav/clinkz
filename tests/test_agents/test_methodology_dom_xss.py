"""Unit tests for the adaptive DOM-XSS methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (reflection mapping)   — canary in script context, fragment route
    Phase 1 (source→sink scan)     — co-occurrence inside one block
    Phase 2 (character fingerprint) — DOM placeholder + static-JS analysis
    Phase 3 (payload synthesis)    — LLM JSON parsing + deterministic fallback
    Phase 6 (finding emission)     — Finding evidence chain for both paths

Plus integration tests that drive ``_test_xss_dom`` end-to-end.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    DOMSourceSinkPair,
    DOMXSSDetectionPath,
    DOMXSSMethodologyResult,
    SynthesizedPayload,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-dom-xss-test",
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
        engagement_id="methodology-dom-xss-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


# ===========================================================================
# Phase 1 — Reflection mapping / source→sink scan
# ===========================================================================


class TestPhase1ReflectionMapping:
    def test_canary_in_script_context_detected(self) -> None:
        agent = _make_agent()
        body = '<html><body><script>var x = "DOMCANARY999999";</script></body></html>'
        assert agent._canary_in_script_context(body, "DOMCANARY999999") is True

    def test_canary_outside_script_not_detected(self) -> None:
        agent = _make_agent()
        body = "<html><body><p>DOMCANARY999999</p></body></html>"
        assert agent._canary_in_script_context(body, "DOMCANARY999999") is False

    def test_source_sink_scan_finds_pair_in_same_block(self) -> None:
        agent = _make_agent()
        body = (
            "<html><body>"
            "<script>var data = location.hash;"
            "document.getElementById('out').innerHTML = data;</script>"
            "</body></html>"
        )
        pairs = agent._dom_xss_phase1_source_sink_scan(body)
        assert len(pairs) == 1
        assert "location.hash" in pairs[0].source.lower()
        assert "innerhtml" in pairs[0].sink.lower()

    def test_source_only_no_pair(self) -> None:
        agent = _make_agent()
        body = "<html><body><script>var d = location.hash;</script></body></html>"
        pairs = agent._dom_xss_phase1_source_sink_scan(body)
        assert pairs == []

    def test_sink_only_no_pair(self) -> None:
        agent = _make_agent()
        body = (
            "<html><body><script>document.getElementById('x').innerHTML = 'static';"
            "</script></body></html>"
        )
        pairs = agent._dom_xss_phase1_source_sink_scan(body)
        assert pairs == []

    def test_source_and_sink_in_separate_blocks_no_pair(self) -> None:
        agent = _make_agent()
        body = (
            "<html><body>"
            "<script>var d = location.hash;</script>"
            "<script>document.body.innerHTML = 'static';</script>"
            "</body></html>"
        )
        pairs = agent._dom_xss_phase1_source_sink_scan(body)
        assert pairs == []


# ===========================================================================
# Phase 3 — Payload synthesis (source→sink fallback)
# ===========================================================================


class TestPhase3FragmentSynthesis:
    @pytest.mark.asyncio
    async def test_llm_payload_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "<svg onload=alert(1)>", '
                '"rationale": "html sink", '
                '"expected_execution": "alert"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        pair = DOMSourceSinkPair(
            source="location.hash",
            sink="innerHTML",
            script_excerpt="x.innerHTML = location.hash",
        )
        synth = await agent._dom_xss_phase3_synthesize_fragment_payload([pair])
        assert synth.payload == "<svg onload=alert(1)>"
        assert "html sink" in synth.rationale

    @pytest.mark.asyncio
    async def test_innerhtml_fallback_choose_img_onerror(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        pair = DOMSourceSinkPair(
            source="location.hash",
            sink="innerHTML",
            script_excerpt="x.innerHTML = location.hash",
        )
        synth = await agent._dom_xss_phase3_synthesize_fragment_payload([pair])
        assert "onerror" in synth.payload.lower()

    @pytest.mark.asyncio
    async def test_document_write_fallback_chooses_script_tag(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        pair = DOMSourceSinkPair(
            source="document.URL",
            sink="document.write",
            script_excerpt="document.write(document.URL)",
        )
        synth = await agent._dom_xss_phase3_synthesize_fragment_payload([pair])
        assert "<script>" in synth.payload.lower()

    @pytest.mark.asyncio
    async def test_eval_fallback_chooses_raw_expression(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        pair = DOMSourceSinkPair(
            source="location.hash",
            sink="eval",
            script_excerpt="eval(location.hash.slice(1))",
        )
        synth = await agent._dom_xss_phase3_synthesize_fragment_payload([pair])
        # No HTML tag in eval fallback — it's a raw expression.
        assert "<" not in synth.payload


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6Emission:
    def test_source_to_sink_finding_carries_evidence(self) -> None:
        agent = _make_agent()
        pair = DOMSourceSinkPair(
            source="location.hash",
            sink="innerHTML",
            script_excerpt="x.innerHTML = location.hash",
        )
        result = DOMXSSMethodologyResult(
            phases_completed=6,
            detection_path=DOMXSSDetectionPath.SOURCE_TO_SINK,
            source_sink_pairs=[pair],
            synthesized_payload=SynthesizedPayload(
                payload="<img src=x onerror=alert(1)>",
                rationale="innerHTML sink",
                expected_execution="image error handler",
            ),
            verified=True,
            # Phase 6 is reachable only once execution has been WITNESSED —
            # today nothing sets this, and a "likely" result becomes a lead.
            verification_strength="verified",
        )
        finding = agent._dom_xss_phase6_emit(
            "http://example.com/page",
            None,
            result,
        )
        joined = " ".join(finding.evidence)
        assert "path=source_to_sink" in joined
        assert "phases_completed=6" in joined
        assert finding.severity.value == "high"
        # G2: the evidence must never assert an observation nobody made.
        assert "executed by client-side JS" not in joined

    def test_phase6_refuses_an_unwitnessed_result(self) -> None:
        """The emission path is closed to a ``likely`` strength by construction."""
        agent = _make_agent()
        result = DOMXSSMethodologyResult(
            phases_completed=6,
            detection_path=DOMXSSDetectionPath.SOURCE_TO_SINK,
            source_sink_pairs=[
                DOMSourceSinkPair(
                    source="location.hash",
                    sink="innerHTML",
                    script_excerpt="x.innerHTML = location.hash",
                )
            ],
            verified=True,
            verification_strength="likely",
        )
        with pytest.raises(RuntimeError, match="without witnessed execution"):
            agent._dom_xss_phase6_emit("http://example.com/page", None, result)

    def test_canary_finding_includes_param(self) -> None:
        from clinkz.models.methodology import ReflectionContext, ReflectionPoint

        agent = _make_agent()
        result = DOMXSSMethodologyResult(
            phases_completed=6,
            detection_path=DOMXSSDetectionPath.CANARY_SCRIPT_CONTEXT,
            reflections=[
                ReflectionPoint(
                    location="script[100]",
                    context=ReflectionContext.JS_CODE,
                    surrounding_snippet="var x = 'CLNKZabc';",
                )
            ],
            synthesized_payload=SynthesizedPayload(
                payload="';alert(1);//",
                rationale="js string break",
                expected_execution="alert",
            ),
            candidate_param="q",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._dom_xss_phase6_emit(
            "http://example.com/search",
            "q",
            result,
        )
        assert "q" in (finding.evidence[0] + finding.evidence[1])
        joined = " ".join(finding.evidence)
        assert "path=canary_script_context" in joined


# ===========================================================================
# Integration — full _test_xss_dom driving the methodology
# ===========================================================================


class TestDOMXSSMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_source_to_sink_path_records_lead_not_finding(self) -> None:
        """G2: static source→sink proves REACHABILITY, never execution.

        Without a client-side execution oracle the honest output is an
        ``UnprovenExploitLead`` — a different type than ``Finding``, never
        counted in coverage, never rendered as confirmed.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        body = (
            "<html><body>"
            "<script>var d = location.hash.slice(1);"
            "document.getElementById('out').innerHTML = d;</script>"
            "</body></html>"
        )
        page = PageAnalysis(
            url="http://example.com/dom.html",
            body=body,
            status=200,
            input_params=[],
        )
        findings = await agent._test_xss_dom(page)
        assert findings == []
        leads = agent._unproven_exploit_leads
        assert len(leads) == 1
        assert leads[0].why_unconfirmed == "execution_not_witnessed_requires_client_side_oracle"
        assert "location.hash" in leads[0].raw_observation
        assert "innerHTML" in leads[0].raw_observation
        assert leads[0].claim.startswith("Candidate ")

    @pytest.mark.asyncio
    async def test_canary_script_context_path_records_lead_not_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            value = params.get("name", "")
            return _HTTPResponse(
                status=200,
                body=f'<html><body><script>var greeting = "{value}";</script></body></html>',
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        # Empty body so the source→sink scan finds nothing; only the
        # per-param canary path should trigger.
        page = PageAnalysis(
            url="http://example.com/greet",
            body="<html><body></body></html>",
            status=200,
            input_params=["name"],
        )
        findings = await agent._test_xss_dom(page)
        assert findings == []
        leads = agent._unproven_exploit_leads
        assert len(leads) == 1
        assert leads[0].parameter == "name"
        assert "client-side" in leads[0].missing_observation

    @pytest.mark.asyncio
    async def test_no_dom_evidence_yields_no_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            return _HTTPResponse(
                status=200,
                body="<html><body><p>nothing reflected</p></body></html>",
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/clean?x=1",
            body="<html><body><p>nothing here</p></body></html>",
            status=200,
            input_params=["x"],
        )
        findings = await agent._test_xss_dom(page)
        assert findings == []
