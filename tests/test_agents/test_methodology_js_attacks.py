"""Unit tests for the adaptive JS-attacks methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — form + script gate
    Phase 2 (observation)  — hidden-field / JS-write / validation collection
    Phase 3 (analysis)     — LLM JSON parsing + deterministic fallback +
                              bypass replay
    Phase 4 (finding)      — Finding evidence chain for both severities

Plus integration tests that drive ``_test_javascript_attacks`` end-to-end.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    JSAttackPatternType,
    JSAttacksMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-js-attacks-test",
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
        engagement_id="methodology-js-attacks-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


# ===========================================================================
# Phase 3 — Analysis (deterministic fallback)
# ===========================================================================


class TestPhase3FallbackAnalysis:
    def test_hidden_field_write_without_token_name(self) -> None:
        agent = _make_agent()
        controlled = [("submit_btn", "document.getElementById('submit_btn').value = 'go'")]
        pattern, severity, _r, should_bypass = agent._fallback_js_attacks_analysis(
            controlled, ["submit_btn"], []
        )
        assert pattern == JSAttackPatternType.HIDDEN_FIELD_WRITE
        assert severity == "medium"
        assert should_bypass is True  # string literal — replayable

    def test_token_named_field_classified_as_token_computation(self) -> None:
        agent = _make_agent()
        controlled = [("csrf_token", "document.getElementById('csrf_token').value = 'abc'")]
        pattern, _sev, _r, _bp = agent._fallback_js_attacks_analysis(controlled, ["csrf_token"], [])
        assert pattern == JSAttackPatternType.TOKEN_COMPUTATION

    def test_validation_only_classified_as_client_validation(self) -> None:
        agent = _make_agent()
        validation_hits = ["if (input.value === 'expected') { ... }"]
        pattern, _sev, _r, should_bypass = agent._fallback_js_attacks_analysis(
            [], [], validation_hits
        )
        assert pattern == JSAttackPatternType.CLIENT_VALIDATION
        assert should_bypass is False

    def test_non_literal_write_not_bypassable(self) -> None:
        agent = _make_agent()
        # Concatenation / function call — not a string literal.
        controlled = [("token", "document.getElementById('token').value = computeHash(time)")]
        _p, _s, _r, should_bypass = agent._fallback_js_attacks_analysis(controlled, ["token"], [])
        assert should_bypass is False

    def test_no_evidence_classified_as_none(self) -> None:
        agent = _make_agent()
        pattern, _sev, _r, _bp = agent._fallback_js_attacks_analysis([], [], [])
        assert pattern == JSAttackPatternType.NONE


# ===========================================================================
# Phase 3 — LLM analysis parsing
# ===========================================================================


class TestPhase3LLMAnalysis:
    @pytest.mark.asyncio
    async def test_llm_classification_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"pattern_type": "token_computation", "severity": "high", '
                '"rationale": "JS computes token", "should_attempt_bypass": true}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        controlled = [("csrf", "elem.value = 'literal'")]
        pattern, severity, rationale, bp = await agent._js_attacks_phase3_analyze(
            controlled, ["csrf"], []
        )
        assert pattern == JSAttackPatternType.TOKEN_COMPUTATION
        assert severity == "high"
        assert "computes" in rationale
        assert bp is True

    @pytest.mark.asyncio
    async def test_llm_unparseable_falls_back_to_deterministic(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        controlled = [("name", "elem.value = 'val'")]
        pattern, _sev, _r, _bp = await agent._js_attacks_phase3_analyze(controlled, ["name"], [])
        # Deterministic fallback would pick HIDDEN_FIELD_WRITE for non-token name.
        assert pattern == JSAttackPatternType.HIDDEN_FIELD_WRITE


# ===========================================================================
# Phase 4 — Finding emission
# ===========================================================================


class TestPhase4Emission:
    def test_static_hidden_field_finding_is_medium(self) -> None:
        agent = _make_agent()
        result = JSAttacksMethodologyResult(
            phases_completed=4,
            forms_analyzed=1,
            hidden_fields_set_by_js=["token"],
            pattern_type=JSAttackPatternType.HIDDEN_FIELD_WRITE,
            form_action="http://example.com/submit",
            form_method="POST",
            severity_inferred="medium",
            rationale="JS sets hidden field",
        )
        form = {"method": "POST", "action": "/submit", "fields": []}
        finding = agent._js_attacks_phase4_emit("http://example.com/submit", form, result)
        assert finding.severity.value == "medium"
        joined = " ".join(finding.evidence)
        assert "pattern=hidden_field_write" in joined
        assert "phases_completed=4" in joined

    def test_bypass_succeeded_upgrades_to_high(self) -> None:
        agent = _make_agent()
        result = JSAttacksMethodologyResult(
            phases_completed=4,
            forms_analyzed=1,
            hidden_fields_set_by_js=["token"],
            pattern_type=JSAttackPatternType.HIDDEN_FIELD_WRITE,
            form_action="http://example.com/submit",
            form_method="POST",
            bypass_attempted=True,
            bypass_succeeded=True,
            bypass_payload={"token": "literal", "user": "clinkzbypass"},
            bypass_marker="success!",
            severity_inferred="high",
            rationale="JS sets hidden field with literal",
        )
        form = {"method": "POST", "action": "/submit", "fields": []}
        finding = agent._js_attacks_phase4_emit("http://example.com/submit", form, result)
        assert finding.severity.value == "high"
        joined = " ".join(finding.evidence)
        assert "bypass_succeeded=True" in joined

    def test_client_validation_finding_is_medium(self) -> None:
        agent = _make_agent()
        result = JSAttacksMethodologyResult(
            phases_completed=4,
            forms_analyzed=1,
            validation_patterns=["if (x.value === 'expected') ..."],
            pattern_type=JSAttackPatternType.CLIENT_VALIDATION,
            form_action="http://example.com/login",
            form_method="POST",
            severity_inferred="medium",
            rationale="client-side checkValidity",
        )
        form = {"method": "POST", "action": "/login", "fields": []}
        finding = agent._js_attacks_phase4_emit("http://example.com/login", form, result)
        assert finding.severity.value == "medium"
        joined = " ".join(finding.evidence)
        assert "pattern=client_validation" in joined


# ===========================================================================
# Integration — full _test_javascript_attacks driving the methodology
# ===========================================================================


class TestJSAttacksMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_hidden_field_write_with_literal_emits_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        # Simulate the bypass POST: server returns a success marker.
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="Well done! Challenge solved.",
            )
        )
        body = (
            "<html><body>"
            '<form method="POST" action="/submit">'
            '<input type="text" name="user">'
            '<input type="hidden" name="token" value="">'
            "</form>"
            '<script>document.getElementById("token").value = "success_value";'
            "</script>"
            "</body></html>"
        )
        page = PageAnalysis(
            url="http://example.com/javascript",
            body=body,
            status=200,
            forms=[
                {
                    "method": "POST",
                    "action": "/submit",
                    "fields": [
                        {"name": "user", "type": "text", "value": ""},
                        {"name": "token", "type": "hidden", "value": ""},
                    ],
                }
            ],
        )
        findings = await agent._test_javascript_attacks(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "pattern=hidden_field_write" in joined or "pattern=token_computation" in joined
        # Bypass attempted + succeeded → severity=high.
        assert findings[0].severity.value == "high"

    @pytest.mark.asyncio
    async def test_client_validation_only_emits_medium_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        body = (
            "<html><body>"
            '<form method="POST" action="/login">'
            '<input type="text" name="user">'
            "</form>"
            "<script>function go(){ if (user.value === 'admin') alert(1); "
            "return false; }</script>"
            "</body></html>"
        )
        page = PageAnalysis(
            url="http://example.com/login",
            body=body,
            status=200,
            forms=[
                {
                    "method": "POST",
                    "action": "/login",
                    "fields": [{"name": "user", "type": "text", "value": ""}],
                }
            ],
        )
        findings = await agent._test_javascript_attacks(page)
        assert len(findings) == 1
        assert findings[0].severity.value == "medium"
        joined = " ".join(findings[0].evidence)
        assert "pattern=client_validation" in joined

    @pytest.mark.asyncio
    async def test_form_without_scripts_yields_no_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        body = (
            "<html><body>"
            '<form method="POST" action="/submit">'
            '<input type="text" name="user">'
            "</form>"
            "</body></html>"
        )
        page = PageAnalysis(
            url="http://example.com/no-js",
            body=body,
            status=200,
            forms=[
                {
                    "method": "POST",
                    "action": "/submit",
                    "fields": [{"name": "user", "type": "text", "value": ""}],
                }
            ],
        )
        findings = await agent._test_javascript_attacks(page)
        assert findings == []
