"""Unit tests for the adaptive security-headers methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — endpoint reachable
    Phase 2 (observation)  — endpoint + origin-root header capture
    Phase 3 (analysis)     — LLM JSON parsing + deterministic fallback
    Phase 4 (finding)      — Finding evidence chain + dedup behaviour

Dedup test verifies that a multi-URL run on the same origin produces N
findings (one per missing header per origin), not N × URL-count.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    HeaderWeaknessSeverity,
    SecurityHeadersMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-security-headers-test",
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
        engagement_id="methodology-security-headers-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(url: str = "http://example.com/page") -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200)


# ===========================================================================
# Phase 2 — Observation (root merge)
# ===========================================================================


class TestPhase2Observation:
    @pytest.mark.asyncio
    async def test_root_csp_merged_into_endpoint_observation(self) -> None:
        agent = _make_agent()

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            if url.endswith("/"):
                return _HTTPResponse(
                    status=200, body="", headers={"Content-Security-Policy": "default-src 'self'"}
                )
            return _HTTPResponse(status=200, body="", headers={})

        agent._http_get = fake_get  # type: ignore[method-assign]
        result = await agent._run_security_headers_methodology(_make_page())
        # CSP was set on /, observation merges, so it should not be in missing.
        assert "Content-Security-Policy" not in result.missing_headers


# ===========================================================================
# Phase 3 — Analysis
# ===========================================================================


class TestPhase3Analysis:
    @pytest.mark.asyncio
    async def test_llm_analysis_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"missing": ["X-Content-Type-Options"], '
                '"weak": [["Content-Security-Policy", "unsafe-inline"]], '
                '"severity": "medium", "rationale": "csp permissive"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        missing, weak, sev, rationale = await agent._security_headers_phase3_analyze(
            "https://example.com/",
            {"content-security-policy": "default-src 'self' 'unsafe-inline'"},
        )
        assert missing == ["X-Content-Type-Options"]
        assert weak == [("Content-Security-Policy", "unsafe-inline")]
        assert sev == HeaderWeaknessSeverity.MEDIUM
        assert "permissive" in rationale

    @pytest.mark.asyncio
    async def test_fallback_missing_csp_marks_medium(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        missing, weak, sev, _r = await agent._security_headers_phase3_analyze(
            "http://example.com/",
            {},
        )
        assert "Content-Security-Policy" in missing
        assert "X-Frame-Options" in missing
        assert "X-Content-Type-Options" in missing
        # Weak set is empty when there is no CSP at all.
        assert weak == []
        assert sev == HeaderWeaknessSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_fallback_https_missing_hsts_flagged(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        missing, _w, sev, _r = await agent._security_headers_phase3_analyze(
            "https://example.com/",
            {"content-security-policy": "default-src 'self'"},
        )
        assert "Strict-Transport-Security" in missing
        assert sev == HeaderWeaknessSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_fallback_csp_unsafe_combination_marks_high(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        # CSP exists but combines unsafe-inline + unsafe-eval + wildcard.
        _m, weak, sev, _r = await agent._security_headers_phase3_analyze(
            "https://example.com/",
            {
                "content-security-policy": (
                    "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"
                ),
                "strict-transport-security": "max-age=63072000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        )
        assert any("Content-Security-Policy" == w[0] for w in weak)
        assert sev == HeaderWeaknessSeverity.HIGH


# ===========================================================================
# Phase 4 — Finding emission + dedup
# ===========================================================================


class TestPhase4Emission:
    def test_one_finding_per_missing_header(self) -> None:
        agent = _make_agent()
        result = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/page",
            headers_observed={},
            missing_headers=["X-Frame-Options", "Content-Security-Policy"],
            weak_headers=[],
            severity_rollup=HeaderWeaknessSeverity.MEDIUM,
            rationale="missing both",
        )
        findings = agent._security_headers_phase4_emit(result)
        assert len(findings) == 2
        titles = sorted(f.title for f in findings)
        assert "Missing Security Header Content-Security-Policy" in titles[0]
        assert "Missing Security Header X-Frame-Options" in titles[1]

    def test_dedup_across_urls_on_same_origin(self) -> None:
        agent = _make_agent()
        result_a = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/page-a",
            missing_headers=["X-Frame-Options"],
            severity_rollup=HeaderWeaknessSeverity.LOW,
        )
        result_b = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/page-b",
            missing_headers=["X-Frame-Options"],
            severity_rollup=HeaderWeaknessSeverity.LOW,
        )
        first = agent._security_headers_phase4_emit(result_a)
        second = agent._security_headers_phase4_emit(result_b)
        assert len(first) == 1
        assert second == []

    def test_different_origins_emit_separately(self) -> None:
        agent = _make_agent()
        result_a = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/",
            missing_headers=["X-Frame-Options"],
            severity_rollup=HeaderWeaknessSeverity.LOW,
        )
        result_b = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://api.example.com",
            observed_url="http://api.example.com/",
            missing_headers=["X-Frame-Options"],
            severity_rollup=HeaderWeaknessSeverity.LOW,
        )
        first = agent._security_headers_phase4_emit(result_a)
        second = agent._security_headers_phase4_emit(result_b)
        assert len(first) == 1
        assert len(second) == 1


# ===========================================================================
# Integration — full _test_security_headers driving all four phases
# ===========================================================================


class TestSecurityHeadersMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_bare_endpoint_emits_findings(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="", headers={})
        )
        page = _make_page("http://example.com/page-1")
        findings = await agent._test_security_headers(page)
        # CSP, XFO, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
        assert len(findings) >= 4
        joined = " ".join(findings[0].evidence)
        assert "origin=http://example.com" in joined
        assert "phases_completed=3" in joined

    @pytest.mark.asyncio
    async def test_multi_url_run_dedup_verified(self) -> None:
        """A 5-URL run on the same origin must NOT produce 5x findings."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 40))
        agent._methodology_llm = agent.llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="", headers={})
        )
        all_findings = []
        for i in range(5):
            page = _make_page(f"http://example.com/page-{i}")
            all_findings.extend(await agent._test_security_headers(page))
        # Same origin → only first page should emit findings; subsequent
        # pages on the same origin must dedup.
        # The first call yields N findings; the next 4 must yield 0.
        first_origin_findings = [
            f for f in all_findings if "origin=http://example.com" in " ".join(f.evidence)
        ]
        # Distinct missing headers per origin — only one entry per
        # (origin, header) pair.
        seen_titles = {f.title for f in first_origin_findings}
        assert len(first_origin_findings) == len(seen_titles)
