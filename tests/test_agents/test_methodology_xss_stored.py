"""Unit tests for the adaptive stored-XSS methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (injection-point mapping)   — submit canary, locate read-back URL
    Phase 2 (character fingerprinting)  — submit-then-fetch round trips
    Phase 3 (payload synthesis)         — re-uses xss-reflected phase 3 hook
    Phase 5 (verification)              — submit + fetch + landing check
    Phase 6 (finding emission)          — evidence chain on the Finding

Plus an end-to-end run that drives all six phases through one ``page``.
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
    CharacterMap,
    FilterBehavior,
    ReflectionContext,
    ReflectionPoint,
    SynthesizedPayload,
    XSSStoredMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-xss-stored-test",
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
        engagement_id="methodology-xss-stored-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_form(field: str = "txtName") -> dict[str, Any]:
    return {
        "action": "",
        "method": "POST",
        "fields": [
            {"name": field, "type": "text", "value": ""},
            {"name": "submit", "type": "submit", "value": "Sign Guestbook"},
        ],
    }


def _make_page(forms: list[dict[str, Any]] | None = None) -> PageAnalysis:
    return PageAnalysis(
        url="http://example.com/guestbook",
        body="",
        status=200,
        forms=forms or [_make_form()],
    )


# ===========================================================================
# Phase 1 — Injection-point mapping
# ===========================================================================


class TestPhase1InjectionPointMapping:
    @pytest.mark.asyncio
    async def test_canary_in_submit_response_marks_action_as_read_back(self) -> None:
        agent = _make_agent()
        # Submit response itself echoes the canary.
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Welcome, CLNKZabc123!")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="other")
        )
        page = _make_page()
        # Canary is generated inside the method; we cheat by patching
        # the reflection mapper to assert the canary path runs.
        url, points = await agent._xss_stored_phase1_injection_point(
            page, _make_form(), "txtName", "CLNKZabc123"
        )
        assert url == page.url  # action == "" → falls back to page.url
        # The body contained the canary, so phase 1 finds at least one reflection.
        assert points  # raw or structured reflection captured

    @pytest.mark.asyncio
    async def test_canary_in_get_after_submit(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Submitted")
        )
        # The page itself shows stored content on a fresh GET.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>Name: CLNKZabc123 said: hello</p>")
        )
        page = _make_page()
        url, points = await agent._xss_stored_phase1_injection_point(
            page, _make_form(), "txtName", "CLNKZabc123"
        )
        assert url == page.url
        assert points

    @pytest.mark.asyncio
    async def test_no_canary_anywhere_returns_none(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Submitted")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="No content")
        )
        page = _make_page()
        url, points = await agent._xss_stored_phase1_injection_point(
            page, _make_form(), "txtName", "CLNKZabc123"
        )
        assert url is None
        assert points == []

    @pytest.mark.asyncio
    async def test_follow_location_redirect_after_submit(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=302,
                body="",
                headers={"Location": "/guestbook?view=1"},
            )
        )
        get_calls = {"n": 0}

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            get_calls["n"] += 1
            if get_calls["n"] == 1:
                return _HTTPResponse(status=200, body="no canary here")
            return _HTTPResponse(status=200, body="Name: CLNKZabc123 said: hi")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        url, points = await agent._xss_stored_phase1_injection_point(
            page, _make_form(), "txtName", "CLNKZabc123"
        )
        assert url is not None
        assert "view=1" in url
        assert points


# ===========================================================================
# Phase 2 — Character fingerprinting
# ===========================================================================


class TestPhase2CharacterFingerprint:
    @pytest.mark.asyncio
    async def test_round_trip_marks_survived_chars(self) -> None:
        agent = _make_agent()

        async def fake_post(_url: str, data: dict[str, str]) -> _HTTPResponse:
            # Submit response leaves the value untouched in a stored block.
            payload = data.get("txtName", "")
            return _HTTPResponse(status=200, body=f"<p>{payload}</p>")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>not used</p>")
        )
        page = _make_page()
        char_map = await agent._xss_stored_phase2_character_fingerprint(
            page, _make_form(), "txtName", page.url
        )
        # All structural chars survive a no-op echo server.
        survived = [c for c, b in char_map.per_char.items() if b == FilterBehavior.SURVIVED]
        assert "<" in survived
        assert ">" in survived
        assert '"' in survived

    @pytest.mark.asyncio
    async def test_html_encoded_chars_recorded(self) -> None:
        agent = _make_agent()

        async def fake_post(_url: str, data: dict[str, str]) -> _HTTPResponse:
            payload = data.get("txtName", "")
            # Server html-encodes < > " in stored output.
            encoded = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return _HTTPResponse(status=200, body=f"<p>{encoded}</p>")

        agent._http_post = fake_post  # type: ignore[method-assign]
        page = _make_page()
        char_map = await agent._xss_stored_phase2_character_fingerprint(
            page, _make_form(), "txtName", page.url
        )
        assert char_map.per_char.get("<") == FilterBehavior.HTML_ENCODED
        assert char_map.per_char.get(">") == FilterBehavior.HTML_ENCODED


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_payload_landing_in_html_body_verifies(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="ok")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="<p>Comment: <script>alert(1)</script></p>",
            )
        )
        page = _make_page()
        verified, ctx = await agent._xss_stored_phase5_verify(
            page, _make_form(), "txtName", "<script>alert(1)</script>", page.url
        )
        assert verified is True
        assert ctx in ("html_body", "script", "tag")

    @pytest.mark.asyncio
    async def test_escaped_payload_does_not_verify(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="ok")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="<p>Comment: &lt;script&gt;alert(1)&lt;/script&gt;</p>",
            )
        )
        page = _make_page()
        verified, ctx = await agent._xss_stored_phase5_verify(
            page, _make_form(), "txtName", "<script>alert(1)</script>", page.url
        )
        assert verified is False
        assert "absent" in ctx


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=6,
            character_map=CharacterMap(per_char={"<": FilterBehavior.SURVIVED}),
            reflections=[
                ReflectionPoint(
                    location="body[100]",
                    context=ReflectionContext.HTML_BODY,
                    surrounding_snippet="<p>...",
                )
            ],
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="< unfiltered in HTML body",
                expected_execution="alert dialog",
            ),
            read_back_url="http://example.com/guestbook",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._xss_stored_phase6_emit("http://example.com/guestbook", "txtName", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "strength=verified" in joined
        assert "read_back_url=http://example.com/guestbook" in joined
        assert finding.severity.value == "high"
        assert "stored xss" in finding.title.lower()


# ===========================================================================
# Integration — full _test_xss_stored driving all six phases
# ===========================================================================


class TestXSSStoredMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_low_style_stored_xss(self) -> None:
        """End-to-end: form post + GET reflects stored content unescaped."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        stored: dict[str, str] = {}

        async def fake_post(_url: str, data: dict[str, str]) -> _HTTPResponse:
            stored["last"] = data.get("txtName", "")
            return _HTTPResponse(status=200, body=f"Stored: {stored['last']}")

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            return _HTTPResponse(status=200, body=f"<p>{stored.get('last', '')}</p>")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        findings = await agent._test_xss_stored(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "strength=verified" in joined
