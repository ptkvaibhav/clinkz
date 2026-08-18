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
from clinkz.models.scan import ParamLocation
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

    @pytest.mark.asyncio
    async def test_json_body_stored_xss(self) -> None:
        """fix #4: a JSON API store (POST /api/Feedbacks {comment}) — no HTML
        <form> — is reached via the synthesized JSON pseudo-form, submitted as
        a JSON body, and verified on read-back."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        stored: dict[str, str] = {}

        async def fake_post_json(
            _url: str, obj: dict[str, Any], method: str = "POST"
        ) -> _HTTPResponse:
            stored["last"] = str(obj.get("comment", ""))
            return _HTTPResponse(status=201, body="ok")

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            # Read-back surface renders the stored comment unescaped.
            return _HTTPResponse(status=200, body=f"<div>{stored.get('last', '')}</div>")

        agent._http_post_json = fake_post_json  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        # No HTML form — purely a JSON-body endpoint.
        page = PageAnalysis(
            url="http://example.com/api/Feedbacks",
            body="",
            status=200,
            input_params=["comment", "rating"],
            request_method="POST",
            content_type="application/json",
            param_locations={
                "comment": ParamLocation.JSON_BODY,
                "rating": ParamLocation.JSON_BODY,
            },
        )
        findings = await agent._test_xss_stored(page)
        assert len(findings) == 1, "stored XSS did not reach the JSON-body injection point"
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "strength=verified" in joined
        # The injection point really was the JSON body (a comment was stored).
        assert stored["last"]


# ===========================================================================
# Verification gate — never emit when nothing actually verified
# ===========================================================================


class TestXSSStoredVerificationGate:
    @pytest.mark.asyncio
    async def test_no_reachable_reflection_emits_nothing(self) -> None:
        """When nothing the methodology submits ever lands in the read-back
        (canary and payload both absent), no payload can be verified — so the
        methodology must emit NO finding, not an unverified one.

        Previously a missing read-back URL produced a 'confirmed' finding with
        strength=unverified even though verification never confirmed an
        executable reflection — the contradiction this gate removes."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        # Server acknowledges the post but never echoes input anywhere.
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Submitted. Thank you.")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>No content stored.</p>")
        )
        page = _make_page()
        findings = await agent._test_xss_stored(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_all_chars_encoded_emits_nothing(self) -> None:
        """Read-back exists but the store HTML-encodes every special char, so
        no payload lands unescaped — emit nothing."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        stored: dict[str, str] = {}

        async def fake_post(_url: str, data: dict[str, str]) -> _HTTPResponse:
            stored["last"] = data.get("txtName", "")
            return _HTTPResponse(status=200, body="Submitted")

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            raw = stored.get("last", "")
            encoded = (
                raw.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;")
            )
            return _HTTPResponse(status=200, body=f"<p>{encoded}</p>")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        findings = await agent._test_xss_stored(page)
        assert findings == []


# ===========================================================================
# G1 — the confirmation gate (the ``impossible``-level phantom)
#
# Engagement 913fecee emitted "Stored XSS via user_token in form" at DVWA
# ``impossible``: the injection point was the anti-CSRF token field, the
# payload was the bare alphanumeric ``alert1``, ``read_back_url`` was None, and
# the synthesis LLM's own verdict was "No JavaScript execution occurs". Each
# condition below independently makes that emission impossible.
# ===========================================================================


class TestStoredXSSConfirmationGate:
    @pytest.mark.asyncio
    async def test_missing_read_back_url_cannot_verify(self) -> None:
        """A confirm with ``read_back_url=None`` must be impossible by construction.

        Previously phase 5 fell back to re-reading the page the payload was
        submitted to, turning any substring already on that page into a
        "confirmation".
        """
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="ok")
        )
        get_mock = AsyncMock(
            return_value=_HTTPResponse(status=200, body="<p><script>alert(1)</script></p>")
        )
        agent._http_get = get_mock  # type: ignore[method-assign]
        page = _make_page()
        verified, ctx = await agent._xss_stored_phase5_verify(
            page, _make_form(), "txtName", "<script>alert(1)</script>", None
        )
        assert verified is False
        assert "read-back" in ctx
        # And it never even fetched — there is nothing to fetch.
        assert get_mock.await_count == 0

    @pytest.mark.asyncio
    async def test_payload_without_functional_chars_cannot_verify(self) -> None:
        """``alert1`` survives the round trip but can never execute."""
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="ok")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>alert1</p>")
        )
        page = _make_page()
        verified, ctx = await agent._xss_stored_phase5_verify(
            page, _make_form(), "txtName", "alert1", page.url
        )
        assert verified is False
        assert "XSS-functional" in ctx

    def test_functional_capability_is_context_dependent(self) -> None:
        agent = _make_agent()
        cap = agent._xss_payload_has_functional_capability
        assert cap("<script>alert(1)</script>", "html_body") is True
        assert cap("' onfocus='alert(1)' autofocus='", "html_body") is True
        assert cap("alert1", "html_body") is False
        assert cap("ClinkzProbe123", "tag") is False
        # Inside a <script> block a string/statement breakout is what counts.
        assert cap("';alert(1);//", "script") is True
        assert cap("alert1", "script") is False

    @pytest.mark.asyncio
    async def test_token_field_is_not_an_injection_point(self) -> None:
        """The anti-CSRF token is the app echoing its own state, not user content."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm
        submitted: list[dict[str, str]] = []

        async def fake_post(_url: str, data: dict[str, str]) -> _HTTPResponse:
            submitted.append(data)
            return _HTTPResponse(status=200, body="ok")

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            return _HTTPResponse(status=200, body="<p>nothing</p>")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        form = {
            "action": "",
            "method": "POST",
            "fields": [{"name": "user_token", "type": "hidden", "value": "abc123"}],
        }
        findings = await agent._test_xss_stored(_make_page(forms=[form]))
        assert findings == []
        assert submitted == [], "the methodology probed an anti-CSRF token field"

    def test_prepopulated_hidden_field_is_not_an_injection_point(self) -> None:
        agent = _make_agent()
        assert agent._xss_stored_field_is_app_controlled(
            {"name": "state", "type": "hidden", "value": "server-issued"}
        )
        # A hidden field the app did NOT pre-populate can still be user-driven.
        assert not agent._xss_stored_field_is_app_controlled(
            {"name": "comment_html", "type": "hidden", "value": ""}
        )

    def test_gate_blocks_emission_regardless_of_llm_verdict(self) -> None:
        """THE emission invariant: deterministic check GATES the LLM — never an OR.

        A positive LLM verdict cannot rescue a result whose deterministic
        verification failed, and phase 6 refuses to render one.
        """
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=5,
            read_back_url="http://example.com/guestbook",
            landing_context="html_body",
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="This will definitely execute and pop an alert.",
                expected_execution="Script executes in the victim's browser.",
            ),
            verified=False,  # the deterministic oracle said no
        )
        ok, reason = agent._xss_stored_confirmation_gate(result)
        assert ok is False
        assert "deterministic" in reason
        with pytest.raises(RuntimeError, match="confirmation gate"):
            agent._xss_stored_phase6_emit("http://example.com/guestbook", "txtName", result)

    def test_gate_vetoes_a_synthesis_that_states_no_execution(self) -> None:
        """The 'never an OR' half: a negative LLM verdict can only SUPPRESS."""
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=5,
            read_back_url="http://example.com/guestbook",
            landing_context="html_body",
            synthesized_payload=SynthesizedPayload(
                payload="<b>alert1</b>",
                rationale=(
                    "Every character required to break out is stripped; it is "
                    "not possible to construct a functional payload."
                ),
                expected_execution="No JavaScript execution occurs.",
            ),
            verified=True,  # deterministic check passed
        )
        ok, reason = agent._xss_stored_confirmation_gate(result)
        assert ok is False
        assert "no execution" in reason

    def test_gate_requires_a_read_back_url(self) -> None:
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=5,
            read_back_url=None,
            landing_context="html_body",
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="breaks out",
                expected_execution="alert fires",
            ),
            verified=True,
        )
        ok, reason = agent._xss_stored_confirmation_gate(result)
        assert ok is False
        assert "read-back" in reason

    def test_gate_passes_a_genuine_confirmation(self) -> None:
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=6,
            read_back_url="http://example.com/guestbook",
            landing_context="html_body",
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="Structural characters survive the store.",
                expected_execution="Script tag executes on render.",
            ),
            verified=True,
        )
        ok, reason = agent._xss_stored_confirmation_gate(result)
        assert ok is True
        assert reason == "confirmed"
