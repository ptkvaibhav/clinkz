"""Unit tests for the adaptive XSS-reflected methodology phases.

Each phase is exercised in isolation with mocked HTTP and LLM:

    Phase 1 (reflection mapping)        — synthetic HTML with each context
    Phase 2 (character fingerprinting)  — scripted HTTP responder shaping
                                           prefix/middle/suffix slices
    Phase 3 (payload synthesis)         — LLM JSON parsing + fallback table
    Phase 4 (encoding bypass)           — LLM JSON parsing + fallback table
    Phase 5 (verification)              — landing-context classification

Plus an end-to-end run that drives all six phases through one ``page``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
    _ReflectionMapper,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    CharacterMap,
    FilterBehavior,
    ReflectionContext,
    ReflectionPoint,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

# NOTE: ``pytest.mark.asyncio`` is applied per-test (only on ``async def``
# tests) rather than module-wide — applying it to sync Phase-1 mapper tests
# emits a PytestWarning under pytest-asyncio.


SCOPE = EngagementScope(
    name="methodology-xss-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------


class _ScriptedLLM(LLMClient):
    """LLM client whose ``generate_text`` returns answers in queue order.

    Each Phase 3 / Phase 4 prompt consumes one queued answer. Tests assert
    on ``prompts`` to verify the right inputs reached the LLM.
    """

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
        engagement_id="methodology-xss-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    # Pin the methodology LLM to the mocked one so we don't get fallbacks
    # to a real provider during tests.
    agent._methodology_llm = agent.llm
    return agent


# ===========================================================================
# Phase 1 — Reflection mapping
# ===========================================================================


class TestPhase1ReflectionMapping:
    """The reflection mapper must classify each context type correctly."""

    def test_html_body_reflection(self) -> None:
        body = "<html><body><p>Hello CLNKZabcdef!</p></body></html>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.HTML_BODY

    def test_attribute_value_reflection(self) -> None:
        body = '<html><body><a href="?q=CLNKZabcdef">link</a></body></html>'
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        # Note: the URL value-attribute classifies as URL (not HTML_ATTRIBUTE_VALUE)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.URL

    def test_generic_attribute_value(self) -> None:
        body = '<input type="text" value="CLNKZabcdef">'
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.HTML_ATTRIBUTE_VALUE

    def test_event_handler_attribute_classifies_as_js_code(self) -> None:
        body = "<button onclick=\"doThing('CLNKZabcdef')\">x</button>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.JS_CODE

    def test_js_string_single(self) -> None:
        body = "<script>var x = 'CLNKZabcdef';</script>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.JS_STRING_SINGLE

    def test_js_string_double(self) -> None:
        body = '<script>var x = "CLNKZabcdef";</script>'
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.JS_STRING_DOUBLE

    def test_js_code_context(self) -> None:
        body = "<script>alert(CLNKZabcdef);</script>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.JS_CODE

    def test_html_comment_reflection(self) -> None:
        body = "<html><!-- CLNKZabcdef --></html>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.COMMENT

    def test_no_reflection_returns_empty(self) -> None:
        agent = _make_agent()
        body = "<html><body>nothing here</body></html>"
        assert agent._xss_phase1_reflection_mapping("CLNKZabcdef", body) == []

    def test_multiple_reflections(self) -> None:
        body = "<html><body><p>CLNKZabcdef</p><script>var x = 'CLNKZabcdef';</script></body></html>"
        agent = _make_agent()
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        contexts = sorted(p.context.value for p in points)
        assert contexts == sorted(
            [ReflectionContext.HTML_BODY.value, ReflectionContext.JS_STRING_SINGLE.value]
        )

    def test_mapper_class_directly_handles_attribute_name(self) -> None:
        # ``handle_starttag`` records token-in-attr-name as HTML_ATTRIBUTE_NAME.
        mapper = _ReflectionMapper("CLNKZabcdef")
        mapper.feed('<input CLNKZabcdef="value">')
        mapper.close()
        # The mapper records the attr-name occurrence, plus may record the
        # tag itself if the parser interprets the body. Verify at least
        # one HTML_ATTRIBUTE_NAME context fired.
        assert any(p.context == ReflectionContext.HTML_ATTRIBUTE_NAME for p in mapper.points)


# ===========================================================================
# Phase 2 — Character fingerprinting
# ===========================================================================


def _make_fingerprint_responder(rules: dict[str, str]) -> Any:
    """Build an async _http_get stub that shapes per-character behavior.

    *rules* maps a single character to one of: ``"survived"``,
    ``"stripped"``, ``"html_encoded"``, ``"url_encoded"``,
    ``"backslash_escaped"``, ``"replaced"``, ``"server_error"``,
    ``"blocked"``. The stub reads the raw probe value out of *params*
    (Phase 2 always sends one ``{param: <prefix><c><suffix>}``) and
    constructs a response body that places *middle* between the two
    tokens, where *middle* is shaped by the per-character rule.
    """
    import html as html_lib
    from urllib.parse import quote

    async def _stub(url: str, params: dict[str, str]) -> _HTTPResponse:
        # Pull the single probe value straight from params — _http_get
        # is mocked, so we never see the URL-encoded form.
        if not params:
            return _HTTPResponse(status=200, body="")
        decoded = next(iter(params.values()))
        # Probe shape: <prefix><c><suffix> where each token is 11 chars
        # ("CLNKZ" + 6 random alnum). Anything else is a non-fingerprint
        # request, echo it through.
        if not decoded.startswith("CLNKZ") or len(decoded) < 23:
            return _HTTPResponse(status=200, body=decoded)
        prefix = decoded[:11]
        suffix = decoded[-11:]
        char = decoded[11:-11]
        rule = rules.get(char, "survived")
        if rule == "server_error":
            return _HTTPResponse(status=500, body="server error")
        if rule == "blocked":
            # Blocked: tokens stripped from body so the prefix isn't found.
            return _HTTPResponse(status=403, body="forbidden")
        if rule == "stripped":
            middle = ""
        elif rule == "html_encoded":
            middle = html_lib.escape(char, quote=True)
            if middle == char:
                # html.escape leaves neutral chars alone — switch to numeric.
                middle = f"&#{ord(char)};"
        elif rule == "url_encoded":
            middle = quote(char, safe="")
            if middle == char:
                middle = f"%{ord(char):02X}"
        elif rule == "backslash_escaped":
            middle = "\\" + char
        elif rule == "replaced":
            middle = "_"
        else:
            middle = char
        body = f"<p>{prefix}{middle}{suffix}</p>"
        return _HTTPResponse(status=200, body=body)

    return _stub


class TestPhase2CharacterFingerprint:
    """Each filter behavior must be classified correctly."""

    async def test_survived_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "survived"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.SURVIVED

    async def test_stripped_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "stripped"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.STRIPPED

    async def test_html_encoded_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "html_encoded"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.HTML_ENCODED

    async def test_url_encoded_classification(self) -> None:
        agent = _make_agent()
        # URL-encoding < gives %3C, which is distinguishable from html-encoded.
        agent._http_get = _make_fingerprint_responder({"<": "url_encoded"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.URL_ENCODED

    async def test_backslash_escaped_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"'": "backslash_escaped"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("'") == FilterBehavior.BACKSLASH_ESCAPED

    async def test_replaced_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "replaced"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.REPLACED

    async def test_server_error_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "server_error"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.SERVER_ERROR

    async def test_blocked_classification(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({"<": "blocked"})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        assert char_map.per_char.get("<") == FilterBehavior.BLOCKED

    async def test_probe_summary_populated(self) -> None:
        agent = _make_agent()
        agent._http_get = _make_fingerprint_responder({})  # type: ignore[method-assign]
        char_map = await agent._xss_phase2_character_fingerprint("http://x/q", "q")
        # All chars survive by default; summary should mention several of them.
        assert "survived" in char_map.probe_summary
        assert len(char_map.per_char) >= 16  # at least the structural batch


# ===========================================================================
# Phase 3 — Payload synthesis
# ===========================================================================


class TestPhase3PayloadSynthesis:
    """LLM JSON parsing + deterministic fallback for missing/malformed responses."""

    async def test_llm_json_parsed_into_synthesized_payload(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "<svg/onload=alert(1)>", '
                '"rationale": "svg vector", '
                '"expected_execution": "alert"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(
            per_char={"<": FilterBehavior.SURVIVED, ">": FilterBehavior.SURVIVED}
        )
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>...</p>",
        )
        result = await agent._xss_phase3_synthesize_payload(reflection, char_map)
        assert result is not None
        assert result.payload == "<svg/onload=alert(1)>"
        assert result.rationale == "svg vector"
        assert "Reflection context" in llm.prompts[0]
        assert "html_body" in llm.prompts[0]

    async def test_llm_returns_empty_falls_back_for_html_body(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(
            per_char={"<": FilterBehavior.SURVIVED, ">": FilterBehavior.SURVIVED}
        )
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>x</p>",
        )
        result = await agent._xss_phase3_synthesize_payload(reflection, char_map)
        assert result is not None
        assert "<script>" in result.payload

    async def test_fallback_attribute_value_double_quote(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(per_char={'"': FilterBehavior.SURVIVED})
        reflection = ReflectionPoint(
            location="<input>[value]",
            context=ReflectionContext.HTML_ATTRIBUTE_VALUE,
            surrounding_snippet='<input value="x">',
        )
        result = await agent._xss_phase3_synthesize_payload(reflection, char_map)
        assert result is not None
        assert '"' in result.payload
        assert "onmouseover" in result.payload

    async def test_no_payload_when_critical_chars_filtered(self) -> None:
        # HTML body but < is stripped — fallback declines to synthesize.
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(per_char={"<": FilterBehavior.STRIPPED})
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>x</p>",
        )
        result = await agent._xss_phase3_synthesize_payload(reflection, char_map)
        assert result is None


# ===========================================================================
# Phase 4 — Encoding bypass
# ===========================================================================


class TestPhase4EncodingBypass:
    async def test_llm_attempts_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=['{"attempts": ["<ScRiPt>alert(1)</ScRiPt>", "<img src=x onerror=alert(1)>"]}']
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(probe_summary="< stripped")
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>x</p>",
        )
        attempts = await agent._xss_phase4_encoding_bypass(
            reflection, char_map, "<script>alert(1)</script>"
        )
        assert attempts[0] == "<ScRiPt>alert(1)</ScRiPt>"
        assert "<img src=x onerror=alert(1)>" in attempts

    async def test_fallback_attempts_when_llm_silent(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap(probe_summary="")
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>x</p>",
        )
        attempts = await agent._xss_phase4_encoding_bypass(
            reflection, char_map, "<script>alert(1)</script>"
        )
        assert len(attempts) >= 1
        assert len(attempts) <= 5

    async def test_attempts_capped_and_deduped(self) -> None:
        # LLM repeats the same payload — dedup must keep one copy.
        llm = _ScriptedLLM(answers=['{"attempts": ["a", "a", "b", "b", "c", "d", "e", "f"]}'])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        char_map = CharacterMap()
        reflection = ReflectionPoint(
            location="body[0]",
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet="<p>x</p>",
        )
        attempts = await agent._xss_phase4_encoding_bypass(reflection, char_map, "x")
        assert len(attempts) <= 5
        assert len(set(attempts)) == len(attempts)


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    async def test_payload_reflected_literally_verified(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="<html><body>Hi <script>alert(1)</script>!</body></html>",
            )
        )
        verified, ctx, _ = await agent._xss_phase5_verify(
            "http://x/q", "q", "<script>alert(1)</script>"
        )
        assert verified is True
        # Landing context should be html_body (we're between </body>'s siblings).
        assert ctx in {"html_body", "tag", "script"}

    async def test_payload_not_reflected_rejected(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html><body>safe</body></html>")
        )
        verified, ctx, _ = await agent._xss_phase5_verify(
            "http://x/q", "q", "<script>alert(1)</script>"
        )
        assert verified is False
        assert "absent" in ctx

    async def test_payload_only_in_comment_rejected(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="<html><!-- echo: <script>alert(1)</script> --></html>",
            )
        )
        verified, ctx, _ = await agent._xss_phase5_verify(
            "http://x/q", "q", "<script>alert(1)</script>"
        )
        assert verified is False
        assert "comment" in ctx

    async def test_payload_inside_attribute_breakout_verified(self) -> None:
        agent = _make_agent()
        # Attribute breakout — the literal quote+onmouseover survives.
        body = '<html><input value="" onmouseover=alert(1) x=""></html>'
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        verified, _ctx, _ = await agent._xss_phase5_verify(
            "http://x/q", "q", '" onmouseover=alert(1) x="'
        )
        assert verified is True


# ===========================================================================
# Integration — full _test_xss_reflected with mocked HTTP + LLM
# ===========================================================================


class TestXSSReflectedIntegration:
    async def test_simple_reflected_xss_detected_with_fallback_llm(self) -> None:
        """End-to-end: < and > survive, payload reflects, finding emitted."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))  # LLM silent → fallback
        agent._methodology_llm = agent.llm

        async def stub_http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            # Echo the parameter value verbatim into HTML body. The stub
            # replaces ``_http_get`` directly, so ``params`` is the raw
            # dict — no URL parsing needed.
            value = next(iter(params.values())) if params else ""
            return _HTTPResponse(
                status=200,
                body=f"<html><body><p>Hello {value}!</p></body></html>",
            )

        agent._http_get = stub_http_get  # type: ignore[method-assign]

        page = PageAnalysis(
            url="http://example.com/echo",
            body="",
            status=200,
            input_params=["q"],
        )
        findings = await agent._test_xss_reflected(page)
        assert len(findings) == 1
        assert "xss" in findings[0].title.lower()
        assert findings[0].severity.value == "high"
        # Methodology evidence: char map + reflection contexts attached.
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=" in joined
        assert "reflection_contexts=" in joined
        assert "character_map=" in joined

    async def test_no_finding_when_param_not_reflected(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>safe</html>")
        )
        page = PageAnalysis(
            url="http://example.com/echo",
            body="",
            status=200,
            input_params=["q"],
        )
        findings = await agent._test_xss_reflected(page)
        assert findings == []
