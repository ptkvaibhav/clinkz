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
    MethodologyResult,
    ReflectionContext,
    ReflectionPoint,
    SynthesizedPayload,
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

    async def test_verifying_response_threaded_into_evidence(self) -> None:
        """BUG 1: the actual verifying response (with the reflected payload) is
        threaded into the finding's evidence — never "(response unavailable)" —
        so the post-run FP-suppression pass does not flag a genuine reflected XSS.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm

        async def stub_http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            value = next(iter(params.values())) if params else ""
            return _HTTPResponse(
                status=200,
                body=f"<html><body><p>Hello {value}!</p></body></html>",
            )

        agent._http_get = stub_http_get  # type: ignore[method-assign]
        page = PageAnalysis(url="http://example.com/echo", body="", status=200, input_params=["q"])
        findings = await agent._test_xss_reflected(page)
        assert len(findings) == 1
        response_line = next(e for e in findings[0].evidence if e.startswith("Response:"))
        assert "(response unavailable)" not in response_line
        # The real reflecting body slice is shown (the payload landed in "Hello …!").
        assert "Hello" in response_line

    def test_emit_refuses_blind_verified_finding(self) -> None:
        """BUG 1 honesty guard: a result marked verified but with no captured
        verifying response emits nothing (verification ran blind) rather than
        shipping a placeholder as confirmed evidence."""
        agent = _make_agent()
        result = MethodologyResult(
            phases_completed=6,
            verified=True,
            verification_strength="verified",
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="r",
                expected_execution="e",
            ),
            verifying_response="",  # never captured
        )
        assert agent._xss_phase6_emit("http://example.com/echo", "q", result) is None


# ===========================================================================
# Fragment URL preservation through the request layer
# ===========================================================================


class TestFragmentURLPreservation:
    """``_build_request_url`` must preserve fragments and merge SPA params."""

    def test_url_with_fragment_round_trips_intact_when_no_params(self) -> None:
        agent = _make_agent()
        url = "http://example.com/#/search?q=test"
        assert agent._build_request_url(url, {}) == url

    def test_plain_url_with_fragment_preserves_fragment(self) -> None:
        agent = _make_agent()
        url = "http://example.com/page#section"
        assert agent._build_request_url(url, {}) == url

    def test_spa_fragment_param_overrides_in_fragment_query(self) -> None:
        agent = _make_agent()
        url = "http://example.com/#/search?q=test"
        out = agent._build_request_url(url, {"q": "<probe>"})
        # Fragment must still be present and updated; server query stays empty.
        assert "#/search?" in out
        assert "q=" in out
        assert "?q=" not in out.split("#")[0]  # nothing leaked to server query
        assert "<probe>" in out or "%3Cprobe%3E" in out

    def test_extra_param_falls_through_to_server_query(self) -> None:
        agent = _make_agent()
        url = "http://example.com/#/search?q=test"
        out = agent._build_request_url(url, {"q": "X", "extra": "Y"})
        # ``q`` lands in the fragment route (route key already there);
        # ``extra`` falls through to the server-side query string.
        assert "#/search?" in out
        # Server-side portion (before #) carries extra=Y.
        server_part = out.split("#")[0]
        assert "extra=Y" in server_part
        # Fragment portion carries q=X.
        frag_part = out.split("#")[1]
        assert "q=X" in frag_part

    def test_url_param_replaces_existing_same_named_server_query(self) -> None:
        # A probe for a param already present in the server query REPLACES its
        # value in place — never appends a duplicate key (``?name=test&name=``),
        # whose effective value is server-dependent and which surfaced as phantom
        # IDOR findings (probe compared against an ambiguously-keyed baseline).
        agent = _make_agent()
        url = "http://example.com/vuln/?name=test"
        out = agent._build_request_url(url, {"name": "<probe>"})
        assert out.startswith("http://example.com/vuln/?name=")
        assert "name=test" not in out  # original value replaced, not duplicated
        assert out.count("name=") == 1  # exactly one key, no doubled query string
        assert "name=%3Cprobe%3E" in out or "name=<probe>" in out

    def test_other_server_query_params_preserved_on_replace(self) -> None:
        # Replacing the probed key must leave sibling query params intact.
        agent = _make_agent()
        url = "http://example.com/vuln/?id=1&Submit=Submit"
        out = agent._build_request_url(url, {"id": "2"})
        assert "Submit=Submit" in out
        assert out.count("id=") == 1
        assert "id=2" in out

    async def test_fragment_url_reaches_http_client_intact(self) -> None:
        """End-to-end: passing a fragment URL through ``_http_get`` keeps it."""
        from clinkz.tools import http_client

        captured: dict[str, Any] = {}
        original_validate = http_client.HTTPClientTool.validate_input

        def capture_validate(self: Any, args: dict[str, Any]) -> dict[str, Any]:
            captured["url"] = args.get("url", "")
            # Stop the request from actually going out — return validated
            # args, then ``execute`` will be patched to short-circuit.
            return original_validate(self, args)

        async def fake_execute(self: Any, args: dict[str, Any]) -> str:
            import json as _json

            return _json.dumps({"status_code": 200, "response_body": "ok"})

        agent = _make_agent()
        original_execute = http_client.HTTPClientTool.execute
        http_client.HTTPClientTool.validate_input = capture_validate  # type: ignore[method-assign]
        http_client.HTTPClientTool.execute = fake_execute  # type: ignore[method-assign]
        try:
            url = "http://example.com/#/search?q=test"
            await agent._http_get(url, {})
            assert "#/search?q=test" in captured["url"]
        finally:
            # BOTH patches must be undone. Restoring only validate_input left a
            # permanently stubbed ``execute`` on the class for the rest of the
            # session, so any later test exercising the real HTTP chokepoint
            # silently ran against this stub instead.
            http_client.HTTPClientTool.validate_input = original_validate  # type: ignore[method-assign]
            http_client.HTTPClientTool.execute = original_execute  # type: ignore[method-assign]


# ===========================================================================
# SPA shell detection
# ===========================================================================


class TestSPAShellDetection:
    """``_is_spa_shell`` must distinguish SPA bootstraps from plain HTML."""

    def test_angular_shell_detected(self) -> None:
        agent = _make_agent()
        body = (
            "<!doctype html><html><head><title>App</title></head>"
            "<body><app-root></app-root>"
            '<script src="runtime.abcd1234.js"></script>'
            '<script src="main.abcd1234.js"></script>'
            "</body></html>"
        )
        assert agent._is_spa_shell(body) is True

    def test_react_shell_detected(self) -> None:
        agent = _make_agent()
        body = (
            "<!doctype html><html><body>"
            '<div id="root"></div>'
            '<script src="/static/js/main.abc.js"></script>'
            "</body></html>"
        )
        assert agent._is_spa_shell(body) is True

    def test_vue_shell_detected(self) -> None:
        agent = _make_agent()
        body = (
            "<!doctype html><html><body>"
            '<div id="app"></div>'
            '<script src="/assets/index-9f8e7d.js"></script>'
            "</body></html>"
        )
        assert agent._is_spa_shell(body) is True

    def test_plain_html_not_spa(self) -> None:
        agent = _make_agent()
        body = (
            "<html><body>"
            "<h1>Welcome</h1><p>Some content here.</p>"
            "<form><input name=q></form>"
            "</body></html>"
        )
        assert agent._is_spa_shell(body) is False

    def test_html_with_jquery_not_spa(self) -> None:
        # Plain page with a jQuery script tag — not an SPA shell.
        agent = _make_agent()
        body = (
            "<html><body>"
            "<h1>Hi</h1><p>regular content</p>"
            '<script src="/static/jquery.min.js"></script>'
            "</body></html>"
        )
        assert agent._is_spa_shell(body) is False

    def test_empty_body_not_spa(self) -> None:
        agent = _make_agent()
        assert agent._is_spa_shell("") is False


# ===========================================================================
# Phase 1 — DOM-context (JS_DOM) classification
# ===========================================================================


class TestPhase1JSDOMClassification:
    """Phase 1 must classify SPA + fragment route param as ``JS_DOM``."""

    def test_spa_shell_with_fragment_param_classifies_as_js_dom(self) -> None:
        agent = _make_agent()
        body = (
            "<!doctype html><html><body>"
            "<app-root></app-root>"
            '<script src="main.abc.js"></script>'
            "</body></html>"
        )
        # Canary not in body — server didn't reflect, but the fragment
        # carries the param being tested. JS_DOM context expected.
        url = "http://example.com/#/search?q=test"
        points = agent._xss_phase1_reflection_mapping(
            "CLNKZabcdef", body, request_url=url, param="q"
        )
        contexts = [p.context for p in points]
        assert ReflectionContext.JS_DOM in contexts

    def test_plain_html_with_fragment_param_does_not_classify_dom(self) -> None:
        # Same fragment URL but server-rendered page — no JS_DOM point.
        agent = _make_agent()
        body = "<html><body><h1>Welcome</h1><p>regular page</p></body></html>"
        url = "http://example.com/#/search?q=test"
        points = agent._xss_phase1_reflection_mapping(
            "CLNKZabcdef", body, request_url=url, param="q"
        )
        assert all(p.context != ReflectionContext.JS_DOM for p in points)

    def test_spa_shell_without_fragment_param_does_not_classify_dom(self) -> None:
        # SPA shell but the param being probed isn't in the fragment route.
        agent = _make_agent()
        body = '<html><body><app-root></app-root><script src="main.abc.js"></script></body></html>'
        url = "http://example.com/page"  # no fragment
        points = agent._xss_phase1_reflection_mapping(
            "CLNKZabcdef", body, request_url=url, param="q"
        )
        assert all(p.context != ReflectionContext.JS_DOM for p in points)

    def test_legacy_signature_still_works(self) -> None:
        # Phase 1 used to take only (canary, body); existing callers must
        # keep working unchanged — the SPA branch is opt-in via kwargs.
        agent = _make_agent()
        body = "<html><body><p>CLNKZabcdef</p></body></html>"
        points = agent._xss_phase1_reflection_mapping("CLNKZabcdef", body)
        assert len(points) == 1
        assert points[0].context == ReflectionContext.HTML_BODY


# ===========================================================================
# JS_DOM end-to-end methodology
# ===========================================================================


class TestXSSReflectedJSDOMIntegration:
    """End-to-end: SPA shell + fragment route + reachable sink → an unproven LEAD.

    This used to assert a high-severity CONFIRMED finding carrying
    ``strength=likely`` in its own evidence, which is the DOM-XSS phantom
    re-entering through the reflected class: what is actually witnessed is an
    SPA shell plus a sink NAME found by static analysis of a bundle, and nothing
    was observed executing. ``_dom_xss_dispatch_result`` demotes exactly that
    evidence; the reflected class now takes the same exit.
    """

    async def test_spa_search_with_innerhtml_sink_records_a_lead_not_a_finding(self) -> None:
        """Juice-Shop-style flow: fragment search route, bundle uses innerHTML."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))  # LLM silent → fallback
        agent._methodology_llm = agent.llm

        spa_shell = (
            "<!doctype html><html><head><title>Shop</title></head>"
            "<body><app-root></app-root>"
            '<script src="runtime.abc.js"></script>'
            '<script src="main.def.js"></script>'
            "</body></html>"
        )
        bundle_js = (
            "function consume(){"
            "  var q = location.hash.split('?q=')[1];"
            "  document.getElementById('out').innerHTML = q;"
            "}"
        )

        async def stub_http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            # Bundle URLs return the fake bundle JS; everything else
            # returns the SPA shell so phase-5 sees an SPA on the
            # fragment payload request.
            if url.endswith(".js"):
                return _HTTPResponse(status=200, body=bundle_js)
            return _HTTPResponse(status=200, body=spa_shell)

        agent._http_get = stub_http_get  # type: ignore[method-assign]

        page = PageAnalysis(
            url="http://example.com/#/search?q=test",
            body=spa_shell,
            status=200,
            input_params=["q"],
        )
        findings = await agent._test_xss_reflected(page)
        assert findings == []

        leads = agent._unproven_exploit_leads
        assert len(leads) == 1
        lead = leads[0]
        assert lead.why_unconfirmed == "execution_not_witnessed_requires_client_side_oracle"
        assert "q" in lead.parameter
        # The reachability evidence is preserved verbatim — demoting the claim
        # must not discard what was actually seen.
        assert "strength=likely" in lead.raw_observation
        assert "JavaScript engine" in lead.missing_observation

    async def test_spa_search_without_sinks_does_not_verify(self) -> None:
        """SPA shell + fragment but bundle has no dangerous sinks → no finding."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm

        spa_shell = (
            "<!doctype html><html><body>"
            '<div id="root"></div>'
            '<script src="main.abc.js"></script>'
            "</body></html>"
        )
        # Bundle reads the source but routes to a safe textContent sink.
        safe_bundle = (
            "function show(){"
            "  var q = location.hash;"
            "  document.getElementById('o').textContent = q;"
            "}"
        )

        async def stub_http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            if url.endswith(".js"):
                return _HTTPResponse(status=200, body=safe_bundle)
            return _HTTPResponse(status=200, body=spa_shell)

        agent._http_get = stub_http_get  # type: ignore[method-assign]

        page = PageAnalysis(
            url="http://example.com/#/search?q=test",
            body=spa_shell,
            status=200,
            input_params=["q"],
        )
        findings = await agent._test_xss_reflected(page)
        assert findings == []
