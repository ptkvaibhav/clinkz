"""Unit tests for the adaptive JS-attacks methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — form + script gate
    Phase 2 (observation)  — hidden-field / JS-write / validation collection
    Phase 3 (analysis)     — deterministic classification (no LLM on this path), then
                             the DETERMINISTIC forge-and-accept confirmation
    Phase 4 (finding)      — emission only for a confirmed forgery

Plus the replayable-expression grammar the confirmation is built on, and
integration tests that drive ``_test_javascript_attacks`` end-to-end.

The load-bearing contract here (G16): observing that a hidden field is
JS-controlled is REACHABILITY. A finding requires the server to have accepted a
value we rebuilt from the page's own chain while rejecting an equal-shaped
control. Everything short of that is an ``UnprovenExploitLead``.
"""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
    _js_bind_leaves,
    _js_candidate_input_values,
    _js_control_value,
    _js_eval_expression,
    _js_expression_fields,
    _js_parse_value_expression,
    _js_render_expression,
    _js_resolve_names,
    _JSValueNode,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED
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

_WHY_UNCONFIRMED = "client_side_control_described_server_acceptance_not_witnessed"


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
        engagement_id="methodology-js-attacks-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _rot13(value: str) -> str:
    out = []
    for char in value:
        if "a" <= char <= "z":
            out.append(chr((ord(char) - 97 + 13) % 26 + 97))
        elif "A" <= char <= "Z":
            out.append(chr((ord(char) - 65 + 13) % 26 + 65))
        else:
            out.append(char)
    return "".join(out)


# ===========================================================================
# The replayable-expression grammar
# ===========================================================================


class TestReplayableGrammar:
    def test_parses_nested_standard_transforms(self) -> None:
        node = _js_parse_value_expression("md5(rot13(phrase))")
        assert node is not None
        assert node.kind == "call" and node.value == "md5"
        assert node.args[0].kind == "call" and node.args[0].value == "rot13"
        assert node.args[0].args[0] == _JSValueNode(kind="name", value="phrase")

    def test_parses_get_element_by_id_value_read(self) -> None:
        node = _js_parse_value_expression('document.getElementById("phrase").value')
        assert node == _JSValueNode(kind="element", value="phrase")

    def test_parses_concatenation_and_literals(self) -> None:
        node = _js_parse_value_expression("'pre-' + btoa(user) + \"-post\"")
        assert node is not None and node.kind == "concat"
        assert node.args[0] == _JSValueNode(kind="literal", value="pre-")
        assert node.args[2] == _JSValueNode(kind="literal", value="-post")

    def test_parses_zero_argument_string_method(self) -> None:
        node = _js_parse_value_expression("md5(name).toUpperCase()")
        assert node is not None
        assert node.kind == "call" and node.value == "touppercase"

    @pytest.mark.parametrize(
        "expr",
        [
            "Date.now()",
            "Math.random()",
            "computeHash(time)",  # a page-defined helper we never saw
            "a * 3",
            "window.secret",
            "md5(a, b)",
            # Malformed escapes a browser tolerates but unicode_escape rejects:
            # the TARGET writes these, so they must be a parse failure and never
            # an exception escaping the methodology.
            r'md5("\xZZ")',
            r'md5("\u12")',
        ],
    )
    def test_rejects_expressions_outside_the_grammar(self, expr: str) -> None:
        # Unreplayable is the honest outcome — no forgery, so no confirmation.
        assert _js_parse_value_expression(expr) is None

    def test_resolves_a_local_variable_to_the_field_it_reads(self) -> None:
        script = 'var phrase = document.getElementById("phrase").value;\nx = md5(phrase);'
        node = _js_parse_value_expression("md5(rot13(phrase))")
        assert node is not None
        resolved = _js_resolve_names(node, script)
        leaf = resolved.args[0].args[0]
        assert leaf == _JSValueNode(kind="element", value="phrase")

    def test_evaluates_the_chain_the_way_the_browser_would(self) -> None:
        node = _js_parse_value_expression("md5(rot13(phrase))")
        assert node is not None
        bound = _js_bind_leaves(node, lambda leaf: leaf.value)
        assert bound is not None
        assert _js_expression_fields(bound) == ["phrase"]
        expected = hashlib.md5(_rot13("success").encode(), usedforsecurity=False).hexdigest()
        assert _js_eval_expression(bound, {"phrase": "success"}) == expected

    def test_binding_fails_when_a_leaf_is_not_a_form_field(self) -> None:
        node = _js_parse_value_expression("md5(nonce)")
        assert node is not None
        assert _js_bind_leaves(node, lambda _leaf: "") is None

    def test_render_is_replayable_by_a_reader(self) -> None:
        node = _js_parse_value_expression("md5(rot13(phrase))")
        assert node is not None
        bound = _js_bind_leaves(node, lambda leaf: leaf.value)
        assert bound is not None
        assert _js_render_expression(bound) == "md5(rot13(<field:phrase>))"


class TestControlValue:
    def test_control_matches_the_forged_shape_but_never_its_value(self) -> None:
        forged = hashlib.md5(b"x", usedforsecurity=False).hexdigest()
        for _ in range(20):
            control = _js_control_value(forged)
            # Same length AND alphabet: a server rejecting it cannot be
            # rejecting it for its shape.
            assert len(control) == len(forged)
            assert all(char in "0123456789abcdef" for char in control)
            assert control != forged

    def test_control_preserves_the_case_class_of_the_forged_value(self) -> None:
        # An uppercase-hex digest and a lowercase-hex digest are different
        # SHAPES. A control drawn from the wrong case would be rejected by a
        # format check rather than by the token check, which would let a
        # format-validating server look like an accepting one.
        upper = "ABCDEF0123456789ABCDEF0123456789"
        for _ in range(20):
            control = _js_control_value(upper)
            assert len(control) == len(upper)
            assert all(char in "0123456789ABCDEF" for char in control)

    def test_non_hex_forged_value_keeps_its_length(self) -> None:
        control = _js_control_value("pre-ZZZZ-post")
        assert len(control) == len("pre-ZZZZ-post")
        assert control != "pre-ZZZZ-post"

    def test_degenerate_value_still_yields_a_different_control(self) -> None:
        for value in ("a", "0", "aaaa"):
            assert _js_control_value(value) != value
            assert len(_js_control_value(value)) == len(value)


class TestCandidateInputDiscovery:
    def test_candidates_come_from_the_app_never_from_a_constant(self) -> None:
        body = (
            '<p>Submit the word "success" to win.</p>'
            '<form><input name="phrase" value="ChangeMe"></form>'
            "<script>if (other.value === 'admin') {}</script>"
        )
        candidates = _js_candidate_input_values(body, "ChangeMe")
        assert candidates[0] == "ChangeMe"  # the field's own default first
        assert "admin" in candidates  # a literal the page's JS compares against
        assert "success" in candidates  # a quoted word in the visible text

    def test_candidate_list_is_bounded(self) -> None:
        body = " ".join(f'<p>"word{i}"</p>' for i in range(40))
        assert len(_js_candidate_input_values(body, "default")) <= 6


# ===========================================================================
# Phase 3 — Analysis (deterministic; the LLM is not on this path)
# ===========================================================================


class TestPhase3DeterministicAnalysis:
    def test_hidden_field_write_without_token_name(self) -> None:
        agent = _make_agent()
        controlled = [("submit_btn", "document.getElementById('submit_btn').value = 'go'")]
        pattern, severity, _r, should_bypass = agent._deterministic_js_attacks_analysis(
            controlled, ["submit_btn"], []
        )
        assert pattern == JSAttackPatternType.HIDDEN_FIELD_WRITE
        assert severity == "medium"
        assert should_bypass is True  # string literal — replayable

    def test_token_named_field_classified_as_token_computation(self) -> None:
        agent = _make_agent()
        controlled = [("csrf_token", "document.getElementById('csrf_token').value = 'abc'")]
        pattern, _sev, _r, _bp = agent._deterministic_js_attacks_analysis(
            controlled, ["csrf_token"], []
        )
        assert pattern == JSAttackPatternType.TOKEN_COMPUTATION

    def test_validation_only_classified_as_client_validation(self) -> None:
        agent = _make_agent()
        validation_hits = ["if (input.value === 'expected') { ... }"]
        pattern, _sev, _r, should_bypass = agent._deterministic_js_attacks_analysis(
            [], [], validation_hits
        )
        assert pattern == JSAttackPatternType.CLIENT_VALIDATION
        assert should_bypass is False

    def test_non_literal_write_not_bypassable(self) -> None:
        agent = _make_agent()
        # Concatenation / function call — not a string literal.
        controlled = [("token", "document.getElementById('token').value = computeHash(time)")]
        _p, _s, _r, should_bypass = agent._deterministic_js_attacks_analysis(
            controlled, ["token"], []
        )
        assert should_bypass is False

    def test_no_evidence_classified_as_none(self) -> None:
        agent = _make_agent()
        pattern, _sev, _r, _bp = agent._deterministic_js_attacks_analysis([], [], [])
        assert pattern == JSAttackPatternType.NONE


# ===========================================================================
# Phase 3 — the LLM is not consulted
# ===========================================================================


class TestPhase3NoLLM:
    @pytest.mark.asyncio
    async def test_the_llm_is_never_consulted(self) -> None:
        """Asserted on the CALL, not on the answer.

        Three of this checkpoint's four outputs are inert on the emitting path
        (severity is overwritten to ``high`` at confirmation, the bypass flag
        gates nothing, the rationale is reconciled against the outcome), so the
        5/57 recorded classification flips changed no deliverable. The fourth
        was live: a ``none`` verdict skips the form, which is a suppression path.
        Only the absence of the call closes it.
        """
        llm = _ScriptedLLM(
            answers=[
                '{"pattern_type": "none", "severity": "high", '
                '"rationale": "JS computes token", "should_attempt_bypass": true}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        controlled = [("csrf", "elem.value = 'literal'")]

        pattern, severity, rationale, bp = await agent._js_attacks_phase3_analyze(
            controlled, ["csrf"], []
        )

        assert llm.prompts == []
        assert llm.answers, "the scripted answer must still be unconsumed"
        # The scripted "none" would have suppressed the class. The deterministic
        # verdict stands instead.
        assert pattern == JSAttackPatternType.TOKEN_COMPUTATION
        assert severity == "medium"
        assert "computes" not in rationale
        assert bp is True  # string literal — the deterministic replayability read

    @pytest.mark.asyncio
    async def test_deterministic_classification_is_the_verdict(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        controlled = [("name", "elem.value = 'val'")]
        pattern, _sev, _r, _bp = await agent._js_attacks_phase3_analyze(controlled, ["name"], [])
        assert pattern == JSAttackPatternType.HIDDEN_FIELD_WRITE


# ===========================================================================
# Phase 4 — Finding emission
# ===========================================================================


class TestPhase4Emission:
    def _confirmed_result(self) -> JSAttacksMethodologyResult:
        return JSAttacksMethodologyResult(
            phases_completed=4,
            forms_analyzed=1,
            hidden_fields_set_by_js=["token"],
            pattern_type=JSAttackPatternType.TOKEN_COMPUTATION,
            form_action="http://example.com/submit",
            form_method="POST",
            severity_inferred="high",
            rationale="JS computes the token with md5(rot13(phrase))",
            forge_attempted=True,
            forge_confirmed=True,
            forge_field="token",
            forge_chain="token = md5(rot13(<field:phrase>))",
            forge_inputs={"phrase": "success"},
            forged_value="38581812b435834ebf84ebcc2c6424d6",
            control_values=["aaaa", "bbbb"],
            control_stable=True,
            forged_stable=True,
            control_excerpt="<p>Invalid token.</p>",
            forged_excerpt="<p>Well done!</p>",
        )

    def test_confirmed_forgery_emits_high_with_the_measurement(self) -> None:
        agent = _make_agent()
        form = {"method": "POST", "action": "/submit", "fields": []}
        finding = agent._js_attacks_phase4_emit(
            "http://example.com/submit", form, self._confirmed_result()
        )
        assert finding.severity.value == "high"
        joined = " ".join(finding.evidence)
        assert "forge_confirmed=True" in joined
        assert "control_stable=True" in joined
        assert "38581812b435834ebf84ebcc2c6424d6" in joined
        assert "Invalid token." in joined and "Well done!" in joined

    def test_emitted_evidence_does_not_restate_its_own_rationale(self) -> None:
        # The G13/G16 deterministic ground: an observation that only repeats the
        # hypothesis is a mechanism description. The confirmed finding's
        # Response line must carry MEASUREMENTS, so the ground must not fire.
        agent = _make_agent()
        result = self._confirmed_result()
        result.rationale = (
            "The hidden field 'token' is populated by client-side JS using "
            "md5(rot13(phrase)), a token-like field name populated via computed "
            "hashing/encoding functions rather than user input validation."
        )
        form = {"method": "POST", "action": "/submit", "fields": []}
        finding = agent._js_attacks_phase4_emit("http://example.com/submit", form, result)
        assert ExploitAgent._fp_ground_observation_is_rationale(finding) is None

    def test_emitting_without_a_confirmed_forgery_is_a_caller_bug(self) -> None:
        agent = _make_agent()
        result = self._confirmed_result()
        result.forge_confirmed = False
        form = {"method": "POST", "action": "/submit", "fields": []}
        with pytest.raises(RuntimeError):
            agent._js_attacks_phase4_emit("http://example.com/submit", form, result)


# ===========================================================================
# Integration — full _test_javascript_attacks driving the methodology
# ===========================================================================


def _token_page(script: str, *, phrase_default: str = "ChangeMe", hint: str = "") -> PageAnalysis:
    body = (
        "<html><body>"
        f"{hint}"
        '<form method="POST" action="/submit">'
        f'<input type="text" name="phrase" id="phrase" value="{phrase_default}">'
        '<input type="hidden" name="token" id="token" value="">'
        '<input type="submit" name="send" value="Submit">'
        "</form>"
        f"<script>{script}</script>"
        "</body></html>"
    )
    return PageAnalysis(
        url="http://example.com/javascript",
        body=body,
        status=200,
        forms=[
            {
                "method": "POST",
                "action": "/submit",
                "fields": [
                    {"name": "phrase", "type": "text", "value": phrase_default},
                    {"name": "token", "type": "hidden", "value": ""},
                    {"name": "send", "type": "submit", "value": "Submit"},
                ],
            }
        ],
    )


_TOKEN_SCRIPT = (
    'var phrase = document.getElementById("phrase").value;'
    'document.getElementById("token").value = md5(rot13(phrase));'
)


class TestJSAttacksMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_server_accepting_the_forged_token_emits_a_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        # A server that validates the token, but only once the phrase is right —
        # so the isolating input has to be searched for.
        winning = "success"
        expected = hashlib.md5(_rot13(winning).encode(), usedforsecurity=False).hexdigest()

        async def _post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            if data.get("phrase") != winning:
                return _HTTPResponse(status=200, body="<p>You got the phrase wrong.</p>")
            if data.get("token") == expected:
                return _HTTPResponse(status=200, body="<p>Well done!</p>")
            return _HTTPResponse(status=200, body="<p>Invalid token.</p>")

        agent._http_post = AsyncMock(side_effect=_post)  # type: ignore[method-assign]
        page = _token_page(_TOKEN_SCRIPT, hint='<p>Submit the word "success" to win.</p>')
        findings = await agent._test_javascript_attacks(page)

        assert len(findings) == 1
        assert findings[0].severity.value == "high"
        joined = " ".join(findings[0].evidence)
        assert "forge_confirmed=True" in joined
        assert expected in joined
        assert "Well done!" in joined
        assert agent._unproven_exploit_leads == []

    @pytest.mark.asyncio
    async def test_server_ignoring_the_token_yields_a_lead_not_a_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>Thanks.</p>")
        )
        page = _token_page(_TOKEN_SCRIPT)
        findings = await agent._test_javascript_attacks(page)

        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1
        lead = agent._unproven_exploit_leads[0]
        assert lead.why_unconfirmed == _WHY_UNCONFIRMED
        assert lead.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        assert "equal-shaped control" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_unreplayable_chain_yields_a_lead_and_never_submits(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<p>ok</p>")
        )
        script = 'document.getElementById("token").value = serverNonce(Date.now());'
        findings = await agent._test_javascript_attacks(_token_page(script))

        assert findings == []
        assert agent._http_post.await_count == 0  # nothing to forge — nothing sent
        assert len(agent._unproven_exploit_leads) == 1
        lead = agent._unproven_exploit_leads[0]
        assert lead.why_unconfirmed == _WHY_UNCONFIRMED
        assert "replayable grammar" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_unstable_control_yields_a_lead(self) -> None:
        # A page whose chrome changes every request (a rotating CSRF nonce) can
        # produce a difference that has nothing to do with our token. The repeat
        # control catches it: two controls that disagree confirm nothing.
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        counter = {"n": 0}

        async def _post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            counter["n"] += 1
            return _HTTPResponse(status=200, body=f"<p>nonce {counter['n']}</p>")

        agent._http_post = AsyncMock(side_effect=_post)  # type: ignore[method-assign]
        findings = await agent._test_javascript_attacks(_token_page(_TOKEN_SCRIPT))

        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1
        assert agent._unproven_exploit_leads[0].why_unconfirmed == _WHY_UNCONFIRMED

    @pytest.mark.asyncio
    async def test_echoed_token_alone_cannot_manufacture_a_differential(self) -> None:
        # The server reflects whatever token it was given and nothing else. The
        # arms differ only by our own value, which is blanked before comparing.
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        async def _post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            return _HTTPResponse(status=200, body=f"<p>you sent {data.get('token', '')}</p>")

        agent._http_post = AsyncMock(side_effect=_post)  # type: ignore[method-assign]
        findings = await agent._test_javascript_attacks(_token_page(_TOKEN_SCRIPT))

        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1

    @pytest.mark.asyncio
    async def test_client_validation_only_yields_a_lead(self) -> None:
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
        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1
        assert agent._unproven_exploit_leads[0].why_unconfirmed == _WHY_UNCONFIRMED

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
        assert agent._unproven_exploit_leads == []  # N/A by construction
