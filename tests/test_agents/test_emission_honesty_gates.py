"""Regression tests for the D1 batch-2 emission-honesty gates (G9–G12).

Each class here pins one rule that a live engagement violated, using that
engagement's own raw evidence as the fixture:

    G9  — the deterministic character map gates emission for EVERY XSS class.
          ``978d4b3e`` (DVWA ``low``) emitted a HIGH "Reflected XSS in page
          parameter" whose own evidence read
          ``character_map=html_encoded='<','>','"','&'``.
    G10 — a candidate the engagement believes is a false positive is demoted,
          never emitted with a caveat; and two shapes can never confirm at all:
          a CONDITIONAL execution claim, and a reflection inside a framework
          error page.
    G11 — a posture check that determines it is not applicable emits nothing.
          ``c310487e`` (DVWA ``impossible``) emitted "Missing Security Header
          Strict-Transport-Security (not applicable, site is HTTP)" as
          confirmed/medium.
    G12 — an SSRF whose "internal content" is an HTTP status line echoed inside
          the stack's own fetch-failure message is reachability, not disclosure.
          ``cb54495c`` confirmed a HIGH SSRF on a loopback fetch that returned
          ``403 Forbidden``.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    _ERROR_BLOCK_MARKERS,
    _FETCH_FAILURE_MARKERS,
    ExploitAgent,
    PageAnalysis,
    _canonical_header_name,
    _HTTPResponse,
    _reflection_only_in_error_block,
    _states_conditional_execution,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    CharacterMap,
    FilterBehavior,
    HeaderWeaknessSeverity,
    MethodologyResult,
    ReflectionContext,
    SynthesizedPayload,
    XSSStoredMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="emission-honesty-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

# The fullwidth-homoglyph payload the live LOW run emitted as a HIGH finding.
FULLWIDTH_PAYLOAD = "＜script＞alert(document.domain)＜/script＞"

# Verbatim from engagement 978d4b3e's finding evidence.
LIVE_ENCODED_MAP = CharacterMap(
    per_char={
        "<": FilterBehavior.HTML_ENCODED,
        ">": FilterBehavior.HTML_ENCODED,
        '"': FilterBehavior.HTML_ENCODED,
        "&": FilterBehavior.HTML_ENCODED,
        "'": FilterBehavior.SURVIVED,
        "(": FilterBehavior.SURVIVED,
        ")": FilterBehavior.SURVIVED,
        ";": FilterBehavior.SURVIVED,
        "=": FilterBehavior.SURVIVED,
        "/": FilterBehavior.SURVIVED,
        "＜": FilterBehavior.SURVIVED,
        "＞": FilterBehavior.SURVIVED,
    }
)

RAW_MAP = CharacterMap(
    per_char={
        "<": FilterBehavior.SURVIVED,
        ">": FilterBehavior.SURVIVED,
        '"': FilterBehavior.SURVIVED,
        "'": FilterBehavior.SURVIVED,
        "=": FilterBehavior.SURVIVED,
        "/": FilterBehavior.SURVIVED,
        ";": FilterBehavior.SURVIVED,
    }
)

# The exact response the live run confirmed on: the payload appears ONLY inside
# PHP's include() warning.
PHP_WARNING_BODY = (
    "<br />\n<b>Warning</b>:  include("
    + FULLWIDTH_PAYLOAD
    + "): Failed to open stream: No such file or directory in "
    "<b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b><br />"
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
        return self.answers.pop(0) if self.answers else ""


def _make_agent(llm: LLMClient | None = None) -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=llm or _ScriptedLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="emission-honesty-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


# ===========================================================================
# G9 — the character map gates EVERY XSS class
# ===========================================================================


class TestG9CharacterMapGatesEveryClass:
    """The rule generalised from stored XSS to reflected and DOM."""

    @pytest.mark.parametrize("landing", ["html_body", "tag", "script"])
    def test_unicode_homoglyph_payload_carries_no_capability(self, landing: str) -> None:
        """A fullwidth U+FF1C is not a tag delimiter in any conforming parser, so
        a payload built from homoglyphs can never execute — in any context."""
        agent = _make_agent()
        ok, why = agent._xss_execution_possible(FULLWIDTH_PAYLOAD, landing, LIVE_ENCODED_MAP)
        assert ok is False
        assert why

    def test_encoded_required_chars_block_a_real_payload(self) -> None:
        """Even a genuinely functional payload cannot confirm when the map says
        the characters it needs were encoded. This is the general statement of
        the rule; the homoglyph case above is one instance of it."""
        agent = _make_agent()
        ok, why = agent._xss_execution_possible(
            "<script>alert(1)</script>", "html_body", LIVE_ENCODED_MAP
        )
        assert ok is False
        assert "did not survive" in why
        assert "html_encoded" in why

    def test_surviving_chars_permit_confirmation(self) -> None:
        """The gate is a suppressor, not a blocker: a real payload whose required
        characters survived passes untouched."""
        agent = _make_agent()
        assert agent._xss_execution_possible("<script>alert(1)</script>", "html_body", RAW_MAP)[0]

    def test_attribute_breakout_survives_when_only_double_quote_encoded(self) -> None:
        """A single-quote attribute breakout is a real bypass when ``'`` survived,
        even though ``<``/``>``/``"`` are encoded — the gate checks the set the
        payload actually uses, not one fixed set."""
        agent = _make_agent()
        assert agent._xss_execution_possible(
            "' onfocus='alert(1)' autofocus='", "tag", LIVE_ENCODED_MAP
        )[0]

    def test_unprobed_character_is_unknown_not_encoded(self) -> None:
        """Absence of evidence never vetoes: a character the map never probed
        cannot be treated as filtered."""
        agent = _make_agent()
        assert agent._xss_execution_possible(
            "<img src=x onerror=alert(1)>", "html_body", CharacterMap()
        )[0]

    @pytest.mark.asyncio
    async def test_reflected_phase5_refuses_the_live_phantom(self) -> None:
        """The reflected class — the one that emitted the live phantom. Phase 5
        sees the payload literally in the body and still refuses."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=PHP_WARNING_BODY)
        )
        verified, why, _resp = await agent._xss_phase5_verify(
            "http://example.com/vulnerabilities/fi/",
            "page",
            FULLWIDTH_PAYLOAD,
            context=ReflectionContext.HTML_BODY,
            char_map=LIVE_ENCODED_MAP,
        )
        assert verified is False
        assert why

    @pytest.mark.asyncio
    async def test_stored_phase5_applies_the_same_map_rule(self) -> None:
        """The stored class — same gate, same rejection."""
        agent = _make_agent()
        agent._submit_form_fields = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=f"<div>{FULLWIDTH_PAYLOAD}</div>")
        )
        form = {"action": "", "method": "POST", "fields": [{"name": "txtName", "type": "text"}]}
        page = PageAnalysis(url="http://example.com/guestbook", body="", status=200, forms=[form])
        verified, why = await agent._xss_stored_phase5_verify(
            page, form, "txtName", FULLWIDTH_PAYLOAD, page.url, LIVE_ENCODED_MAP
        )
        assert verified is False
        assert why

    def test_dom_class_shares_the_gate(self) -> None:
        """The DOM class routes through the same gate. Its map is synthetic (the
        server never sees the fragment), so the capability half is vacuous — but
        the claim half is not, and a conditional claim still vetoes."""
        agent = _make_agent()
        ok, _why = agent._xss_confirmation_gate(
            payload=FULLWIDTH_PAYLOAD,
            landing="js_dom_likely (sinks: document.write)",
            char_map=agent._xss_phase2_dom_character_fingerprint(),
        )
        assert ok is True
        ok, why = agent._xss_confirmation_gate(
            payload=FULLWIDTH_PAYLOAD,
            landing="js_dom_likely (sinks: document.write)",
            char_map=agent._xss_phase2_dom_character_fingerprint(),
            expected_execution="If the browser normalizes the fullwidth brackets it will execute.",
        )
        assert ok is False
        assert "conditional" in why

    def test_phase6_suppresses_when_the_gate_rejects(self) -> None:
        """End of the chain: even a result marked ``verified`` emits nothing when
        the gate rejects it, so no future caller can route around phase 5."""
        agent = _make_agent()
        result = MethodologyResult(
            phases_completed=6,
            verified=True,
            character_map=LIVE_ENCODED_MAP,
            landing_context="html_body",
            verifying_response=PHP_WARNING_BODY,
            synthesized_payload=SynthesizedPayload(
                payload=FULLWIDTH_PAYLOAD,
                rationale="Fullwidth variants survive the filter.",
                expected_execution="Once normalized, the tag executes.",
            ),
        )
        assert agent._xss_phase6_emit("http://example.com/x", "page", result) is None


# ===========================================================================
# G10 — speculation and error pages never confirm
# ===========================================================================


class TestG10ConditionalExecutionClaims:
    @pytest.mark.parametrize(
        "claim",
        [
            "Once rendered, the browser folds ＜ and ＞ into < and >, executing the tag.",
            "If such normalization occurs after the HTML-encoding step, the brackets collapse.",
            "When the surrounding page or normalization layer converts the full-width characters.",
            "If Unicode normalization/folding is applied at any stage before parsing.",
        ],
    )
    def test_live_conditional_claims_are_detected(self, claim: str) -> None:
        """All four rationales the live runs emitted are hypotheses about an
        unobserved downstream transform."""
        assert _states_conditional_execution(claim) is not None

    @pytest.mark.parametrize(
        "claim",
        [
            "The payload lands unescaped in the html_body context and the browser runs alert(1).",
            "Payload survives the store and lands unescaped in html_body context.",
            "The single quote breaks out of the attribute value, adding an onfocus handler.",
        ],
    )
    def test_observational_claims_pass(self, claim: str) -> None:
        """An observation of what DID happen is not a conditional claim."""
        assert _states_conditional_execution(claim) is None


class TestG10ReflectionInErrorPage:
    def test_payload_only_inside_a_php_warning_is_not_executable(self) -> None:
        assert (
            _reflection_only_in_error_block(
                PHP_WARNING_BODY, FULLWIDTH_PAYLOAD, _ERROR_BLOCK_MARKERS
            )
            == "<b>warning</b>"
        )

    def test_a_clean_landing_anywhere_defeats_the_veto(self) -> None:
        """Only when EVERY occurrence sits in an error block is the reflection
        non-executable — a payload that also lands in normal markup is real."""
        body = f"<div>{FULLWIDTH_PAYLOAD}</div>{PHP_WARNING_BODY}"
        assert (
            _reflection_only_in_error_block(body, FULLWIDTH_PAYLOAD, _ERROR_BLOCK_MARKERS) is None
        )

    def test_absent_needle_is_not_an_error_reflection(self) -> None:
        assert (
            _reflection_only_in_error_block(PHP_WARNING_BODY, "nope", _ERROR_BLOCK_MARKERS) is None
        )

    @pytest.mark.asyncio
    async def test_stored_gate_rejects_an_error_block_read_back(self) -> None:
        agent = _make_agent()
        agent._submit_form_fields = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        payload = "<script>alert(1)</script>"
        body = f"<b>Warning</b>:  include({payload}): Failed to open stream"
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        form = {"action": "", "method": "POST", "fields": [{"name": "txtName", "type": "text"}]}
        page = PageAnalysis(url="http://example.com/g", body="", status=200, forms=[form])
        verified, why = await agent._xss_stored_phase5_verify(
            page, form, "txtName", payload, page.url, RAW_MAP
        )
        assert verified is False
        assert "error block" in why


class TestG10SuppressDontAnnotate:
    def test_stored_confirmation_gate_rejects_a_conditional_claim(self) -> None:
        """A stored result that passes every deterministic check still cannot
        confirm on a conditional execution claim."""
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            verified=True,
            read_back_url="http://example.com/g",
            landing_context="html_body",
            character_map=RAW_MAP,
            synthesized_payload=SynthesizedPayload(
                payload="<script>alert(1)</script>",
                rationale="Tags survive the store.",
                expected_execution="If the template layer later decodes the entities, it runs.",
            ),
        )
        ok, why = agent._xss_stored_confirmation_gate(result)
        assert ok is False
        assert "conditional" in why


# ===========================================================================
# G11 — a not-applicable posture check emits nothing
# ===========================================================================


class TestG11PostureApplicability:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (
                "Strict-Transport-Security (not applicable, site is HTTP)",
                "Strict-Transport-Security",
            ),
            ("X-Frame-Options / CSP frame-ancestors", "X-Frame-Options"),
            ("X-Frame-Options (or CSP frame-ancestors)", "X-Frame-Options"),
            ("X-Frame-Options (and no frame-ancestors CSP directive)", "X-Frame-Options"),
            ("Content Security Policy", "Content-Security-Policy"),
            ("server", "Server"),
            ("   ", ""),
        ],
    )
    def test_header_names_canonicalise(self, raw: str, expected: str) -> None:
        assert _canonical_header_name(raw) == expected

    def _gate(self, url: str, observed: dict[str, str], missing: list[str], weak=None):
        agent = ExploitAgent.__new__(ExploitAgent)
        agent._logger = logging.getLogger("test.headers")
        return agent._gate_security_header_analysis(
            url, observed, (missing, list(weak or []), HeaderWeaknessSeverity.MEDIUM, "r")
        )

    def test_hsts_is_dropped_on_a_plain_http_origin(self) -> None:
        """The live IMPOSSIBLE defect: HSTS has no meaning without TLS, so its
        absence is not a weakness and nothing is emitted."""
        missing, _weak, _sev, rationale = self._gate(
            "http://172.20.0.2/", {}, ["Strict-Transport-Security"]
        )
        assert missing == []
        assert "not applicable" in rationale.lower()

    def test_hsts_survives_on_https(self) -> None:
        """The gate is applicability, not a blanket suppression."""
        missing, _weak, sev, _r = self._gate(
            "https://example.com/", {}, ["Strict-Transport-Security"]
        )
        assert missing == ["Strict-Transport-Security"]
        assert sev == HeaderWeaknessSeverity.MEDIUM

    def test_the_titles_own_not_applicable_caveat_is_honoured(self) -> None:
        """When the analysis writes the caveat into the name, honour it as a drop
        instead of rendering the caveat as a finding title."""
        missing, _weak, _sev, _r = self._gate(
            "https://example.com/", {}, ["Strict-Transport-Security (not applicable, site is HTTP)"]
        )
        assert missing == []

    def test_duplicate_header_variants_collapse_to_one(self) -> None:
        """One engagement emitted three separate findings for X-Frame-Options."""
        missing, _weak, _sev, _r = self._gate(
            "http://t/",
            {},
            [
                "X-Frame-Options",
                "X-Frame-Options (or CSP frame-ancestors)",
                "X-Frame-Options (and no frame-ancestors CSP directive)",
            ],
        )
        assert missing == ["X-Frame-Options"]

    def test_a_header_we_observed_is_never_reported_missing(self) -> None:
        missing, _weak, _sev, _r = self._gate("http://t/", {"server": "Apache"}, ["Server"])
        assert missing == []

    def test_a_header_we_did_not_observe_is_never_reported_weak(self) -> None:
        _missing, weak, _sev, _r = self._gate(
            "http://t/", {}, [], [("Server", "version disclosed")]
        )
        assert weak == []

    def test_deprecated_header_absence_is_correct_configuration(self) -> None:
        missing, _weak, _sev, _r = self._gate("https://t/", {}, ["X-XSS-Protection"])
        assert missing == []

    def test_severity_falls_when_its_only_driver_is_dropped(self) -> None:
        """Dropping the entry that justified MEDIUM must take the MEDIUM with it,
        or the surviving findings inherit a severity nothing supports."""
        _m, _w, sev, _r = self._gate(
            "http://t/", {}, ["Strict-Transport-Security", "Referrer-Policy"]
        )
        assert sev == HeaderWeaknessSeverity.LOW


# ===========================================================================
# G12 — a failed fetch is reachability, not disclosure
# ===========================================================================


class TestG12SSRFOn403:
    def test_status_line_titles_are_rejected_as_markers(self) -> None:
        """``403 Forbidden`` is the very string the fetching stack prints in its
        own failure message, so it can never distinguish disclosure from
        failure."""
        for title in ("403 Forbidden", "404 Not Found", "500 Internal Server Error", "Error"):
            assert ExploitAgent._ssrf_distinctive_marker(f"<title>{title}</title>") != title

    def test_a_real_title_is_still_a_marker(self) -> None:
        assert (
            ExploitAgent._ssrf_distinctive_marker("<title>GeoServer Web Admin</title>")
            == "GeoServer Web Admin"
        )

    @pytest.mark.asyncio
    async def test_no_marker_is_harvested_from_a_non_2xx_reference(self) -> None:
        """The root cause: the marker was harvested from a 403 reference page."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=403, body="<title>403 Forbidden</title><h1>Forbidden</h1>"
            )
        )
        assert await agent._ssrf_marker_at_path("http://t/vulnerabilities/") == ""

    @pytest.mark.asyncio
    async def test_a_2xx_reference_still_yields_its_marker(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<title>Internal Admin Console</title>")
        )
        assert await agent._ssrf_marker_at_path("http://t/admin/") == "Internal Admin Console"

    def test_marker_inside_a_fetch_failure_message_is_not_disclosure(self) -> None:
        """The live confirming body: PHP reporting that the loopback fetch got a
        403. The request went out (reachability) and returned nothing."""
        body = (
            "<br /><b>Warning</b>:  include(http://127.0.0.1:80/vulnerabilities/): "
            "Failed to open stream: HTTP request failed! HTTP/1.1 403 Forbidden in "
            "<b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b>"
        )
        assert (
            _reflection_only_in_error_block(body, "403 Forbidden", _FETCH_FAILURE_MARKERS)
            is not None
        )

    def test_genuinely_disclosed_content_is_untouched(self) -> None:
        """A marker in normal response position is real disclosure and must not
        be swept up by the failure gate."""
        body = "<html><title>Internal Admin Console</title><p>secrets</p></html>"
        assert (
            _reflection_only_in_error_block(body, "Internal Admin Console", _FETCH_FAILURE_MARKERS)
            is None
        )


# ===========================================================================
# Evidence must reproduce the request that was actually sent
# ===========================================================================


class TestEvidenceRequestIsTheRealRequest:
    """A Request evidence line a reader cannot reproduce is not evidence.

    ``_open_redirect_phase6_emit`` rendered ``f"{url}?{param}={payload}"``. On an
    endpoint whose URL already carries the parameter — DVWA's redirect handler is
    ``…/source/low.php?redirect=info.php`` — that printed ``redirect=`` TWICE,
    while ``_build_request_url`` REPLACES a same-named param in place (LESSONS
    #30). The rendered line described a request that was never sent.

    It is not a cosmetic defect: in engagement ``441c5728`` the post-run analysis
    read the doubled rendering as a "malformed/duplicated redirect parameter …
    possible test-harness payload construction artifact" and demoted a
    cleanly-confirmed finding (302 → ``Location: //evil.example``) on that basis.
    Bad evidence produced a bad verdict.
    """

    HANDLER = "http://t/app/open_redirect/source/low.php?redirect=info.php"

    def test_a_param_already_in_the_url_is_replaced_not_doubled(self) -> None:
        agent = _make_agent()
        built = agent._build_request_url(self.HANDLER, {"redirect": "//evil.example"})
        assert built.count("redirect=") == 1
        assert "info.php" not in built

    def test_the_naive_rendering_is_what_doubled_it(self) -> None:
        """Pins WHY the old line was wrong, so a future edit back to string
        concatenation fails here rather than in a live engagement."""
        naive = f"{self.HANDLER}?redirect=//evil.example"
        assert naive.count("redirect=") == 2

    def test_a_clean_url_is_unaffected(self) -> None:
        agent = _make_agent()
        built = agent._build_request_url("http://t/go", {"redirect": "//evil.example"})
        assert built.count("redirect=") == 1


# ===========================================================================
# G21 — a prose veto may not overrule a measurement
# ===========================================================================


class TestG21ProseVetoNeverOverrulesAWitness:
    """Three identical DVWA LOW engagements, one missing finding.

    Ladder B ran the same target three times. In all three the reflected class
    reached phase 5 on ``name`` with the same measurement — ``verified=True
    strength=verified context=html_body payload='<script>alert(1)</script>'``,
    all 25 probed characters surviving. Runs 1 and 3 emitted. Run 2
    (``43c813ba``) suppressed BOTH of its tasks at phase 6, with:

        reason=execution claim is conditional on an unobserved transform
               ('when' + 'unescape')
        reason=execution claim is conditional on an unobserved transform
               ('when' + 'transform')

    Nothing about the target differed. The model wrote a different sentence, and
    a veto that reads that sentence dropped a vulnerability the engine had
    already measured.

    The rule: a condition that reads PROSE applies only to an effect nobody
    witnessed. A witnessed literal landing outranks it — the same direction the
    emission side already runs in.
    """

    PAYLOAD = "<script>alert(1)</script>"

    # The two shapes run 2's model produced, reconstructed to the trace's own
    # reason strings: a conditional connective co-occurring with a transform verb.
    B2_RATIONALES = (
        "The name parameter is echoed into the page; when the application "
        "unescapes it the script tag executes.",
        "Reflected into the HTML body — when no transform is applied on output the tag runs.",
    )

    def _result(self, rationale: str, *, witnessed: bool) -> MethodologyResult:
        return MethodologyResult(
            phases_completed=5,
            verified=True,
            verification_strength="verified",
            character_map=RAW_MAP,
            landing_context="html_body",
            literal_landing_witnessed=witnessed,
            verifying_response=f"<pre>Hello {self.PAYLOAD}</pre>",
            synthesized_payload=SynthesizedPayload(
                payload=self.PAYLOAD,
                rationale=rationale,
                expected_execution="alert(1) runs in the page origin.",
            ),
        )

    @pytest.mark.parametrize("rationale", B2_RATIONALES)
    def test_run2_wording_no_longer_suppresses_a_measured_landing(self, rationale: str) -> None:
        agent = _make_agent()
        finding = agent._xss_phase6_emit(
            "http://t/vulnerabilities/xss_r/", "name", self._result(rationale, witnessed=True)
        )
        assert finding is not None, "a witnessed literal landing was dropped on wording"
        assert finding.title == "Reflected XSS in name parameter"

    @pytest.mark.parametrize("rationale", B2_RATIONALES)
    def test_the_same_wording_still_vetoes_an_unwitnessed_claim(self, rationale: str) -> None:
        """G10 is not weakened. Without the measurement the veto still bites —
        which is the case it was written for."""
        agent = _make_agent()
        ok, reason = agent._xss_confirmation_gate(
            payload=self.PAYLOAD,
            landing="html_body",
            char_map=RAW_MAP,
            rationale=rationale,
            expected_execution="",
            literal_landing_witnessed=False,
        )
        assert ok is False
        assert "conditional on an unobserved transform" in reason

    def test_run1_and_run3_wording_was_never_at_risk(self) -> None:
        """The control: the wording the two emitting runs produced trips no veto
        either way, which is exactly why they emitted."""
        agent = _make_agent()
        for witnessed in (True, False):
            ok, reason = agent._xss_confirmation_gate(
                payload=self.PAYLOAD,
                landing="html_body",
                char_map=RAW_MAP,
                rationale="The payload lands unescaped in the html_body context.",
                expected_execution="The browser parses the tag and runs alert(1).",
                literal_landing_witnessed=witnessed,
            )
            assert (ok, reason) == (True, "confirmed")

    def test_a_measurement_does_not_rescue_a_failed_character_map(self) -> None:
        """The witness lifts the PROSE vetoes only. A deterministic condition —
        the character map, the error-block check — is unaffected, or the fix
        would have re-opened the G9 phantom it sits next to."""
        agent = _make_agent()
        ok, why = agent._xss_confirmation_gate(
            payload=self.PAYLOAD,
            landing="html_body",
            char_map=LIVE_ENCODED_MAP,
            rationale="Lands unescaped.",
            expected_execution="",
            literal_landing_witnessed=True,
        )
        assert ok is False
        assert "did not survive" in why

    def test_a_measurement_does_not_rescue_an_error_page_reflection(self) -> None:
        """A functional payload echoed ONLY inside a PHP warning is still the
        interpreter reporting what it refused to do, witness or not."""
        agent = _make_agent()
        ok, why = agent._xss_confirmation_gate(
            payload=self.PAYLOAD,
            landing="html_body",
            char_map=RAW_MAP,
            rationale="Lands unescaped.",
            expected_execution="",
            verifying_body=(
                "<br />\n<b>Warning</b>:  include("
                + self.PAYLOAD
                + "): Failed to open stream in <b>/var/www/html/x.php</b><br />"
            ),
            literal_landing_witnessed=True,
        )
        assert ok is False
        assert "error block" in why

    def test_dom_path_keeps_the_veto_because_it_witnesses_no_landing(self) -> None:
        """The JS_DOM branch of phase 5 never looks for the payload in the body —
        the server does not echo a fragment — so it must never claim the witness."""
        agent = _make_agent()
        ok, reason = agent._xss_confirmation_gate(
            payload=self.PAYLOAD,
            landing="js_dom_likely (sinks: document.write)",
            char_map=RAW_MAP,
            rationale=self.B2_RATIONALES[0],
            expected_execution="",
            literal_landing_witnessed=False,
        )
        assert ok is False
        assert "conditional on an unobserved transform" in reason

    def test_the_witness_is_recorded_in_the_evidence(self) -> None:
        """The measurement has to be readable from the raw report, or the
        post-run cross-check has nothing to tell it apart from the prose."""
        agent = _make_agent()
        finding = agent._xss_phase6_emit(
            "http://t/vulnerabilities/xss_r/",
            "name",
            self._result(self.B2_RATIONALES[0], witnessed=True),
        )
        assert finding is not None
        assert any(ev.startswith("literal_landing_witnessed=True") for ev in finding.evidence), (
            finding.evidence
        )

    def test_the_fp_crosscheck_ground_reads_the_same_witness(self) -> None:
        """The demotion side runs the same rule: ground 3 read the same prose to
        demote, so it reads the same witness to stand down."""
        agent = _make_agent()
        finding = agent._xss_phase6_emit(
            "http://t/vulnerabilities/xss_r/",
            "name",
            self._result(self.B2_RATIONALES[0], witnessed=True),
        )
        assert finding is not None
        assert agent._fp_ground_conditional_claim(finding) is None

    @pytest.mark.parametrize("witness_line", ["literal_landing_witnessed=False", None])
    def test_the_fp_crosscheck_ground_still_fires_without_the_witness(
        self, witness_line: str | None
    ) -> None:
        """Ground 3 is a pure function of a finding's evidence, and it serves
        every class — including the ones that never run the XSS gate and so never
        write the witness at all. Absent or False, it demotes exactly as before."""
        agent = _make_agent()
        finding = agent._make_finding(
            title="Reflected XSS in name parameter",
            severity="high",
            endpoint="http://t/vulnerabilities/xss_r/",
            parameter="name",
            evidence_request="GET http://t/vulnerabilities/xss_r/ — name=x",
            evidence_response="<pre>Hello x</pre>",
            technique="WSTG-INPV-01",
        )
        if witness_line is not None:
            finding.evidence.append(witness_line)
        finding.evidence.append(f"synthesis_rationale={self.B2_RATIONALES[0]}")
        assert agent._fp_ground_conditional_claim(finding) is not None

    def test_the_reflected_class_never_reaches_the_crosscheck_unwitnessed(self) -> None:
        """And the belt to that brace: without the measurement the gate refuses
        at phase 6, so nothing unwitnessed ever gets as far as a demotion."""
        agent = _make_agent()
        assert (
            agent._xss_phase6_emit(
                "http://t/vulnerabilities/xss_r/",
                "name",
                self._result(self.B2_RATIONALES[0], witnessed=False),
            )
            is None
        )

    @pytest.mark.parametrize("witnessed", [True, False])
    def test_stored_xss_runs_the_identical_rule(self, witnessed: bool) -> None:
        """The gate is shared, so the flake was latent in stored XSS too. Its
        phase 5 only returns True past a literal read-back, so it always carries
        the witness — pin both halves anyway."""
        agent = _make_agent()
        result = XSSStoredMethodologyResult(
            phases_completed=5,
            verified=True,
            verification_strength="verified",
            character_map=RAW_MAP,
            landing_context="html_body",
            literal_landing_witnessed=witnessed,
            read_back_url="http://t/vulnerabilities/xss_s/",
            synthesized_payload=SynthesizedPayload(
                payload=self.PAYLOAD,
                rationale=self.B2_RATIONALES[0],
                expected_execution="",
            ),
        )
        ok, reason = agent._xss_stored_confirmation_gate(result)
        assert ok is witnessed, reason
