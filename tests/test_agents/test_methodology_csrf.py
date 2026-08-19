"""Unit tests for the adaptive CSRF methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — state-changing detection
    Phase 2 (observation)  — token-shape extraction + rotation sampling
    Phase 3 (analysis)     — deterministic classification (no LLM on this path)
    Phase 4 (finding)      — Finding evidence chain + dedup behaviour
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    CSRFMethodologyResult,
    CSRFWeaknessType,
)
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-csrf-test",
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
        engagement_id="methodology-csrf-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(url: str = "http://example.com/transfer") -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200)


# ===========================================================================
# Phase 1 — Hypothesis
# ===========================================================================


class TestPhase1Hypothesis:
    def test_post_method_qualifies(self) -> None:
        agent = _make_agent()
        form = {"method": "POST", "action": "/transfer", "fields": []}
        assert agent._csrf_phase1_hypothesis(form) is True

    def test_delete_method_qualifies(self) -> None:
        agent = _make_agent()
        form = {"method": "DELETE", "action": "/users/1", "fields": []}
        assert agent._csrf_phase1_hypothesis(form) is True

    def test_get_with_action_verb_qualifies(self) -> None:
        agent = _make_agent()
        form = {"method": "GET", "action": "/account/delete", "fields": []}
        assert agent._csrf_phase1_hypothesis(form) is True

    def test_get_without_state_change_skipped(self) -> None:
        agent = _make_agent()
        form = {"method": "GET", "action": "/search", "fields": []}
        assert agent._csrf_phase1_hypothesis(form) is False

    def test_post_without_sensitive_signal_skipped(self) -> None:
        """A token-less POST that is not security-sensitive (a guestbook sign) is
        NOT a CSRF target — the over-emission fix (engagement f7a761a1 sprayed
        CSRF across /xss_s/, /csp/, /javascript/, /upload/)."""
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/vulnerabilities/xss_s/",
            "fields": [
                {"name": "txtName", "type": "text"},
                {"name": "mtxMessage", "type": "text"},
                {"name": "btnSign", "type": "submit"},
            ],
        }
        assert agent._csrf_phase1_hypothesis(form) is False

    def test_password_change_form_qualifies(self) -> None:
        """The genuine password-change challenge (DVWA /csrf/, a GET form with
        password_new/password_conf) must still confirm."""
        agent = _make_agent()
        form = {
            "method": "GET",
            "action": "",
            "fields": [
                {"name": "password_new", "type": "password"},
                {"name": "password_conf", "type": "password"},
                {"name": "Change", "type": "submit"},
            ],
        }
        assert agent._csrf_phase1_hypothesis(form) is True

    def test_security_sensitive_predicate_consistency(self) -> None:
        """Equivalent non-sensitive pages get the SAME verdict (no arbitrary
        confirmed-vs-FP): a CSP-include and a crypto-encrypt POST both skip."""
        agent = _make_agent()
        csp = {"method": "POST", "action": "/vulnerabilities/csp/", "fields": [{"name": "include"}]}
        crypto = {
            "method": "POST",
            "action": "/vulnerabilities/cryptography/",
            "fields": [{"name": "message"}, {"name": "direction"}],
        }
        assert agent._csrf_phase1_hypothesis(csp) is False
        assert agent._csrf_phase1_hypothesis(crypto) is False

    def test_lone_password_field_not_sensitive(self) -> None:
        """A lone password field is NOT a CSRF target (engagement ec39350b:
        DVWA ``/cryptography/index.php``'s ``['password','']`` form sprayed a
        CSRF finding off the single password input). A password signal qualifies
        only with mutation structure — a second password field or a
        change/registration qualifier — which this form has neither of."""
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "index.php",
            "fields": [
                {"name": "password", "type": "password"},
                {"name": "", "type": "submit"},
            ],
        }
        assert (
            agent._csrf_is_security_sensitive(
                form, "http://example.com/vulnerabilities/cryptography/index.php"
            )
            is False
        )
        assert agent._csrf_phase1_hypothesis(form) is False

    def test_new_and_confirm_password_post_form_qualifies(self) -> None:
        """A password *mutation* — new + confirm password fields — IS a CSRF
        target even as a bare POST (the genuine password-change class), via the
        >= 2 password-fields mutation-structure signal."""
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/account/password",
            "fields": [
                {"name": "password_new", "type": "password"},
                {"name": "password_conf", "type": "password"},
                {"name": "Change", "type": "submit"},
            ],
        }
        assert agent._csrf_is_security_sensitive(form) is True
        assert agent._csrf_phase1_hypothesis(form) is True


# ===========================================================================
# Phase 2 — Observation
# ===========================================================================


class TestPhase2Observation:
    @pytest.mark.asyncio
    async def test_extracts_static_token_value(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/transfer",
            "fields": [
                {"name": "csrf_token", "type": "hidden", "value": "abc123"},
                {"name": "amount", "type": "text", "value": ""},
            ],
        }
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body='<input name="csrf_token" type="hidden" value="abc123">',
            )
        )
        tokens, evidence = await agent._csrf_phase2_observation(_make_page(), form)
        assert "csrf_token" in tokens
        assert tokens["csrf_token"][0] == "abc123"
        # Three samples: initial value + two refetches.
        assert len(tokens["csrf_token"]) == 3
        assert evidence["cookie_samesite"] == ""

    @pytest.mark.asyncio
    async def test_no_token_fields_returns_empty(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/transfer",
            "fields": [{"name": "amount", "type": "text"}],
        }
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        tokens, _ev = await agent._csrf_phase2_observation(_make_page(), form)
        assert tokens == {}

    @pytest.mark.asyncio
    async def test_extracts_samesite_directive(self) -> None:
        agent = _make_agent()
        form = {"method": "POST", "action": "/transfer", "fields": []}
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="",
                headers={"Set-Cookie": "sid=xyz; Path=/; SameSite=Strict"},
            )
        )
        _tokens, evidence = await agent._csrf_phase2_observation(_make_page(), form)
        assert evidence["cookie_samesite"] == "strict"


# ===========================================================================
# Phase 3 — Analysis
# ===========================================================================


class TestPhase3Analysis:
    @pytest.mark.asyncio
    async def test_the_llm_is_never_consulted(self) -> None:
        """The model is not asked — asserted on the CALL, not on the answer.

        A behavioural test ("the verdict matches the deterministic one") passes
        just as happily against a version that consults the model and discards
        its reply, which is not the property being claimed. The claim is that
        this class cannot vary with the model that served it, and only the
        absence of the call establishes that.
        """
        llm = _ScriptedLLM(
            answers=[
                '{"weakness": "predictable", "protected": false, "rationale": "constant token"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        weakness, protected, rationale = await agent._csrf_phase3_analyze(
            {"csrf": ["v1", "v1", "v1"]}, {}
        )

        assert llm.prompts == []
        assert llm.answers, "the scripted answer must still be unconsumed"
        # And the verdict is the deterministic one, not the model's.
        assert weakness == CSRFWeaknessType.PREDICTABLE
        assert protected is False
        assert "stayed constant" in rationale

    @pytest.mark.asyncio
    async def test_missing_token_marks_unprotected(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        weakness, protected, _r = await agent._csrf_phase3_analyze(
            {}, {"set_cookie_present": False, "cookie_samesite": ""}
        )
        assert weakness == CSRFWeaknessType.MISSING
        assert protected is False

    @pytest.mark.asyncio
    async def test_samesite_strict_compensates(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        weakness, protected, _r = await agent._csrf_phase3_analyze(
            {}, {"set_cookie_present": True, "cookie_samesite": "strict"}
        )
        assert weakness == CSRFWeaknessType.SAMESITE_COMPENSATED
        assert protected is True

    @pytest.mark.asyncio
    async def test_constant_token_marks_predictable(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        weakness, protected, _r = await agent._csrf_phase3_analyze(
            {"csrf_token": ["t1", "t1", "t1"]}, {}
        )
        assert weakness == CSRFWeaknessType.PREDICTABLE
        assert protected is False

    @pytest.mark.asyncio
    async def test_rotating_tokens_marks_protected(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        weakness, protected, _r = await agent._csrf_phase3_analyze(
            {"csrf_token": ["t1", "t2", "t3"]}, {}
        )
        assert weakness is None
        assert protected is True

    @pytest.mark.asyncio
    async def test_rotating_session_bound_token_is_protection(self) -> None:
        """A rotating, session-bound ``user_token`` transmitted via GET is genuine
        protection (the DVWA-high phantom). The override fires before the
        classifier, and no model opinion can reach the verdict at all now."""
        llm = _ScriptedLLM(
            answers=[
                '{"weakness": "missing", "protected": false, '
                '"rationale": "GET-transmitted token is effectively missing"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        weakness, protected, _r = await agent._csrf_phase3_analyze(
            {"user_token": ["a1b2", "c3d4", "e5f6"]},
            {"tokens_without_cookies": {}, "cookie_samesite": "", "set_cookie_present": False},
        )
        assert protected is True
        assert weakness is None
        assert llm.prompts == []

    @pytest.mark.asyncio
    async def test_token_present_without_cookies_not_session_bound(self) -> None:
        """A 'token' that is still served on the cookie-stripped fetch is not
        session-bound, so the protection override does NOT fire — the deterministic
        classification stands (here: a constant value → predictable)."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        protected, _reason = agent._csrf_token_provides_protection(
            {"user_token": ["a1", "b2", "c3"]},
            {"tokens_without_cookies": {"user_token": "still-here"}},
        )
        assert protected is False


# ===========================================================================
# Phase 4 — Finding
# ===========================================================================


class TestPhase4Finding:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = CSRFMethodologyResult(
            phases_completed=4,
            form_action="http://example.com/transfer",
            method="POST",
            tokens_observed={},
            weakness_type=CSRFWeaknessType.MISSING,
            protected=False,
            rationale="no token observed",
        )
        finding = agent._csrf_phase4_emit(
            "http://example.com/transfer",
            {"method": "POST", "action": "/transfer", "fields": []},
            result,
        )
        joined = " ".join(finding.evidence)
        assert "phases_completed=4" in joined
        assert "weakness_type=missing" in joined
        assert finding.severity.value == "high"

    def test_predictable_weakness_is_medium(self) -> None:
        agent = _make_agent()
        result = CSRFMethodologyResult(
            phases_completed=4,
            form_action="http://example.com/x",
            method="POST",
            tokens_observed={"csrf": ["v1", "v1"]},
            weakness_type=CSRFWeaknessType.PREDICTABLE,
            protected=False,
        )
        finding = agent._csrf_phase4_emit(
            "http://example.com/x",
            {"method": "POST", "action": "/x", "fields": []},
            result,
        )
        assert finding.severity.value == "medium"


# ===========================================================================
# Integration — full _test_csrf driving all four phases
# ===========================================================================


class TestCSRFMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_missing_token_post_form_emits_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        page = PageAnalysis(
            url="http://example.com/transfer",
            body="",
            status=200,
            forms=[
                {
                    "method": "POST",
                    "action": "/transfer",
                    "fields": [{"name": "amount", "type": "text"}],
                }
            ],
        )
        findings = await agent._test_csrf(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "weakness_type=missing" in joined
        assert "phases_completed=4" in joined

    @pytest.mark.asyncio
    async def test_protected_form_yields_no_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        # Rotate token across refetches.
        rotation = iter(
            [
                _HTTPResponse(
                    status=200,
                    body='<input name="csrf_token" type="hidden" value="r2">',
                ),
                _HTTPResponse(
                    status=200,
                    body='<input name="csrf_token" type="hidden" value="r3">',
                ),
                # The cookie-inspection GET + without-cookies GETs may also occur.
                _HTTPResponse(status=200, body=""),
                _HTTPResponse(status=200, body=""),
            ]
        )

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            try:
                return next(rotation)
            except StopIteration:
                return _HTTPResponse(status=200, body="")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/transfer",
            body="",
            status=200,
            forms=[
                {
                    "method": "POST",
                    "action": "/transfer",
                    "fields": [
                        {"name": "csrf_token", "type": "hidden", "value": "r1"},
                        {"name": "amount", "type": "text"},
                    ],
                }
            ],
        )
        findings = await agent._test_csrf(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_rotating_token_get_form_no_finding_despite_llm_missing(self) -> None:
        """FIX 2 end-to-end: a DVWA-high/impossible-shaped GET password-change
        form with a rotating, session-bound user_token emits NOTHING even when
        the LLM insists the token is 'missing'."""
        llm = _ScriptedLLM(
            answers=[
                '{"weakness": "missing", "protected": false, "rationale": "GET token missing"}'
            ]
            * 4
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        agent._session_cookies = {"PHPSESSID": "abc"}
        rotation = iter(
            [
                _HTTPResponse(status=200, body='<input name="user_token" value="t2">'),
                _HTTPResponse(status=200, body='<input name="user_token" value="t3">'),
                _HTTPResponse(status=200, body=""),  # cookie-inspection GET
                # without-cookies GET: DVWA 302s to login, no token in body
                _HTTPResponse(status=302, body=""),
            ]
        )

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            try:
                return next(rotation)
            except StopIteration:
                return _HTTPResponse(status=200, body="")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/csrf/",
            body="",
            status=200,
            forms=[
                {
                    "method": "GET",
                    "action": "",
                    "fields": [
                        {"name": "password_new", "type": "password"},
                        {"name": "password_conf", "type": "password"},
                        {"name": "Change", "type": "submit"},
                        {"name": "user_token", "type": "hidden", "value": "t1"},
                    ],
                }
            ],
        )
        findings = await agent._test_csrf(page)
        assert findings == []


# ===========================================================================
# fix #4 — JSON-body state-changing API (no HTML form)
# ===========================================================================


def _json_api_page() -> PageAnalysis:
    """A *security-sensitive* state-changing JSON API endpoint with no HTML <form>.

    A password-change API (the sensitive-action class CSRF actually matters for)
    reached only via the synthesized JSON pseudo-form (fix #4). A low-impact
    JSON API (e.g. a feedback/comment post) is deliberately NOT a CSRF target
    under the tightened sensitivity gate, so this page is sensitive on purpose.
    """
    return PageAnalysis(
        url="http://example.com/rest/user/change-password",
        body="",
        status=200,
        input_params=["current", "new"],
        request_method="POST",
        content_type="application/json",
        param_locations={
            "current": ParamLocation.JSON_BODY,
            "new": ParamLocation.JSON_BODY,
        },
    )


class TestCSRFJsonBody:
    @pytest.mark.asyncio
    async def test_cookie_session_flags_missing_token(self) -> None:
        """A cookie-authenticated *security-sensitive* state-changing JSON API
        with no anti-CSRF token is CSRF-able — the synthesized JSON pseudo-form
        is evaluated and a finding is emitted (deterministic fallback, silent
        LLM)."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._session_cookies = {"session": "abc"}  # ambient cookie
        # No token field, no SameSite directive on any response.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="{}", headers={})
        )
        findings = await agent._test_csrf(_json_api_page())
        assert len(findings) == 1
        assert "CSRF" in findings[0].title

    @pytest.mark.asyncio
    async def test_bearer_only_session_is_justified_non_finding(self) -> None:
        """A JSON API authenticated purely by a bearer header (no ambient
        cookie) is NOT CSRF-able — the honesty guard suppresses the finding."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._session_headers = {"Authorization": "Bearer JWT"}
        agent._session_cookies = {}
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="{}", headers={})
        )
        findings = await agent._test_csrf(_json_api_page())
        assert findings == []
