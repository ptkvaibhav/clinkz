"""Unit tests for the adaptive brute-force methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (hypothesis)   — auth-endpoint detection
    Phase 2 (observation)  — 8 failed-auth attempts, response signatures
    Phase 3 (analysis)     — LLM JSON parsing + deterministic fallback
    Phase 4 (finding)      — Finding evidence chain
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    BruteForceMethodologyResult,
    BruteForceObservation,
    BruteForceProtectionType,
)
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-brute-force-test",
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
        engagement_id="methodology-brute-force-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _login_form(method: str = "POST") -> dict[str, Any]:
    return {
        "method": method,
        "action": "/login",
        "fields": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
            {"name": "Login", "type": "submit", "value": "Login"},
        ],
    }


# ===========================================================================
# Phase 1 — Hypothesis
# ===========================================================================


class TestPhase1Hypothesis:
    def test_login_form_shape_qualifies(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/", body="", status=200)
        ok, _ev = agent._brute_force_phase1_hypothesis(page, _login_form())
        assert ok is True

    def test_path_match_alone_qualifies(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/rest/user/login", body="", status=200)
        # An API endpoint may not expose a login-shape HTML form, but the
        # path alone is enough to qualify.
        form = {"method": "POST", "action": "/rest/user/login", "fields": []}
        ok, _ev = agent._brute_force_phase1_hypothesis(page, form)
        assert ok is True

    def test_unrelated_form_skipped(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(url="http://example.com/search", body="", status=200)
        form = {
            "method": "GET",
            "action": "/search",
            "fields": [{"name": "q", "type": "text"}],
        }
        ok, _ev = agent._brute_force_phase1_hypothesis(page, form)
        assert ok is False


# ===========================================================================
# Phase 2 — Observation
# ===========================================================================


class TestPhase2Observation:
    @pytest.mark.asyncio
    async def test_collects_eight_observations(self) -> None:
        agent = _make_agent()
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Username and/or password incorrect.")
        )
        observations, evidence = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            _login_form(),
            {},
        )
        assert len(observations) == 8
        assert all(o.status == 200 for o in observations)
        assert evidence["username_field"] == "username"

    @pytest.mark.asyncio
    async def test_rate_limit_short_circuits(self) -> None:
        agent = _make_agent()
        responses = iter(
            [
                _HTTPResponse(status=200, body="invalid"),
                _HTTPResponse(status=200, body="invalid"),
                _HTTPResponse(
                    status=429,
                    body="too many requests",
                    headers={"Retry-After": "60"},
                ),
            ]
        )

        async def fake_post(_url: str, _data: dict[str, str]) -> _HTTPResponse:
            return next(responses)

        agent._http_post = fake_post  # type: ignore[method-assign]
        observations, _ev = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            _login_form(),
            {},
        )
        assert len(observations) == 3
        assert observations[-1].status == 429
        assert observations[-1].retry_after == "60"

    @pytest.mark.asyncio
    async def test_no_password_field_returns_empty(self) -> None:
        agent = _make_agent()
        form = {
            "method": "POST",
            "action": "/login",
            "fields": [{"name": "username", "type": "text"}],
        }
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        observations, _ev = await agent._brute_force_phase2_observation(
            "http://example.com/login",
            form,
            {},
        )
        assert observations == []


# ===========================================================================
# Phase 3 — Analysis
# ===========================================================================


def _obs(
    n: int,
    *,
    status: int = 200,
    length: int = 1024,
    time_ms: float = 50.0,
    body_marker: str = "",
    retry_after: str = "",
    auth_reached: bool = True,
) -> BruteForceObservation:
    """One observation row.

    ``auth_reached`` defaults to True so the protection-shape tests below
    exercise the classifier they are about; the positive control itself has
    dedicated tests in :class:`TestPositiveControl`.
    """
    return BruteForceObservation(
        attempt=n,
        status=status,
        length=length,
        time_ms=time_ms,
        body_marker=body_marker,
        retry_after=retry_after,
        auth_reached=auth_reached,
        auth_reach_reason="test fixture",
    )


class TestPhase3Analysis:
    @pytest.mark.asyncio
    async def test_llm_classification_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "rate_limit", "protected": true, '
                '"observed_at_attempt": 3, "rationale": "429 at attempt 3"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(8)]
        ptype, protected, attempt, rationale = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.RATE_LIMIT
        assert protected is True
        assert attempt == 3
        assert "429" in rationale

    @pytest.mark.asyncio
    async def test_no_protection_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(8)]
        ptype, protected, attempt, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.NONE
        assert protected is False
        assert attempt is None

    @pytest.mark.asyncio
    async def test_retry_after_fallback_detects_rate_limit(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(3)] + [
            _obs(3, status=429, retry_after="30"),
        ]
        ptype, protected, attempt, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.RATE_LIMIT
        assert protected is True
        assert attempt == 3

    @pytest.mark.asyncio
    async def test_captcha_marker_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(4)] + [
            _obs(4, body_marker="captcha required"),
        ]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.CAPTCHA
        assert protected is True

    @pytest.mark.asyncio
    async def test_delay_fallback(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [
            _obs(0, time_ms=50.0),
            _obs(1, time_ms=80.0),
            _obs(2, time_ms=120.0),
            _obs(3, time_ms=200.0),
            _obs(4, time_ms=400.0),
            _obs(5, time_ms=800.0),
            _obs(6, time_ms=1200.0),
            _obs(7, time_ms=1600.0),
        ]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.DELAY
        assert protected is True


# ===========================================================================
# Phase 4 — Finding
# ===========================================================================


class TestPhase4Finding:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = BruteForceMethodologyResult(
            phases_completed=4,
            login_url="http://example.com/login",
            method="POST",
            observations=[_obs(i) for i in range(8)],
            protection_type=BruteForceProtectionType.NONE,
            protected=False,
            rationale="all responses identical",
        )
        finding = agent._brute_force_phase4_emit(_login_form(), result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=4" in joined
        assert "protection_type=none" in joined
        assert finding.severity.value == "medium"


# ===========================================================================
# Integration — full _test_brute_force driving all four phases
# ===========================================================================


class TestBruteForceMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_unprotected_login_emits_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="Username and/or password incorrect.")
        )
        page = PageAnalysis(
            url="http://example.com/login",
            body="",
            status=200,
            forms=[_login_form()],
        )
        findings = await agent._test_brute_force(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "protection_type=none" in joined
        assert "phases_completed=4" in joined

    @pytest.mark.asyncio
    async def test_rate_limited_login_no_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm
        agent._http_post = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=429,
                body="too many requests",
                headers={"Retry-After": "60"},
            )
        )
        page = PageAnalysis(
            url="http://example.com/login",
            body="",
            status=200,
            forms=[_login_form()],
        )
        findings = await agent._test_brute_force(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_json_login_no_rate_limit_emits_finding(self) -> None:
        """fix #4: a JSON login API (POST /rest/user/login {email,password}) —
        no HTML <form> — is reached via the synthesized JSON pseudo-form, its
        credentials submitted as a JSON body, and 'no rate-limit' detected."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        posted: list[dict[str, Any]] = []

        async def fake_post_json(
            _url: str, obj: dict[str, Any], method: str = "POST"
        ) -> _HTTPResponse:
            posted.append(obj)
            return _HTTPResponse(status=401, body="Invalid email or password.")

        agent._http_post_json = fake_post_json  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/rest/user/login",
            body="",
            status=200,
            input_params=["email", "password"],
            request_method="POST",
            content_type="application/json",
            param_locations={
                "email": ParamLocation.JSON_BODY,
                "password": ParamLocation.JSON_BODY,
            },
        )
        findings = await agent._test_brute_force(page)
        assert len(findings) == 1, "brute-force did not reach the JSON login API"
        joined = " ".join(findings[0].evidence)
        assert "protection_type=none" in joined
        # Credentials really were submitted as a JSON body, 8 times.
        assert len(posted) == 8
        assert posted[0]["email"] and posted[0]["password"]


# ===========================================================================
# G3 — the positive control and the constant-delay shape
#
# Two live misreads motivated these. At DVWA ``high`` the eight attempts came
# back [200, 302x7] with length=1: seven requests carried a stale anti-CSRF
# token and were redirected away before authenticating, so "no lockout marker"
# was trivially true of requests that never reached auth — and the module
# reported the endpoint unprotected. At DVWA ``medium`` all eight attempts took
# ~2250 ms against a ~200 ms page load — a deliberate sleep(2) throttle — and
# the monotonic-growth check read the flat penalty as no protection.
# ===========================================================================


class TestPositiveControl:
    """Did the bad-credential attempt actually reach the auth handler?"""

    def _agent(self) -> ExploitAgent:
        return _make_agent()

    def test_bounced_redirect_did_not_reach_auth(self) -> None:
        """DVWA ``high``: 302 to a different path with a 1-byte body."""
        agent = self._agent()
        resp = _HTTPResponse(status=302, body=" ", headers={"Location": "index.php"})
        reached, reason = agent._brute_force_attempt_reached_auth(
            resp, "http://t/vulnerabilities/brute/", "the login page baseline"
        )
        assert reached is False
        assert "bounced" in reason

    def test_redirect_back_to_the_auth_endpoint_reached_auth(self) -> None:
        """A genuine POST-redirect-GET login renders its outcome on the redirect."""
        agent = self._agent()
        resp = _HTTPResponse(status=302, body="", headers={"Location": "/login"})
        reached, _reason = agent._brute_force_attempt_reached_auth(
            resp, "http://t/login", "baseline"
        )
        assert reached is True

    def test_401_reached_auth(self) -> None:
        agent = self._agent()
        resp = _HTTPResponse(status=401, body='{"error":"invalid"}')
        reached, reason = agent._brute_force_attempt_reached_auth(
            resp, "http://t/rest/user/login", "baseline"
        )
        assert reached is True
        assert "401" in reason

    def test_auth_failure_marker_absent_from_baseline_reached_auth(self) -> None:
        """DVWA ``low``: 200 rendering 'Username and/or password incorrect.'"""
        agent = self._agent()
        body = "<html><body>Username and/or password incorrect.</body></html>"
        reached, reason = agent._brute_force_attempt_reached_auth(
            resp=_HTTPResponse(status=200, body=body),
            login_url="http://t/vulnerabilities/brute/",
            baseline_body="<html><body>login form only</body></html>",
        )
        assert reached is True
        assert "incorrect" in reason

    def test_response_identical_to_baseline_did_not_reach_auth(self) -> None:
        agent = self._agent()
        baseline = "<html><body>login form only, nothing happened here</body></html>"
        reached, reason = agent._brute_force_attempt_reached_auth(
            resp=_HTTPResponse(status=200, body=baseline),
            login_url="http://t/login",
            baseline_body=baseline,
        )
        assert reached is False
        assert "indistinguishable" in reason

    def test_no_response_did_not_reach_auth(self) -> None:
        agent = self._agent()
        reached, _reason = agent._brute_force_attempt_reached_auth(
            _HTTPResponse(status=0, body=""), "http://t/login", "baseline"
        )
        assert reached is False


class TestInconclusiveGate:
    @pytest.mark.asyncio
    async def test_unreached_attempts_yield_inconclusive_not_unprotected(self) -> None:
        """The DVWA ``high`` shape: one attempt authenticated, seven bounced."""
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "none", "protected": false, '
                '"observed_at_attempt": null, "rationale": "all responses look alike"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(0)] + [
            _obs(i, status=302, length=1, auth_reached=False) for i in range(1, 8)
        ]
        ptype, protected, _attempt, rationale = await agent._brute_force_phase3_analyze(
            observations, baseline_ms=200.0
        )
        assert ptype == BruteForceProtectionType.INCONCLUSIVE
        assert protected is True, "INCONCLUSIVE must never emit a finding"
        assert "never reached the authentication handler" in rationale

    @pytest.mark.asyncio
    async def test_emission_requires_the_positive_control(self) -> None:
        """End-to-end: the finding gate is ``auth_reached AND not protected``."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 4))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, params: dict[str, str], **_kw: object) -> _HTTPResponse:
            if not params:  # the unauthenticated baseline fetch
                return _HTTPResponse(status=200, body="<html>login form</html>")
            # Every credential submission is bounced away, exactly like high.
            return _HTTPResponse(status=302, body=" ", headers={"Location": "/index.php"})

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/brute/",
            body="",
            status=200,
            forms=[{**_login_form(), "method": "GET"}],
        )
        findings = await agent._test_brute_force(page)
        assert findings == []


class TestConstantDelayIsProtection:
    @pytest.mark.asyncio
    async def test_flat_penalty_classified_as_delay(self) -> None:
        """DVWA ``medium``: ~2250 ms per attempt against a ~200 ms page load."""
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "none", "protected": false, '
                '"observed_at_attempt": null, "rationale": "times fluctuate narrowly"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [
            _obs(0, time_ms=2241.87),
            _obs(1, time_ms=2257.14),
            _obs(2, time_ms=2262.88),
            _obs(3, time_ms=2236.52),
            _obs(4, time_ms=2244.40),
            _obs(5, time_ms=2243.21),
            _obs(6, time_ms=2254.33),
            _obs(7, time_ms=2259.55),
        ]
        ptype, protected, _a, rationale = await agent._brute_force_phase3_analyze(
            observations, baseline_ms=205.0
        )
        assert ptype == BruteForceProtectionType.DELAY
        assert protected is True
        assert "consistent penalty" in rationale

    @pytest.mark.asyncio
    async def test_unthrottled_attempts_still_emit(self) -> None:
        """DVWA ``low``: ~215 ms attempts against a ~200 ms baseline is no throttle."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i, time_ms=215.0 + i) for i in range(8)]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(
            observations, baseline_ms=200.0
        )
        assert ptype == BruteForceProtectionType.NONE
        assert protected is False


class TestDeterministicGatesTheLLM:
    @pytest.mark.asyncio
    async def test_llm_cannot_clear_a_deterministic_protection(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "none", "protected": false, '
                '"observed_at_attempt": null, "rationale": "looks unprotected to me"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i, retry_after="60" if i == 5 else "") for i in range(8)]
        ptype, protected, _a, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.RATE_LIMIT
        assert protected is True

    @pytest.mark.asyncio
    async def test_llm_may_add_a_protection_the_deterministic_pass_missed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"protection_type": "lockout", "protected": true, '
                '"observed_at_attempt": 4, "rationale": "shape shifts at attempt 4"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        observations = [_obs(i) for i in range(8)]
        ptype, protected, attempt, _r = await agent._brute_force_phase3_analyze(observations)
        assert ptype == BruteForceProtectionType.LOCKOUT
        assert protected is True
        assert attempt == 4
