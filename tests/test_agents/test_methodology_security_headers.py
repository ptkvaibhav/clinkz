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

        assert llm.prompts == []
        assert llm.answers, "the scripted answer must still be unconsumed"
        # And the verdict is the deterministic one, not the model's.
        assert weak == [("Content-Security-Policy", "permissive: unsafe-inline")]
        assert "Strict-Transport-Security" in missing
        assert sev == HeaderWeaknessSeverity.MEDIUM
        assert "Deterministic analysis" in rationale

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
# Phase 3 — version-disclosing banners (ported out of the LLM path)
# ===========================================================================

#: The header set DVWA serves, byte-identical at every security level. Taken
#: from the recorded phase-2 observation, not invented: this exact pair is what
#: the LLM path reported at `impossible` and omitted at the other three levels.
_DVWA_OBSERVED: dict[str, str] = {
    "server": "Apache/2.4.67 (Debian)",
    "x-powered-by": "PHP/8.5.6",
}

_DVWA_LEVELS = ("low", "medium", "high", "impossible")


class TestVersionDisclosingBanners:
    @pytest.mark.asyncio
    async def test_server_and_x_powered_by_are_flagged_weak(self) -> None:
        agent = _make_agent()
        _m, weak, _s, _r = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", dict(_DVWA_OBSERVED)
        )
        assert ("Server", "discloses server software and version") in weak
        assert ("X-Powered-By", "discloses application technology") in weak

    @pytest.mark.asyncio
    async def test_a_versionless_server_banner_is_not_a_finding(self) -> None:
        """`Server: cloudflare` names software, not a build to look a CVE up in."""
        agent = _make_agent()
        _m, weak, _s, _r = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", {"server": "cloudflare"}
        )
        assert not any(w[0] == "Server" for w in weak)

    @pytest.mark.asyncio
    async def test_x_powered_by_needs_no_version(self) -> None:
        """The header's only function is to name the stack, so presence is it."""
        agent = _make_agent()
        _m, weak, _s, _r = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", {"x-powered-by": "Express"}
        )
        assert ("X-Powered-By", "discloses application technology") in weak

    @pytest.mark.asyncio
    async def test_banners_do_not_move_the_severity_rollup(self) -> None:
        agent = _make_agent()
        _m, _w, with_banners, _r = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", dict(_DVWA_OBSERVED)
        )
        _m2, _w2, without, _r2 = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", {}
        )
        assert with_banners == without


class TestLadderInvariance:
    """A byte-identical observation must produce a byte-identical verdict.

    This is strictly stronger than the finding-count comparison the DVWA ladder
    used to be graded on. A count can match while the *contents* differ, and the
    defect this replaces did exactly that: on the same observation the class
    reported `weak=[]` at low/medium/high and `weak=['Server','X-Powered-By']`
    at impossible, so the ladder read as a two-finding posture regression that
    was really the model varying.
    """

    @pytest.mark.asyncio
    async def test_all_four_levels_produce_identical_header_findings(self) -> None:
        verdicts = []
        for _level in _DVWA_LEVELS:
            # A fresh agent per level: the real ladder is four engagements, and
            # sharing one agent would let per-instance dedup state mask drift.
            agent = _make_agent()
            missing, weak, severity, _rationale = await agent._security_headers_phase3_analyze(
                "http://localhost:8080/", dict(_DVWA_OBSERVED)
            )
            verdicts.append((tuple(missing), tuple(weak), severity))

        assert len(set(verdicts)) == 1, dict(zip(_DVWA_LEVELS, verdicts, strict=True))

    @pytest.mark.asyncio
    async def test_the_shared_verdict_is_pinned(self) -> None:
        """Identical-to-each-other is not enough — four identical wrongs pass it."""
        agent = _make_agent()
        missing, weak, severity, _r = await agent._security_headers_phase3_analyze(
            "http://localhost:8080/", dict(_DVWA_OBSERVED)
        )
        assert missing == [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        assert weak == [
            ("Server", "discloses server software and version"),
            ("X-Powered-By", "discloses application technology"),
        ]
        assert severity == HeaderWeaknessSeverity.MEDIUM


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

    def test_dedup_is_case_insensitive_on_header_name(self) -> None:
        """BUG 4: the LLM emits header names with inconsistent casing across
        pages ("Content-Security-Policy" vs "content-security-policy"), which a
        case-sensitive (origin, header) key let emit twice. The same origin's
        header must collapse to one finding regardless of casing — including a
        header reported missing on one page and weak on another."""
        agent = _make_agent()
        title_case = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/",
            missing_headers=["Content-Security-Policy"],
            severity_rollup=HeaderWeaknessSeverity.MEDIUM,
        )
        lower_case = SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://example.com",
            observed_url="http://example.com/vulnerabilities/csp/",
            headers_observed={"content-security-policy": "script-src 'self'"},
            weak_headers=[("content-security-policy", "no default-src")],
            severity_rollup=HeaderWeaknessSeverity.HIGH,
        )
        first = agent._security_headers_phase4_emit(title_case)
        second = agent._security_headers_phase4_emit(lower_case)
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
# G20 — an origin-level fact is addressed by its origin
# ===========================================================================


class TestG20FindingTargetIsTheOrigin:
    """12 of 16 flaky entries in one ladder came from this one line.

    This method emits per (origin, header) and the first URL to reach it wins
    the dedup — but the finding recorded THAT URL as its target. Three identical
    LOW engagements measured the same seven origin-level headers and reported
    them against three different addresses:

        run 1  http://172.20.0.2/
        run 2  http://172.20.0.2/hackable/uploads/
        run 3  http://172.20.0.2/  (missing) + http://172.20.0.2  (weak)

    Same origin, same headers, same severity — three keys. The plan reached a
    different page first, and a concurrent crawl reaches a different page first
    every run. Header hygiene is a property of the origin, so the origin is the
    address; the page that was measured stays in the evidence as provenance.
    """

    # The three addresses the live runs actually recorded.
    LIVE_OBSERVED_URLS = (
        "http://172.20.0.2/",
        "http://172.20.0.2/hackable/uploads/",
        "http://172.20.0.2",
    )

    @staticmethod
    def _result(observed_url: str) -> SecurityHeadersMethodologyResult:
        return SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin="http://172.20.0.2",
            observed_url=observed_url,
            headers_observed={"server": "Apache/2.4.65", "x-powered-by": "PHP/8.5.6"},
            missing_headers=["Content-Security-Policy"],
            weak_headers=[("Server", "discloses server software")],
            severity_rollup=HeaderWeaknessSeverity.MEDIUM,
            rationale="origin-level posture",
        )

    def test_the_target_is_identical_whichever_page_was_measured_first(self) -> None:
        """A fresh agent per run, exactly as three engagements are three runs."""
        keys = set()
        for observed_url in self.LIVE_OBSERVED_URLS:
            agent = _make_agent()
            findings = agent._security_headers_phase4_emit(self._result(observed_url))
            assert len(findings) == 2
            keys.add(tuple(sorted((f.title, f.target) for f in findings)))
        assert len(keys) == 1, f"the finding key still varies with the measured page: {keys}"

    def test_the_target_is_the_origin_not_a_page(self) -> None:
        agent = _make_agent()
        findings = agent._security_headers_phase4_emit(
            self._result("http://172.20.0.2/hackable/uploads/")
        )
        assert {f.target for f in findings} == {"http://172.20.0.2"}
        for finding in findings:
            assert "hackable" not in finding.target
            assert "hackable" not in finding.title

    def test_the_measured_page_survives_as_provenance(self) -> None:
        """Dropping it would be the opposite error — the reader must still be
        able to reproduce the exact request the observation came from."""
        agent = _make_agent()
        findings = agent._security_headers_phase4_emit(
            self._result("http://172.20.0.2/hackable/uploads/")
        )
        for finding in findings:
            blob = "\n".join(finding.evidence)
            assert "GET http://172.20.0.2/hackable/uploads/" in blob
            assert "origin=http://172.20.0.2" in blob

    LIVE_CSP = "default-src 'self' 'unsafe-inline'"

    def _analysis(self) -> tuple[list[str], list[tuple[str, str]], HeaderWeaknessSeverity, str]:
        """What the analysis said on DVWA's one CSP-serving page."""
        return (
            ["X-Content-Type-Options", "Referrer-Policy"],
            [("Content-Security-Policy", "allows unsafe-inline")],
            HeaderWeaknessSeverity.LOW,
            "csp present but permissive",
        )

    def test_a_header_only_a_deep_page_sets_is_missing_for_the_origin(self) -> None:
        """The second half of the same defect: the ADDRESS was origin-scoped but
        the VERDICT was still whichever page won the race.

        DVWA serves a CSP on `/vulnerabilities/csp/` and nowhere else. The run
        that measured that page first reported the origin's CSP "weak" (at LOW
        severity); the two that reached `/` first reported it "missing". A header
        one deep page sets does not protect the origin."""
        agent = _make_agent()
        missing, weak, severity, rationale = agent._gate_security_header_analysis(
            "http://172.20.0.2/vulnerabilities/csp/",
            {"content-security-policy": self.LIVE_CSP},
            self._analysis(),
            root_header_names={"server", "x-powered-by", "content-type"},
        )
        assert "Content-Security-Policy" in missing
        assert [w[0] for w in weak] == []
        assert "NOT on the origin root" in rationale
        assert severity == HeaderWeaknessSeverity.MEDIUM, "no CSP on the origin is medium"

    def test_a_header_the_root_does_set_stays_weak(self) -> None:
        """The control — this must not turn every weak verdict into a missing
        one. An origin that really serves a permissive CSP keeps that verdict."""
        agent = _make_agent()
        missing, weak, _severity, _rationale = agent._gate_security_header_analysis(
            "http://172.20.0.2/vulnerabilities/csp/",
            {"content-security-policy": self.LIVE_CSP},
            self._analysis(),
            root_header_names={"content-security-policy", "server"},
        )
        assert "Content-Security-Policy" not in missing
        assert [w[0] for w in weak] == ["Content-Security-Policy"]

    def test_no_root_evidence_never_vetoes(self) -> None:
        """When the root could not be fetched there is no origin evidence, and
        absence of evidence never drives a verdict."""
        agent = _make_agent()
        _missing, weak, _severity, _rationale = agent._gate_security_header_analysis(
            "http://172.20.0.2/vulnerabilities/csp/",
            {"content-security-policy": self.LIVE_CSP},
            self._analysis(),
            root_header_names=None,
        )
        assert [w[0] for w in weak] == ["Content-Security-Policy"]

    def test_the_verdict_is_the_same_whichever_page_is_measured(self) -> None:
        """The property the ladder measures, asserted directly: every page on the
        origin reaches the same origin-level verdict for the same header."""
        agent = _make_agent()
        root_names = {"server", "x-powered-by", "content-type"}
        verdicts = set()
        for url, headers in (
            ("http://172.20.0.2/", {}),
            ("http://172.20.0.2/vulnerabilities/csp/", {"content-security-policy": self.LIVE_CSP}),
            ("http://172.20.0.2/hackable/uploads/", {}),
        ):
            analysis = (
                (["Content-Security-Policy"], [], HeaderWeaknessSeverity.MEDIUM, "no csp")
                if not headers
                else self._analysis()
            )
            missing, weak, _s, _r = agent._gate_security_header_analysis(
                url, headers, analysis, root_header_names=root_names
            )
            verdicts.add(
                ("missing" if "Content-Security-Policy" in missing else None)
                or ("weak" if any(w[0] == "Content-Security-Policy" for w in weak) else "absent")
            )
        assert verdicts == {"missing"}, verdicts

    def test_the_origin_itself_is_derived_deterministically(self) -> None:
        """scheme://netloc — no path, no trailing slash, no query. Two pages on
        one host can never produce two origin strings."""
        agent = _make_agent()
        origins = {
            agent._security_headers_origin(url)
            for url in (
                "http://172.20.0.2",
                "http://172.20.0.2/",
                "http://172.20.0.2/hackable/uploads/",
                "http://172.20.0.2/vulnerabilities/xss_r/?name=x#frag",
            )
        }
        assert origins == {"http://172.20.0.2"}


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
