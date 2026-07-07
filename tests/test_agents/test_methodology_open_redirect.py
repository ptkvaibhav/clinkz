"""Unit tests for the adaptive open-redirect methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (injection-point mapping)   — baseline / variant probes
    Phase 2 (redirect-handling fingerprint) — validator + bypass primitives
    Phase 3 (bypass-type ranking)       — LLM JSON parsing + fallback table
    Phase 4 (payload synthesis)         — LLM JSON parsing + fallback table
    Phase 5 (verification)              — Location / body-redirect check
    Phase 6 (finding emission)          — evidence chain on the Finding
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
    OpenRedirectMethodologyResult,
    RedirectBypassType,
    RedirectPrimitives,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-open-redirect-test",
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
        engagement_id="methodology-open-redirect-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(url: str = "http://example.com/?to=/home") -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=["to"])


def _dvwa_open_redirect_server(level: str):
    """Simulate DVWA's open_redirect module at a given security level.

    A GET with no ``redirect`` value (the harvest seed / index fetch) returns the
    module index whose link carries ``?redirect=info.php`` — the allowlist token
    High requires. A GET carrying a ``redirect`` value applies the level's
    validator and, when accepted, echoes it into the ``Location`` header — exactly
    DVWA's ``header("location: " . $_GET['redirect'])`` shape.

    Ground truth (DVWA cheat sheet): Low accepts any absolute URL; Medium blocks
    ``http(s)://`` (protocol-relative bypass); High requires the target to contain
    the substring ``info.php`` (attacker-URL-with-info.php bypass); Impossible is
    ID-based with no attacker-controlled destination.
    """
    index_html = '<p>Pick a link.</p><a href="?redirect=info.php">User info</a>'

    def _accepts(value: str) -> bool:
        low = value.lower()
        if level == "low":
            return True
        if level == "medium":
            return "http://" not in low and "https://" not in low
        if level == "high":
            return "info.php" in low
        return False  # impossible: destination is not attacker-controlled

    async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
        if "redirect" not in params:
            return _HTTPResponse(status=200, body=index_html)
        value = params["redirect"]
        if level == "impossible":
            # ID-based redirect to a fixed in-site page; the value is ignored.
            return _HTTPResponse(status=302, body="", headers={"Location": "info.php?id=1"})
        if _accepts(value):
            return _HTTPResponse(status=302, body="", headers={"Location": value})
        return _HTTPResponse(status=200, body=index_html)  # blocked → index page

    return fake_get


def _relative_echo_server():
    """Echo the param value into a *relative* same-host ``Location``.

    The redirect lands on an in-site page that merely *contains* the attacker
    string in a query component — never an off-site navigation. The honesty guard
    must treat this as a non-finding (a redirect to an in-site page is not the
    open-redirect finding).
    """
    index_html = '<a href="?redirect=info.php">User info</a>'

    async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
        if "redirect" not in params:
            return _HTTPResponse(status=200, body=index_html)
        return _HTTPResponse(
            status=302, body="", headers={"Location": f"/go?u={params['redirect']}"}
        )

    return fake_get


def _dvwa_high_source_server():
    """DVWA ``source/high.php``: accepts only values containing ``info.php``.

    Models the real DVWA structure where the level handler lives at
    ``source/high.php`` and serves NO links itself (a bare fetch 500s with no
    harvestable token), so the substring-allowlist token can only come from the
    param's own original value (``?redirect=info.php``).
    """

    async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
        if "redirect" not in params:
            return _HTTPResponse(status=500, body="<p>Missing redirect target.</p>")
        value = params["redirect"]
        if "info.php" in value:
            return _HTTPResponse(status=302, body="", headers={"Location": value})
        return _HTTPResponse(status=500, body="<p>You can only redirect to the info page.</p>")

    return fake_get


def _make_dvwa_page(path: str = "/vulnerabilities/open_redirect/") -> PageAnalysis:
    return PageAnalysis(
        url=f"http://dvwa.test{path}?redirect=info.php",
        body="",
        status=200,
        input_params=["redirect"],
    )


# ===========================================================================
# Phase 1 — Injection-point mapping
# ===========================================================================


class TestPhase1InjectionPointMapping:
    @pytest.mark.asyncio
    async def test_no_divergence_not_a_candidate(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="same body")
        )
        is_candidate, _probes = await agent._open_redirect_phase1_injection_point(
            _make_page(), "to", "/home"
        )
        assert is_candidate is False

    @pytest.mark.asyncio
    async def test_appended_url_diverges_marks_candidate(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("to", "")
            if "evil.example" in val:
                return _HTTPResponse(
                    status=302,
                    body="",
                    headers={"Location": "https://evil.example"},
                )
            return _HTTPResponse(status=200, body="welcome")

        agent._http_get = fake_get  # type: ignore[method-assign]
        is_candidate, _probes = await agent._open_redirect_phase1_injection_point(
            _make_page(), "to", "/home"
        )
        assert is_candidate is True


# ===========================================================================
# Phase 2 — Redirect handling fingerprint
# ===========================================================================


class TestPhase2RedirectHandlingFingerprint:
    @pytest.mark.asyncio
    async def test_no_validator_marks_direct_at_proto_relative_working(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("to", "")
            # No validator: the server reflects whatever the param sends.
            return _HTTPResponse(status=302, body="", headers={"Location": val})

        agent._http_get = fake_get  # type: ignore[method-assign]
        # Drive phase 1 first so phase 2 has the baseline.
        _ok, probes = await agent._open_redirect_phase1_injection_point(_make_page(), "to", "/home")
        primitives, _ev = await agent._open_redirect_phase2_fingerprint(
            _make_page(), "to", "/home", probes
        )
        # A plain absolute off-site URL is accepted ⇒ no validator. The genuinely
        # off-site shapes are working; ``appended_url`` stays a relative same-host
        # path, so honest host-resolution does NOT count it as off-site.
        assert "direct" in primitives.working_bypass_primitives
        assert "at_syntax" in primitives.working_bypass_primitives
        assert "protocol_relative" in primitives.working_bypass_primitives
        assert "appended_url" not in primitives.working_bypass_primitives
        assert primitives.validator_type == "none"

    @pytest.mark.asyncio
    async def test_strict_validator_rejects_everything(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            # Always redirect to the same trusted host.
            return _HTTPResponse(status=302, body="", headers={"Location": "/safe-home"})

        agent._http_get = fake_get  # type: ignore[method-assign]
        _ok, probes = await agent._open_redirect_phase1_injection_point(_make_page(), "to", "/home")
        primitives, _ev = await agent._open_redirect_phase2_fingerprint(
            _make_page(), "to", "/home", probes
        )
        assert primitives.validator_type == "strict_or_unknown"
        assert primitives.working_bypass_primitives == []


# ===========================================================================
# Phase 3 — Bypass type ranking
# ===========================================================================


class TestPhase3BypassTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "at_syntax", "rationale": "userinfo bypass"},'
                '{"type": "appended_url", "rationale": "fallback"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._open_redirect_phase3_rank_bypass_types(
            RedirectPrimitives(working_bypass_primitives=["at_syntax", "appended_url"]),
            {},
        )
        assert ranked[0] == RedirectBypassType.AT_SYNTAX
        assert ranked[1] == RedirectBypassType.APPENDED_URL

    @pytest.mark.asyncio
    async def test_fallback_no_validator_picks_direct(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._open_redirect_phase3_rank_bypass_types(
            RedirectPrimitives(
                validator_type="none",
                working_bypass_primitives=["appended_url", "at_syntax"],
            ),
            {},
        )
        assert ranked[0] == RedirectBypassType.DIRECT_REDIRECT


# ===========================================================================
# Phase 4 — Payload synthesis
# ===========================================================================


class TestPhase4PayloadSynthesis:
    @pytest.mark.asyncio
    async def test_llm_advisory_when_primitive_not_confirmed(self) -> None:
        """When phase 2 did NOT confirm the primitive, the LLM synthesis is used."""
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "https://evil.example/llm-path", '
                '"expected_indicator": "evil.example", '
                '"rationale": "appended path"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._open_redirect_phase4_synthesize(
            RedirectBypassType.APPENDED_URL,
            # No confirmed primitive → LLM is consulted (advisory path).
            RedirectPrimitives(working_bypass_primitives=[]),
        )
        assert synth is not None
        assert synth["payload"] == "https://evil.example/llm-path"

    @pytest.mark.asyncio
    async def test_deterministic_preferred_when_primitive_confirmed(self) -> None:
        """LESSONS #18/#28: a confirmed primitive uses the deterministic build,
        NOT the LLM guess — even when the LLM returns valid (but mangled) JSON.
        """
        llm = _ScriptedLLM(
            answers=[
                # A live-LLM-style mangle: valid JSON, but a dead %00 appended.
                '{"payload": "https://evil.example/%00", '
                '"expected_indicator": "evil.example", "rationale": "guess"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._open_redirect_phase4_synthesize(
            RedirectBypassType.APPENDED_URL,
            RedirectPrimitives(working_bypass_primitives=["appended_url"]),
        )
        assert synth is not None
        # The deterministic build wins — the LLM's %00 mangle is not used.
        assert synth["payload"] == "https://evil.example/"
        # The LLM was not consulted for the confirmed primitive.
        assert llm.prompts == []

    @pytest.mark.asyncio
    async def test_fallback_synthesis_table(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._open_redirect_phase4_synthesize(
            RedirectBypassType.AT_SYNTAX,
            RedirectPrimitives(working_bypass_primitives=["at_syntax"]),
        )
        assert synth is not None
        assert "@evil.example" in synth["payload"]


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_attacker_location_verifies(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=302, body="", headers={"Location": "https://evil.example"}
            )
        )
        verified, observed = await agent._open_redirect_phase5_verify(
            _make_page(), "to", "https://evil.example"
        )
        assert verified is True
        assert observed is not None
        assert "evil.example" in observed

    @pytest.mark.asyncio
    async def test_safe_location_does_not_verify(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=302, body="", headers={"Location": "/safe-home"})
        )
        verified, _observed = await agent._open_redirect_phase5_verify(
            _make_page(), "to", "https://evil.example"
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_200_with_attacker_location_does_not_verify(self) -> None:
        """A ``Location`` header on a status-200 response is not a server redirect."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="", headers={"Location": "https://evil.example"}
            )
        )
        verified, _observed = await agent._open_redirect_phase5_verify(
            _make_page(), "to", "https://evil.example"
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_body_meta_refresh_does_not_confirm_via_phase5(self) -> None:
        """Body-level meta refresh (status 200) never rides the 3xx confirm path."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body='<meta http-equiv="refresh" content="0; url=https://evil.example/path">',
            )
        )
        verified, _observed = await agent._open_redirect_phase5_verify(
            _make_page(), "to", "https://evil.example/path"
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_dom_signal_detects_body_meta_refresh_separately(self) -> None:
        """The demoted DOM signal detects a body meta refresh to the attacker host."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body='<meta http-equiv="refresh" content="0; url=https://evil.example/path">',
            )
        )
        dom_target = await agent._open_redirect_dom_signal(
            _make_page(), "to", "https://evil.example/path"
        )
        assert dom_target is not None
        assert "evil.example" in dom_target


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = OpenRedirectMethodologyResult(
            phases_completed=6,
            primitives=RedirectPrimitives(
                validator_type="none",
                working_bypass_primitives=["appended_url"],
                redirect_status_form="3xx_location",
            ),
            bypass_type=RedirectBypassType.APPENDED_URL,
            synthesized_payload="https://evil.example/",
            redirect_target_observed="https://evil.example/",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._open_redirect_phase6_emit("http://example.com/redirect", "to", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "bypass_type=appended_url" in joined
        assert "evil.example" in joined
        assert finding.severity.value == "medium"

    def test_dom_redirect_is_lower_severity(self) -> None:
        """A body-level (DOM) redirect emits a lower-severity finding than a 3xx."""
        agent = _make_agent()
        result = OpenRedirectMethodologyResult(
            phases_completed=6,
            primitives=RedirectPrimitives(redirect_status_form="body_redirect"),
            bypass_type=RedirectBypassType.DIRECT_REDIRECT,
            synthesized_payload="https://evil.example/",
            redirect_target_observed="https://evil.example/",
            verified=True,
            verification_strength="dom_redirect",
            dom_redirect=True,
        )
        finding = agent._open_redirect_phase6_emit("http://example.com/redirect", "to", result)
        assert finding.severity.value == "low"
        assert "DOM/client-side" in finding.title


# ===========================================================================
# Confirm-honesty — the deterministic 3xx + attacker-host predicate
# ===========================================================================


class TestConfirmHonestyPredicate:
    """The load-bearing predicate: confirm ONLY on a 3xx whose Location host is
    the attacker host. Same-host echoes and javascript:/data: schemes never
    confirm; a body-only redirect never rides the 3xx path.
    """

    def test_absolute_attacker_url_is_attacker(self) -> None:
        agent = _make_agent()
        assert (
            agent._redirect_target_is_attacker("https://evil.example/", "http://t.test/x") is True
        )

    def test_protocol_relative_is_attacker(self) -> None:
        agent = _make_agent()
        assert agent._redirect_target_is_attacker("//evil.example/", "http://t.test/x") is True

    def test_same_host_containing_attacker_is_not(self) -> None:
        agent = _make_agent()
        # A same-host path that merely CONTAINS the attacker string is in-site.
        assert (
            agent._redirect_target_is_attacker("/go?u=https://evil.example", "http://t.test/x")
            is False
        )

    def test_javascript_and_data_schemes_never_confirm(self) -> None:
        agent = _make_agent()
        assert agent._redirect_target_is_attacker("javascript:alert(1)", "http://t.test/x") is False
        assert (
            agent._redirect_target_is_attacker(
                "data:text/html,<script>alert(1)</script>", "http://t.test/x"
            )
            is False
        )

    @pytest.mark.asyncio
    async def test_javascript_location_does_not_verify(self) -> None:
        """Even a 3xx whose Location is a javascript: URI is not a host redirect."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=302, body="", headers={"Location": "javascript:alert(1)"}
            )
        )
        verified, _observed = await agent._open_redirect_phase5_verify(
            _make_page(), "to", "javascript:alert(1)"
        )
        assert verified is False


# ===========================================================================
# Integration — full _test_open_redirect driving all six phases
# ===========================================================================


class TestOpenRedirectMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_appended_url_open_redirect_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("to", "")
            return _HTTPResponse(status=302, body="", headers={"Location": val})

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        findings = await agent._test_open_redirect(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "bypass_type=" in joined


# ===========================================================================
# FIX 3 — allowlist bypass (token harvested from the app)
# ===========================================================================


class TestOpenRedirectAllowlistBypass:
    def test_redirect_param_recognition(self) -> None:
        assert ExploitAgent._is_redirect_param("to") is True
        assert ExploitAgent._is_redirect_param("redirect") is True
        assert ExploitAgent._is_redirect_param("returnUrl") is True
        assert ExploitAgent._is_redirect_param("q") is False

    def test_bypass_payloads_embed_token_and_target_attacker(self) -> None:
        token = "https://github.com/juice-shop/juice-shop"
        payloads = ExploitAgent._allowlist_bypass_payloads(token)
        # Every payload carries the allowlisted token AND points at the attacker.
        assert all("evil.example" in p for p in payloads)
        assert any(p == f"https://evil.example/?x={token}" for p in payloads)
        # The @-userinfo form strips the scheme from the token's host portion.
        assert any(p.endswith("@evil.example") for p in payloads)

    @pytest.mark.asyncio
    async def test_harvest_tokens_from_redirect_links(self) -> None:
        """Absolute URLs the app wraps in its own redirect param are harvested."""
        agent = _make_agent()
        bundle = (
            'a.href="redirect?to=https://github.com/juice-shop/juice-shop";'
            'b="redirect?to=https://blockchain.info/address/1AbKfg"'
        )

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            if url.endswith("/"):
                return _HTTPResponse(status=200, body='<script src="/main.js"></script>')
            if url.endswith("main.js"):
                return _HTTPResponse(status=200, body=bundle)
            return _HTTPResponse(status=404, body="")

        agent._http_get = fake_get  # type: ignore[method-assign]
        tokens = await agent._harvest_allowlist_tokens(_make_page())
        assert "https://github.com/juice-shop/juice-shop" in tokens

    @pytest.mark.asyncio
    async def test_allowlist_bypass_confirms_via_redirect(self) -> None:
        """Blocked generic probes, but a token-bearing payload redirects to attacker.

        Mirrors Juice Shop /redirect?to=: a substring allowlist 406s a naive
        payload but accepts one containing an allowlisted token, while the
        Location still points at the attacker host.
        """
        agent = _make_agent()
        allowlisted = "https://github.com/juice-shop/juice-shop"
        bundle = f'x.href="redirect?to={allowlisted}"'

        async def fake_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            # Harvest fetches: root shell + bundle.
            if params == {} and url.endswith("/"):
                return _HTTPResponse(status=200, body='<script src="/m.js"></script>')
            if params == {} and url.endswith("m.js"):
                return _HTTPResponse(status=200, body=bundle)
            # Redirect probes: only a target containing the allowlisted token is
            # accepted (302 to the attacker); everything else is blocked (406).
            to = params.get("to", "")
            if allowlisted in to:
                return _HTTPResponse(status=302, body="", headers={"Location": to})
            return _HTTPResponse(status=406, body="Unrecognized target URL for redirect")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/redirect?to=/home")
        findings = await agent._test_open_redirect(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "allowlist_bypass" in joined
        assert "evil.example" in joined

    @pytest.mark.asyncio
    async def test_no_tokens_means_no_finding(self) -> None:
        """If no allowlisted token can be harvested, the bypass yields nothing."""
        agent = _make_agent()

        async def fake_get(url: str, params: dict[str, str]) -> _HTTPResponse:
            if params == {}:
                return _HTTPResponse(status=200, body="<html>no links</html>")
            return _HTTPResponse(status=406, body="blocked")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/redirect?to=/home")
        findings = await agent._test_open_redirect(page)
        assert findings == []


# ===========================================================================
# DVWA security levels — Low / Medium / High confirm; Impossible is a non-finding
# ===========================================================================


class TestDVWALevels:
    """End-to-end ``_test_open_redirect`` against each DVWA open_redirect level.

    Proves the methodology confirms the ground-truth bypass for each exploitable
    level (cross-checked against the DVWA cheat sheet) and honestly emits nothing
    for the unexploitable Impossible level and for a same-host phantom redirect.
    """

    @pytest.mark.asyncio
    async def test_low_confirms_direct_offsite(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _dvwa_open_redirect_server("low")  # type: ignore[method-assign]
        findings = await agent._test_open_redirect(_make_dvwa_page())
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        # Honesty: confirmation is the off-site host, not a same-host echo.
        assert "redirect_target_observed=https://evil.example" in joined

    @pytest.mark.asyncio
    async def test_medium_confirms_protocol_relative(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _dvwa_open_redirect_server("medium")  # type: ignore[method-assign]
        findings = await agent._test_open_redirect(_make_dvwa_page())
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "bypass_type=protocol_relative" in joined
        assert "//evil.example" in joined

    @pytest.mark.asyncio
    async def test_high_confirms_substring_allowlist_bypass(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _dvwa_open_redirect_server("high")  # type: ignore[method-assign]
        findings = await agent._test_open_redirect(_make_dvwa_page())
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "bypass_type=allowlist_bypass" in joined
        # The harvested substring token rides in the off-site attacker URL.
        assert "info.php" in joined
        assert "evil.example" in joined

    @pytest.mark.asyncio
    async def test_high_via_original_value_token_only(self) -> None:
        """High confirms when the only allowlist token is the param's own value.

        Mirrors DVWA's real ``source/high.php``: the handler serves no links, so
        the ``info.php`` substring is recovered from the param's ``?redirect=``
        value rather than a harvested page.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _dvwa_high_source_server()  # type: ignore[method-assign]
        page = _make_dvwa_page("/vulnerabilities/open_redirect/source/high.php")
        findings = await agent._test_open_redirect(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "bypass_type=allowlist_bypass" in joined
        assert "evil.example" in joined

    @pytest.mark.asyncio
    async def test_impossible_is_a_non_finding(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _dvwa_open_redirect_server("impossible")  # type: ignore[method-assign]
        findings = await agent._test_open_redirect(_make_dvwa_page())
        assert findings == []

    @pytest.mark.asyncio
    async def test_same_host_phantom_is_not_confirmed(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 12))
        agent._methodology_llm = agent.llm
        agent._http_get = _relative_echo_server()  # type: ignore[method-assign]
        findings = await agent._test_open_redirect(_make_dvwa_page())
        assert findings == []
