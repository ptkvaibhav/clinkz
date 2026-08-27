"""Unit tests for the adaptive IDOR methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (reference-point mapping)  — candidacy by lexical signal +
                                         response-shape evidence
    Phase 2 (authz-model fingerprint)  — id format, predictability,
                                         authz-check presence
    Phase 3 (exploitation-type ranking) — LLM JSON parsing + fallback
    Phase 4 (reference synthesis)       — LLM JSON parsing + fallback
    Phase 5 (verification)              — response-shape divergence
    Phase 6 (finding emission)          — evidence chain on the Finding
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._idor_oracle import TIER_MULTI_ROLE
from clinkz.agents._plan_ranking import attempt_window
from clinkz.agents._principal import ANONYMOUS, Principal
from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    IDORExploitationType,
    IDORMethodologyResult,
    IDORPrimitives,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-idor-test",
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
        engagement_id="methodology-idor-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(
    url: str = "http://example.com/account?id=1", params: list[str] | None = None
) -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=params or ["id"])


# ---------------------------------------------------------------------------
# Phase-5 harness: a target that answers by (reference, who is asking)
# ---------------------------------------------------------------------------


# Peers, and RANKED as peers. A crossing arm is evidence only while the caller
# does not outrank the owner, so an undeclared rank bounds every one of these
# verdicts to a lead — see ``privilege_order``. Equal rank is the cleanest
# crossing there is: no role either of them holds authorizes reading the
# other's record.
ALICE = Principal(role="alice", username="alice", cookies={"sid": "a"}, primary=True, privilege=0)
BOB = Principal(role="bob", username="bob", cookies={"sid": "b"}, privilege=0)


def _who(agent: ExploitAgent) -> str:
    """The identity the agent's carrier is currently sending as."""
    if agent._principal_isolation:
        return agent._active_principal.role if agent._active_principal else ANONYMOUS
    return next((p.role for p in agent._principals if p.primary), "alice")


def _by_reference(
    agent: ExploitAgent,
    responder: Callable[[str, str], _HTTPResponse],
) -> list[tuple[str, str]]:
    """Route every probe through *responder*, recording ``(reference, principal)``.

    A single-return mock cannot exercise the four arms: they differ only in what
    they carry and as whom, so a target that answers the same thing to everyone
    makes "A read B's record" and "this page is public" indistinguishable — the
    exact confusion the oracle exists to resolve.
    """
    seen: list[tuple[str, str]] = []

    async def _send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        who = _who(agent)
        seen.append((value, who))
        return responder(value, who)

    agent._send_probe = _send_probe  # type: ignore[method-assign]
    return seen


def _peer_records(reference: str, who: str) -> _HTTPResponse:
    """A record store: id 1 is alice's, id 2 is bob's, nothing else exists.

    Anonymous is redirected to login, so the object is not public; an unknown
    reference 404s, so the never-issued control refuses. Both are properties of
    an ordinary application and both are what make the crossing observation mean
    something.
    """
    records = {
        "1": "user: alice email: alice@x.example role: user dob: 1990-01-01 region: us",
        "2": (
            "user: bob email: bob@x.example role: user "
            "dob: 1985-02-02 region: eu phone: +44-12345 city: london"
        ),
    }
    if reference not in records:
        return _HTTPResponse(status=404, body="no such user", headers={})
    if who == ANONYMOUS:
        return _HTTPResponse(status=302, body="", headers={})
    return _HTTPResponse(status=200, body=records[reference], headers={})


# ===========================================================================
# Phase 1 — Reference point mapping
# ===========================================================================


class TestPhase1ReferencePointMapping:
    @pytest.mark.asyncio
    async def test_name_signal_alone_marks_candidate(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="some content")
        )
        is_candidate, ev = await agent._idor_phase1_reference_point(_make_page(), "id", "1")
        assert is_candidate is True
        assert ev["name_signal"] is True

    @pytest.mark.asyncio
    async def test_no_name_signal_but_increment_diverges_is_candidate(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("q", "")
            if val == "1":
                return _HTTPResponse(
                    status=200,
                    body=(
                        "user: alice email: alice@x.example role: user dob: 1990-01-01 region: us"
                    ),
                )
            # Much longer response so divergence threshold (10 bytes) clears.
            return _HTTPResponse(
                status=200,
                body=(
                    "user: bob email: bob@x.example role: admin "
                    "dob: 1985-02-02 region: eu phone: +44-12345"
                ),
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(url="http://example.com/?q=1", body="", status=200, input_params=["q"])
        is_candidate, ev = await agent._idor_phase1_reference_point(page, "q", "1")
        assert is_candidate is True
        assert ev["name_signal"] is False

    @pytest.mark.asyncio
    async def test_no_signal_and_scalar_body_not_a_candidate(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="OK")
        )
        page = PageAnalysis(
            url="http://example.com/?q=hello", body="", status=200, input_params=["q"]
        )
        is_candidate, _ev = await agent._idor_phase1_reference_point(page, "q", "hello")
        assert is_candidate is False


# ===========================================================================
# Phase 2 — Authz model fingerprint
# ===========================================================================


class TestPhase2AuthzModelFingerprint:
    @pytest.mark.asyncio
    async def test_numeric_id_sequential_no_authz(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val in ("1", "2", "11"):
                return _HTTPResponse(
                    status=200,
                    body=f"user: u{val} email: u{val}@x role: user",
                )
            return _HTTPResponse(status=200, body="user: u? email: ? role: user")

        agent._http_get = fake_get  # type: ignore[method-assign]
        phase1_ev = {"increment_diverged": True, "baseline_body": "user: u1 email: u1@x"}
        primitives, _ev = await agent._idor_phase2_fingerprint(_make_page(), "id", "1", phase1_ev)
        assert primitives.id_format == "numeric"
        assert primitives.predictability == "sequential"
        assert primitives.authz_check_present is False

    @pytest.mark.asyncio
    async def test_uuid_format_random(self) -> None:
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="resource")
        )
        primitives, _ev = await agent._idor_phase2_fingerprint(
            _make_page(),
            "id",
            "550e8400-e29b-41d4-a716-446655440000",
            {"increment_diverged": False, "baseline_body": "resource"},
        )
        assert primitives.id_format == "uuid"
        assert primitives.predictability == "random_uuid"

    @pytest.mark.asyncio
    async def test_authz_check_present_when_unauthorized(self) -> None:
        agent = _make_agent()

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val == "99999999":
                return _HTTPResponse(status=403, body="forbidden")
            return _HTTPResponse(status=200, body="user resource")

        agent._http_get = fake_get  # type: ignore[method-assign]
        primitives, _ev = await agent._idor_phase2_fingerprint(
            _make_page(),
            "id",
            "1",
            {"increment_diverged": True, "baseline_body": "user resource"},
        )
        assert primitives.authz_check_present is True


# ===========================================================================
# Phase 3 — Exploitation type ranking
# ===========================================================================


class TestPhase3ExploitationTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "horizontal", "rationale": "peer"},'
                '{"type": "vertical", "rationale": "fallback"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            {},
        )
        # The model orders the SUPPORTED block; the unsupported tail keeps the
        # deterministic order, because there the model is ranking hypotheses
        # against no observation at all.
        assert ranking.ranked[0] == IDORExploitationType.HORIZONTAL
        assert IDORExploitationType.VERTICAL in ranking.ranked

    @pytest.mark.asyncio
    async def test_fallback_sequential_ranks_horizontal_first(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(
                id_format="numeric",
                predictability="sequential",
                increment_diverged=True,
            ),
            {},
        )
        assert ranking.ranked[0] == IDORExploitationType.HORIZONTAL

    @pytest.mark.asyncio
    async def test_fallback_authz_present_ranks_pollution(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(
                id_format="numeric",
                predictability="opaque",
                authz_check_present=True,
            ),
            {},
        )
        assert IDORExploitationType.PARAMETER_POLLUTION in ranking.ranked
        assert IDORExploitationType.PARAMETER_POLLUTION in ranking.supported

    @pytest.mark.asyncio
    async def test_an_opaque_identifier_never_withholds_horizontal(self) -> None:
        """The single line that dropped 41 of the corpus's 49 IDOR confirmations.

        ``predictability == "opaque"`` says you cannot GUESS the next identifier.
        It says nothing about whether the object behind a known one is protected,
        and 1,087 of the 1,186 gate-closed IDOR fingerprints in the corpus are
        opaque while ``horizontal`` accounts for 48 of the 49 confirmations.
        Phase 3 is reached only past the divergence gate, so a reference probe
        has already answered differently from the baseline.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        ranking = await agent._idor_phase3_rank_exploitation_types(
            IDORPrimitives(
                id_format="numeric",
                predictability="opaque",
                increment_diverged=False,
                unauth_status_observed=200,
            ),
            {},
        )
        window = attempt_window(ranking.ranked, ranking.supported)
        assert window[0] == IDORExploitationType.HORIZONTAL
        assert IDORExploitationType.HORIZONTAL in ranking.supported
        # No authz check and an unauthenticated 200 is the function-level
        # signal, and the corpus's one function_level confirmation has exactly
        # this fingerprint — so it must be inside the window too.
        assert IDORExploitationType.FUNCTION_LEVEL in window


# ===========================================================================
# Phase 4 — Reference synthesis
# ===========================================================================


class TestPhase4ReferenceSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(answers=['{"reference": "42", "rationale": "next-id peer"}'])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.HORIZONTAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "41",
        )
        assert synth is not None
        assert synth["reference"] == "42"

    @pytest.mark.asyncio
    async def test_fallback_horizontal_numeric_increments(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.HORIZONTAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "5",
        )
        assert synth is not None
        assert synth["reference"] == "6"

    @pytest.mark.asyncio
    async def test_fallback_vertical_numeric_uses_id_1(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._idor_phase4_synthesize(
            IDORExploitationType.VERTICAL,
            IDORPrimitives(id_format="numeric", predictability="sequential"),
            "5",
        )
        assert synth is not None
        assert synth["reference"] == "1"


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    """Phase 5 is now four dispatched arms, so every test needs a real target.

    The old tests mocked ``_http_get`` with one canned response, which the
    four-arm oracle correctly refuses: an endpoint that returns the same body to
    every reference and every principal is a page, not a boundary.
    """

    @staticmethod
    def _peer_target(reference: str, who: str) -> _HTTPResponse:
        records = {
            "1": "user: alice email: alice@x.example role: user dob: 1990-01-01",
            "2": "user: bob email: bob@x.example role: user dob: 1985-02-02",
        }
        if reference not in records:
            return _HTTPResponse(status=404, body="not found", headers={})
        if who == ANONYMOUS:
            return _HTTPResponse(status=302, body="", headers={})
        return _HTTPResponse(status=200, body=records[reference], headers={})

    @pytest.mark.asyncio
    async def test_a_peer_record_attributed_to_a_second_principal_verifies(self) -> None:
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(agent, self._peer_target)
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "user: alice"},
            IDORPrimitives(id_format="numeric", authz_check_present=True),
            "1",
        )
        assert verdict.confirmed is True, verdict.detail
        assert control is not None and control.satisfied

    @pytest.mark.asyncio
    async def test_identical_response_does_not_verify(self) -> None:
        """One body for every reference: the control cannot refuse.

        The anonymous arm is refused so the verdict lands on the CONTROL rather
        than on "the object is public" — two different facts about a target, and
        this test is about the control.
        """
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda _ref, who: (
                _HTTPResponse(status=302, body="", headers={})
                if who == ANONYMOUS
                else _HTTPResponse(status=200, body="same exact body", headers={})
            ),
        )
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "same exact body"},
            IDORPrimitives(id_format="numeric", authz_check_present=True),
            "1",
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == "never_sent_control_did_not_refuse"

    @pytest.mark.asyncio
    async def test_403_does_not_verify(self) -> None:
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda _ref, _who: _HTTPResponse(status=403, body="forbidden", headers={}),
        )
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "user: alice"},
            IDORPrimitives(id_format="numeric", authz_check_present=True),
            "1",
        )
        assert verdict.confirmed is False
        assert control is None, "no candidate resolved, so there was nothing to control"


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = IDORMethodologyResult(
            phases_completed=6,
            primitives=IDORPrimitives(
                id_format="numeric",
                predictability="sequential",
                increment_diverged=True,
            ),
            exploitation_type=IDORExploitationType.HORIZONTAL,
            synthesized_reference="2",
            rationale="peer-resource increment",
            indicator_observed="response shape matched baseline with different content",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._idor_phase6_emit("http://example.com/account", "id", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "exploitation_type=horizontal" in joined
        assert "reference=2" in joined
        assert finding.severity.value == "high"


# ===========================================================================
# Integration — full _test_idor driving all six phases
# ===========================================================================


class TestIDORMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_authbypass_style_horizontal_idor(self) -> None:
        """A genuine horizontal IDOR end-to-end, with a second principal.

        All six phases drive to a finding because every arm cleared AND the
        record A was served is the one B's own authorized read returns. With one
        principal the same target produces a LEAD — asserted below, because the
        difference between those two outcomes is the whole of PART 3.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm
        agent._principals = (ALICE, BOB)
        _by_reference(agent, _peer_records)

        findings = await agent._test_idor(_make_page())
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "exploitation_type=" in joined
        assert f"idor_tier={TIER_MULTI_ROLE}" in joined
        assert "never_sent_control=refused" in joined
        assert "Arm crossing:" in joined
        assert "Arm owner_read:" in joined

    @pytest.mark.asyncio
    async def test_the_same_target_with_one_principal_emits_a_lead(self) -> None:
        """PART 3, end to end: single-role MAY ONLY LEAD."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm
        agent._principals = (ALICE,)
        _by_reference(agent, _peer_records)

        findings = await agent._test_idor(_make_page())
        assert findings == []
        leads = [
            lead
            for lead in agent._unproven_exploit_leads
            if lead.why_unconfirmed == "single_role_cannot_attribute"
        ]
        assert leads, [lead.why_unconfirmed for lead in agent._unproven_exploit_leads]
        lead = leads[0]
        assert "could" not in lead.claim.lower() or "Candidate IDOR" in lead.claim
        assert "authenticated principals are required" in lead.missing_observation
        assert "Arms dispatched:" in lead.raw_observation

    @pytest.mark.asyncio
    async def test_no_authz_boundary_emits_nothing(self) -> None:
        """The ec39350b phantom, end-to-end: ``info.php?id=2`` → id=3 diverges,
        but a bogus out-of-allotment id (99999999) ALSO returns a normal 200
        record — no authorization boundary exists. The content divergence is a
        public lookup doing its job, not an IDOR. Phase 5 must refuse to verify
        ⇒ zero findings (without the authz guard the divergent peer WOULD have
        verified)."""
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = params.get("id", "")
            if val == "99999999":
                # Bogus id served a normal record-shaped 200 — no boundary.
                return _HTTPResponse(
                    status=200,
                    body="name: nobody email: nobody@corp.example role: user status: active",
                )
            if val == "2":
                return _HTTPResponse(
                    status=200,
                    body=(
                        "name: alice email: alice@corp.example role: user "
                        "dob: 1990-01-01 region: us status: active"
                    ),
                )
            # Every other id (incl. the id=3 peer) returns a substantial,
            # differently-worded record — divergence that WOULD verify but for
            # the missing boundary.
            return _HTTPResponse(
                status=200,
                body=(
                    "name: bob email: bob@corp.example role: user "
                    "dob: 1985-02-02 region: eu status: active phone: 555-0102"
                ),
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/info.php?id=2",
            body="",
            status=200,
            input_params=["id"],
        )
        findings = await agent._test_idor(page)
        assert findings == []


# ===========================================================================
# Deterministic divergence gate — no LLM, no finding on identical responses
# ===========================================================================


class TestIDORDeterministicGate:
    @pytest.mark.asyncio
    async def test_identical_response_emits_nothing_and_makes_no_llm_call(self) -> None:
        """Every reference probe byte-identical to baseline ⇒ not an IDOR.

        The deterministic gate must short-circuit *before* the phase-3 LLM
        checkpoint: emit nothing and make zero LLM calls. This is the
        false-positive shape where IDOR claimed divergence on an identical
        response (length 5390 → 5390)."""
        llm = _ScriptedLLM(answers=["SHOULD-NOT-BE-USED"] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        # Param named "id" → lexical name-signal candidate, but every probe
        # returns the same body, so there is no divergence to confirm.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="X" * 5390)
        )
        page = _make_page()  # url ...?id=1, params ["id"]
        findings = await agent._test_idor(page)

        assert findings == []
        assert llm.prompts == [], "gate must fire before any LLM checkpoint"

    @pytest.mark.asyncio
    async def test_status_change_probe_passes_gate(self) -> None:
        """A status change on a probe is divergence — the gate lets it through
        to the LLM checkpoints (here the scripted-empty LLM falls back)."""
        llm = _ScriptedLLM(answers=[""] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        async def fake_get(_url: str, params: dict[str, str]) -> _HTTPResponse:
            if params.get("id") == "99999999":
                return _HTTPResponse(status=403, body="forbidden")
            return _HTTPResponse(status=200, body="user: alice role: user " * 10)

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        await agent._test_idor(page)
        # The gate did not short-circuit: at least the phase-3 ranking prompt
        # was issued.
        assert llm.prompts, "diverged probe should reach the LLM checkpoint"

    @pytest.mark.asyncio
    async def test_csrf_token_churn_same_length_emits_nothing(self) -> None:
        """A per-request CSRF token at identical length is NOT divergence.

        The exact login.php phantom: every GET returns the same length (1524)
        but a freshly regenerated 32-char hex ``user_token``. The bytes differ,
        yet nothing meaningful diverged — the IDOR fingerprint folds long hex
        runs, so the gate must short-circuit before any LLM checkpoint and emit
        no finding."""
        llm = _ScriptedLLM(answers=["SHOULD-NOT-BE-USED"] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        counter = {"n": 0}

        async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
            # 32-char hex token, regenerated each call; body length is constant.
            counter["n"] += 1
            token = f"{counter['n']:032x}"
            body = f"<form><input name='user_token' value='{token}'><p>login form</p></form>"
            return _HTTPResponse(status=200, body=body)

        agent._http_get = fake_get  # type: ignore[method-assign]
        # Param "id" is a lexical candidate, so candidacy passes — the gate (not
        # the param guard) is what must suppress this case.
        page = _make_page()
        findings = await agent._test_idor(page)

        assert findings == []
        assert llm.prompts == [], "token-churn must not reach any LLM checkpoint"


# ===========================================================================
# Auth-form / credential / token params are never IDOR candidates
# ===========================================================================


class TestIDORAuthFormParamExclusion:
    @pytest.mark.parametrize("param", ["username", "password", "Login", "user_token"])
    @pytest.mark.asyncio
    async def test_login_form_param_excluded_before_any_probe(self, param: str) -> None:
        """login.php fields (username/password/Login/user_token) are not object
        references — phase 1 rejects them with zero HTTP probes."""
        agent = _make_agent()
        # Even a resource-shaped response must not rescue an excluded param.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<table><tr><td>x</td></tr></table>" * 5)
        )
        page = PageAnalysis(
            url="http://example.com/login.php",
            body="",
            status=200,
            input_params=["username", "password", "Login", "user_token"],
        )
        is_candidate, ev = await agent._idor_phase1_reference_point(page, param, "1")
        assert is_candidate is False
        assert ev.get("excluded") is True
        assert agent._http_get.await_count == 0, "excluded param must skip all probes"

    @pytest.mark.asyncio
    async def test_full_test_idor_emits_nothing_on_login_form(self) -> None:
        """End-to-end: a login form's params produce no IDOR findings and make
        no LLM calls."""
        llm = _ScriptedLLM(answers=["SHOULD-NOT-BE-USED"] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<form>login</form>")
        )
        page = PageAnalysis(
            url="http://example.com/login.php",
            body="",
            status=200,
            input_params=["username", "password", "Login", "user_token"],
        )
        findings = await agent._test_idor(page)
        assert findings == []
        assert llm.prompts == []

    @pytest.mark.asyncio
    async def test_genuine_id_param_still_a_candidate(self) -> None:
        """The exclusion must not suppress a real object-reference param."""
        agent = _make_agent()
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="user: alice role: user")
        )
        is_candidate, ev = await agent._idor_phase1_reference_point(_make_page(), "id", "1")
        assert is_candidate is True
        assert ev.get("excluded") is None


# ===========================================================================
# Reflection-sink params are never IDOR candidates / findings
# ===========================================================================


class TestIDORReflectionSink:
    @pytest.mark.asyncio
    async def test_reflection_sink_excluded_in_phase1(self) -> None:
        """A param echoed verbatim into an otherwise-unchanged page (DVWA xss_r's
        ``name`` → "Hello <value>") is a reflection sink, not an object
        reference — phase 1 excludes it."""
        agent = _make_agent()

        async def reflect(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = next(iter(params.values()), "")
            return _HTTPResponse(
                status=200,
                body=f"<html><body><h1>Hello {val}</h1><p>welcome back</p></body></html>",
            )

        agent._http_get = reflect  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/xss_r/",
            body="",
            status=200,
            input_params=["name"],
        )
        is_candidate, ev = await agent._idor_phase1_reference_point(page, "name", "1")
        assert is_candidate is False
        assert ev.get("reflection_sink") is True
        assert ev.get("excluded") is True

    @pytest.mark.asyncio
    async def test_reflection_sink_full_test_idor_emits_nothing(self) -> None:
        """End-to-end: a pure reflection sink yields no IDOR finding and makes no
        LLM call (phantom 1: IDOR via xss_r's ``name`` echoing the synthesized
        value)."""
        llm = _ScriptedLLM(answers=["SHOULD-NOT-BE-USED"] * 8)
        agent = _make_agent(llm)
        agent._methodology_llm = llm

        async def reflect(_url: str, params: dict[str, str]) -> _HTTPResponse:
            val = next(iter(params.values()), "")
            return _HTTPResponse(
                status=200,
                body=f"<html><body><h1>Hello {val}</h1><p>welcome back home</p></body></html>",
            )

        agent._http_get = reflect  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/xss_r/",
            body="",
            status=200,
            input_params=["name"],
        )
        findings = await agent._test_idor(page)
        assert findings == []
        assert llm.prompts == [], "reflection sink must not reach any LLM checkpoint"


# ===========================================================================
# Phase 5 verification honesty — reflection / error-page / collapse guards
# ===========================================================================


class TestPhase5Honesty:
    """The three hand-written guards, and which arm catches each now.

    Two of them are subsumed by the never-issued control. An error page and a
    collapsed "no such resource" page are the SAME observation — the response is
    a property of the handler rather than of the reference — so a reference of
    the same shape that nobody owns gets the identical treatment, the control
    fails to refuse, and the candidate dies. One rule instead of two, and one
    that generalises to the next shape nobody has met yet.

    Reflection is NOT one of them, and assuming it was is a mistake this suite
    caught: a reflection sink echoes the CONTROL's reference too, so the control
    arm sees a different string, refuses correctly, and licenses nothing. Worse,
    the owner's read of the same reference echoes the same string back, which
    reads as an identical rendering — three arms agreeing on an artifact of one
    substitution. So reflection keeps its own guard
    (:func:`~clinkz.agents._idor_oracle.reflection_explains`), applied before
    attribution.
    """

    @pytest.mark.asyncio
    async def test_a_reflection_sink_does_not_confirm(self) -> None:
        """And the CONTROL correctly refuses, which is exactly why it is not enough.

        A sink that echoes every input echoes the never-issued reference too, so
        the control sees a different string and refuses — a clean bill of health
        for a parameter that selects no object at all.
        """
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda ref, who: (
                _HTTPResponse(status=302, body="", headers={})
                if who == ANONYMOUS
                else _HTTPResponse(
                    status=200,
                    body=f"Welcome {ref} to your dashboard. Account overview follows.",
                    headers={},
                )
            ),
        )
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "longreference123", "rationale": "synthesized"},
            {"baseline_status": 200, "baseline_body": "Welcome x to your dashboard."},
            IDORPrimitives(id_format="opaque", authz_check_present=True),
            "x",
        )
        assert verdict.confirmed is False
        assert "reflection sink" in verdict.detail
        assert control is not None and control.satisfied, (
            "the control refuses on a reflection sink — that is the point of this test"
        )

    @pytest.mark.asyncio
    async def test_an_error_page_is_killed_by_the_control(self) -> None:
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda ref, _who: (
                _HTTPResponse(
                    status=200,
                    body="Account details: name=alice email=alice@x role=user balance=100.",
                    headers={},
                )
                if ref == "1"
                else _HTTPResponse(
                    status=200,
                    body="Error: the requested source does not exist. No such id was found.",
                    headers={},
                )
            ),
        )
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "Account details: name=alice"},
            IDORPrimitives(id_format="numeric", authz_check_present=True),
            "1",
        )
        assert verdict.confirmed is False
        assert control is not None and not control.satisfied

    @pytest.mark.asyncio
    async def test_a_collapsed_response_is_killed_by_the_control(self) -> None:
        """The 33484 -> 1730 phantom: a 'no such resource' page, not a record."""
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda ref, _who: (
                _HTTPResponse(status=200, body="<table>" + ("y" * 33484) + "</table>", headers={})
                if ref == "xss_s"
                else _HTTPResponse(status=200, body="x" * 1730, headers={})
            ),
        )
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "a3f8c2d1e9b74056", "rationale": "synthesized"},
            {"baseline_status": 200, "baseline_body": "<table>" + ("y" * 33484) + "</table>"},
            IDORPrimitives(id_format="opaque", authz_check_present=True),
            "xss_s",
        )
        assert verdict.confirmed is False
        assert control is not None and not control.satisfied

    @pytest.mark.asyncio
    async def test_a_genuine_peer_resource_still_verifies(self) -> None:
        """The honesty guards must not suppress a true positive."""
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        bodies = {
            "alpha_module": "module alpha source listing: " + ("alpha line of code; " * 1200),
            "beta_module": "module beta source listing: " + ("beta line of code; " * 1200),
        }
        _by_reference(
            agent,
            lambda ref, who: (
                _HTTPResponse(status=404, body="no such module", headers={})
                if ref not in bodies
                else _HTTPResponse(status=302, body="", headers={})
                if who == ANONYMOUS
                else _HTTPResponse(status=200, body=bodies[ref], headers={})
            ),
        )
        verdict, _arms, control = await agent._idor_phase5_verify(
            _make_page(),
            "id",
            {"reference": "beta_module", "rationale": "peer module"},
            {"baseline_status": 200, "baseline_body": bodies["alpha_module"]},
            IDORPrimitives(id_format="opaque", authz_check_present=True),
            "alpha_module",
        )
        assert verdict.confirmed is True, verdict.detail
        assert control is not None and control.satisfied


# ===========================================================================
# The inversion: ref(0) is the CONTROL, no longer the precondition
# ===========================================================================


class TestTheAuthzProbeIsAControlNotAPrecondition:
    """Phase 5 used to open on ``if not authz_check_present: return False``.

    Across 2,955 recorded engagements that gate consumed **616 of 668**
    phase-5 refusals, and phase 2 recorded ``authz_check_present`` False on
    **1,226 of 1,256** fingerprints — because an application that 404s an id
    nobody owns and 200s a neighbour's record discriminates perfectly, and the
    gate read exactly that shape as "no boundary exists".

    Both tests below run the SAME target and differ only in the flag, so what is
    being asserted is that the flag decides nothing.
    """

    @staticmethod
    def _records(reference: str, who: str) -> _HTTPResponse:
        records = {
            "2": "name: alice email: alice@corp.example role: user dob: 1990-01-01 region: us",
            "3": "name: bob email: bob@corp.example role: user dob: 1985-02-02 region: eu",
        }
        if reference not in records:
            return _HTTPResponse(status=404, body="no such record", headers={})
        if who == ANONYMOUS:
            return _HTTPResponse(status=302, body="", headers={})
        return _HTTPResponse(status=200, body=records[reference], headers={})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("authz_check_present", [True, False])
    async def test_the_flag_does_not_decide_the_verdict(self, authz_check_present: bool) -> None:
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(agent, self._records)
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _make_page(url="http://example.com/info.php?id=2"),
            "id",
            {"reference": "3", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "name: alice"},
            IDORPrimitives(
                id_format="numeric",
                authz_check_present=authz_check_present,
                unauth_status_observed=403 if authz_check_present else 200,
            ),
            "2",
        )
        assert verdict.confirmed is True, verdict.detail

    @pytest.mark.asyncio
    async def test_a_genuinely_public_object_is_still_refused(self) -> None:
        """What the old precondition was REACHING for, done by a dispatched arm.

        The anonymous arm carries no session material at all. Being served the
        record means the target hands it to anyone, so there is no boundary —
        and this is not-applicable rather than unproven, so it leaves no lead.
        """
        agent = _make_agent()
        agent._principals = (ALICE, BOB)
        _by_reference(
            agent,
            lambda ref, _who: (
                _HTTPResponse(status=404, body="no such record", headers={})
                if ref not in ("2", "3")
                else _HTTPResponse(
                    status=200,
                    body=f"name: person{ref} email: person{ref}@corp.example role: user",
                    headers={},
                )
            ),
        )
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _make_page(url="http://example.com/info.php?id=2"),
            "id",
            {"reference": "3", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": "name: person2"},
            IDORPrimitives(id_format="numeric", authz_check_present=False),
            "2",
        )
        assert verdict.confirmed is False
        assert verdict.object_is_public is True
        assert verdict.why_unconfirmed == ""


# ===========================================================================
# Phase 6 evidence — well-formed request URL (no doubled query string)
# ===========================================================================


class TestPhase6Evidence:
    def test_evidence_request_has_no_doubled_query_string(self) -> None:
        """When the endpoint already carries the param, the evidence request URL
        REPLACES it rather than producing ``?id=xss_s?id=...`` (phantom 2)."""
        agent = _make_agent()
        result = IDORMethodologyResult(
            phases_completed=6,
            primitives=IDORPrimitives(id_format="opaque", predictability="opaque"),
            exploitation_type=IDORExploitationType.HORIZONTAL,
            synthesized_reference="a3f8c2d1e9b74056",
            verified=True,
            verification_strength="verified",
            indicator_observed="content diverges",
        )
        finding = agent._idor_phase6_emit(
            "http://172.20.0.2/vulnerabilities/view_source_all.php?id=xss_s",
            "id",
            result,
        )
        request_line = next(e for e in finding.evidence if e.startswith("Request:"))
        assert "?id=xss_s?id=" not in request_line  # no doubled query string
        assert request_line.count("?") == 1
        assert request_line.count("id=") == 1
        assert "id=a3f8c2d1e9b74056" in request_line
