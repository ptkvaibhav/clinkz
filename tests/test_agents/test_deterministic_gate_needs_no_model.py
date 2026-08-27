"""Silence from a detection path is not evidence of cleanliness.

Engagement ``d67835f5`` shipped fourteen phantom findings and recorded **zero**
false-positive events. Three defects lined up to make that look like a clean
review, and each is pinned here:

1. **Half the deterministic grounds were gated by an LLM.** Eight probes decide
   whether a candidate's own evidence contradicts it. Four ran unconditionally
   at the emission chokepoint; the other four ran only inside the post-run
   false-positive cross-check, i.e. only once a model had nominated the finding.
   A guard whose entire value is that it needs no model must not be reachable
   only through one.
2. **The refusal that stopped the cross-check was swallowed.**
   ``DecisionPathFallbackError`` was an ordinary ``Exception``, so the broad
   handler that (correctly) degrades the call turned it into an empty suspect
   list — which is exactly what the cross-check returns when it looked and found
   nothing wrong. Its sibling ``ProviderPolicyError`` had already been hardened
   against that pattern; this one had not, and that asymmetry is the incident.
3. **Nothing recorded that the review had not happened.** A component that is
   invoked, fails, and contributes zero now says so on the contribution ledger,
   where a component that ran and correctly found nothing does not.
"""

from __future__ import annotations

import pytest

from clinkz.agents._principal import Principal
from clinkz.llm.base import DecisionPathFallbackError, LLMError, ProviderPolicyError
from clinkz.models.finding import (
    UNPROVEN_WHY_UNCONFIRMED,
    ExploitAnalysis,
    ExploitPlan,
    Finding,
    FindingStatus,
    Severity,
)
from clinkz.observability.ledger import (
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)

from .test_exploit_v2 import _CONTROL_ARM, MockLLM, _make_agent


@pytest.fixture
def ledger():
    """An active ledger for the duration of one test, always torn down."""
    active = ContributionLedger(engagement_id="test-engagement-001")
    set_active_ledger(active)
    try:
        yield active
    finally:
        set_active_ledger(None)


def _error_page_finding() -> Finding:
    """A candidate tripping a ground that used to be reachable only via the LLM."""
    return Finding(
        title="Command Injection in ip parameter",
        description="Technique: WSTG-INPV-12. Parameter: ip.",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        target="http://t/vulnerabilities/exec/",
        evidence=[
            "Request: ip=;echo clinkzcmdi51696",
            "Response: matched 'clinkzcmdi51696'",
            "response_status=500",
        ],
    )


class TestEveryGroundRunsAtTheChokepoint:
    def test_the_ninth_ground_reads_the_run_not_the_evidence(self) -> None:
        """Ground 9 compares a registry DECLARATION against the run's principals.

        Both halves are engine facts, so it needs no structured-evidence reader:
        there is nothing here a response body could influence. It is the
        chokepoint half of PART 3 — the methodology refuses first, and this is
        what makes the refusal structural rather than something one class
        remembers, exactly as ground 8 does for the never-sent control.
        """
        agent = _make_agent()
        agent._principals = ()
        idor = Finding(
            title="Insecure Direct Object Reference via id parameter (horizontal)",
            description="Technique: WSTG-ATHZ-04. Parameter: id.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            target="http://t/account",
            evidence=["Request: GET /account?id=2", "Response: bob's record"],
        )
        ground = agent._fp_ground_insufficient_principals(idor)
        assert ground is not None
        assert "2 authenticated principals" in ground

        agent._principals = (
            Principal(role="a", cookies={"s": "1"}, primary=True),
            Principal(role="b", cookies={"s": "2"}),
        )
        assert agent._fp_ground_insufficient_principals(idor) is None

    def test_the_ninth_ground_leaves_every_other_class_alone(self) -> None:
        """A class needing one principal must be untouched by the new rule."""
        agent = _make_agent()
        agent._principals = ()
        assert agent._fp_ground_insufficient_principals(_error_page_finding()) is None

    def test_both_consumers_read_one_declaration(self) -> None:
        """The gate and the cross-check must not carry separate ground lists.

        They did, and the shorter one was the one that decided emission.
        """
        agent = _make_agent()
        declared = agent._deterministic_grounds()
        assert len(declared) == 9, "a ground was added or dropped without updating the table"
        names = [probe.__name__ for probe, _ in declared]
        assert len(set(names)) == len(names), "a ground is declared twice"
        reasons = [why for _, why in declared]
        assert all(reasons) and len(set(reasons)) == len(reasons), (
            "every ground needs its own lead reason — a shared one loses which "
            "guard fired, which is the only thing the lead can be acted on"
        )

    def test_every_ground_reason_is_in_the_closed_vocabulary(self) -> None:
        """An unregistered reason is silently normalised, and lands as a lie.

        ``_record_unproven_lead`` normalises an unknown ``why`` to
        ``not_instrumentable`` — "the confirming observation needs access we do
        not hold". Two grounds shipped without an entry, so every lead they
        produced told the operator the engine could not reach the target, when
        what actually happened is that the observation refuted itself. A lead's
        reason is the only part an operator can act on.
        """
        agent = _make_agent()
        unregistered = [
            why for _, why in agent._deterministic_grounds() if why not in UNPROVEN_WHY_UNCONFIRMED
        ]
        assert not unregistered, (
            f"{unregistered} would be normalised to `not_instrumentable`, which "
            "states a reason that is not what happened"
        )

    @pytest.mark.asyncio
    async def test_a_ground_that_was_llm_gated_now_blocks_emission(self) -> None:
        """The error-page ground, with no model anywhere in the call."""
        agent = _make_agent()
        finding = _error_page_finding()
        assert await agent._persist_finding(finding) is False
        agent.state.add_finding.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_suppressed_candidate_survives_as_a_lead(self) -> None:
        """Suppression is a demotion, never a deletion — the observation is kept."""
        agent = _make_agent()
        await agent._persist_finding(_error_page_finding())
        assert agent._unproven_exploit_leads, "a suppressed candidate must still reach the operator"
        lead = agent._unproven_exploit_leads[-1]
        assert lead.why_unconfirmed == "observation_landed_in_an_error_response"
        assert "status=500" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_a_clean_candidate_still_emits(self, ledger: ContributionLedger) -> None:
        """The gate must not become a wall. Eight grounds, none of them tripped."""
        agent = _make_agent()
        clean = Finding(
            title="Missing Security Headers",
            description="Technique: WSTG-CONF-07. Parameter: -.",
            severity=Severity.LOW,
            status=FindingStatus.CONFIRMED,
            target="http://t/",
            evidence=["Request: GET http://t/", "Response: 200, no CSP header"],
        )
        assert await agent._persist_finding(clean) is True

    @pytest.mark.asyncio
    async def test_examining_and_suppressing_nothing_is_not_an_alarm(
        self, ledger: ContributionLedger
    ) -> None:
        """ "The gate suppressed nothing" and "the gate never ran" are opposites.

        Only one of them is a clean bill of health, and the portfolio run could
        not be told apart on it.
        """
        agent = _make_agent()
        await agent._persist_finding(
            Finding(
                title="Missing Security Headers",
                description="Technique: WSTG-CONF-07. Parameter: -.",
                severity=Severity.LOW,
                status=FindingStatus.CONFIRMED,
                target="http://t/",
                evidence=["Request: GET http://t/", "Response: 200"],
            )
        )
        gate = next(r for r in ledger.records() if r.name == "exploit.emission_gate")
        assert gate.invocations == 1
        assert gate.correctly_empty, "an examined-and-cleared candidate is not a defect"
        assert LedgerAlarm.SILENT not in gate.alarms


class TestTheRefusalCannotBeSwallowed:
    def test_the_two_siblings_share_the_mechanism(self) -> None:
        """One was hardened against the broad-except pattern and one was not."""
        for refusal in (ProviderPolicyError, DecisionPathFallbackError):
            assert not issubclass(refusal, Exception), (
                f"{refusal.__name__} is catchable by a broad `except Exception`, which "
                "is the handler shape that hid it"
            )

    def test_it_no_longer_rotates_the_chain(self) -> None:
        """An LLMError rotates; rotating is the behaviour being refused."""
        assert not issubclass(DecisionPathFallbackError, LLMError)

    def test_a_broad_handler_does_not_reach_it(self) -> None:
        with pytest.raises(DecisionPathFallbackError):
            try:
                raise DecisionPathFallbackError("refused on the SUPPRESS path")
            except Exception:  # noqa: BLE001 — the handler shape under test
                pytest.fail("a broad except swallowed the refusal")

    def test_an_explicit_handler_still_catches_it(self) -> None:
        """Degrading is correct; degrading silently is not. The handler must exist."""
        caught = False
        try:
            raise DecisionPathFallbackError("refused")
        except DecisionPathFallbackError:
            caught = True
        assert caught


class _RefusingLLM(MockLLM):
    """A primary that failed, with the fallback refused on the SUPPRESS path."""

    async def generate_text(self, prompt: str, **kwargs) -> str:
        raise DecisionPathFallbackError(
            "Refusing to let 'gemini' serve 'exploit._llm_analyze_results' after "
            "primary 'anthropic' failed. This call is declared SUPPRESS."
        )


class TestAReviewThatDidNotHappenSaysSo:
    @pytest.mark.asyncio
    async def test_the_refusal_is_caught_by_name(self, ledger: ContributionLedger) -> None:
        agent = _make_agent(llm=_RefusingLLM())
        analysis = await agent._llm_analyze_results([_error_page_finding()], ExploitPlan())
        assert analysis.false_positive_suspects == []
        assert analysis.cross_check_ran is False, (
            "an empty suspect list from a call that never answered must not be "
            "indistinguishable from one that reviewed and cleared everything"
        )
        assert "NOT reviewed" in analysis.coverage_summary

    @pytest.mark.asyncio
    async def test_the_ledger_alarms_on_a_review_that_never_ran(
        self, ledger: ContributionLedger
    ) -> None:
        agent = _make_agent(llm=_RefusingLLM())
        await agent._llm_analyze_results([_error_page_finding()], ExploitPlan())
        record = next(r for r in ledger.records() if r.name == "exploit.fp_cross_check")
        assert record.invocations == 1 and record.successes == 0
        assert LedgerAlarm.ALL_FAILED in record.alarms
        assert record in ledger.alarming()

    @pytest.mark.asyncio
    async def test_a_review_that_ran_and_cleared_everything_does_not_alarm(
        self, ledger: ContributionLedger
    ) -> None:
        """The fifth fact: correctly found nothing.

        Reported as a defect it becomes a permanent false alarm, and a permanent
        false alarm trains an operator to skim the section a real one appears in.
        """
        agent = _make_agent()
        analysis = await agent._llm_analyze_results([_error_page_finding()], ExploitPlan())
        assert analysis.cross_check_ran is True
        record = next(r for r in ledger.records() if r.name == "exploit.fp_cross_check")
        assert record.successes == 1
        assert record.correctly_empty
        assert LedgerAlarm.SILENT not in record.alarms

    def test_an_unfilled_analysis_claims_no_review(self) -> None:
        """The default has to be the conservative one."""
        assert ExploitAnalysis().cross_check_ran is False

    @pytest.mark.asyncio
    async def test_nothing_is_demoted_when_the_review_never_ran(self) -> None:
        """The degradation direction is unchanged: no opinion suppresses nothing."""
        agent = _make_agent()
        findings = [_error_page_finding()]
        await agent._mark_false_positive_suspects(findings, ExploitAnalysis(cross_check_ran=False))
        assert len(findings) == 1


class TestTheGateIsUpstreamOfTheCrossCheck:
    @pytest.mark.asyncio
    async def test_an_llm_cannot_suppress_what_the_code_did_not(self) -> None:
        """G13 both ways: a rationale naming no ground demotes nothing.

        With every ground now enforced at emission, an emitted finding carries no
        contradiction by construction — so the cross-check's suppression power is
        exactly the code's, and an LLM cannot subtract from the report on its own.
        """
        agent = _make_agent()
        survivor = Finding(
            title="SQL Injection in id parameter",
            description="Technique: WSTG-INPV-05. Parameter: id.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            target="http://t/vulnerabilities/sqli/",
            evidence=[
                "Request: GET http://t/vulnerabilities/sqli/?id=1",
                "Response: true=4842B false=4848B (delta=6)",
                "payload=1' AND '1'='1",
                *_CONTROL_ARM,
            ],
        )
        findings = [survivor]
        await agent._mark_false_positive_suspects(
            findings,
            ExploitAnalysis(
                cross_check_ran=True,
                false_positive_suspects=[
                    {"id": survivor.id, "reason": "the differential is only 6 bytes, marginal"}
                ],
            ),
        )
        assert findings == [survivor], (
            "six bytes IS the signal — a judgement about a measurement names no "
            "contradiction and must not suppress it"
        )
