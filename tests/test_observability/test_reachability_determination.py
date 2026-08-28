"""Absence is not zero, at the reachability seam.

Every reachability predicate compares a counter against zero and, when it does
not hold, writes a sentence about the CLIENT'S APPLICATION — *no endpoint the
scan discovered carried this class's surface*. That sentence is only worth what
the producer behind the counter is worth, and a counter left at its default is
byte-identical to one a producer set to zero.

An exploit phase that errored therefore filed all thirty methodology classes as
NOT APPLICABLE, each carrying that sentence, rendered in the client PDF under
*Built, but not reachable on this target*. That is not a wrong number; it is a
wrong sentence about a client's application, generated from a phase that never
ran.

Two doors reach the same all-zero state independently — the exploit phase's
result and the plan-alarm register — so both are tested here, and a third
route in (a phase that DID deliver while nothing served its reasoning step) is
caught by the run-completion reconciliation rather than by the gate.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.agents._report_integrity import reconcile_reachability_claims
from clinkz.observability.component_registry import (
    METHODOLOGY_PREFIX,
    PREDICATES,
    EngagementReachability,
    ReachabilityKey,
    ReachabilitySource,
)
from clinkz.observability.ledger import ComponentKind, ContributionLedger
from clinkz.observability.plan_alarms import (
    PlanAlarmRegister,
    PlanTruncation,
    set_active_plan_alarms,
)
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.tools.resolver import ToolResolver

_SQLI = f"{METHODOLOGY_PREFIX}_test_sqli"
_ALL_REPORTED = frozenset(ReachabilitySource)


@pytest.fixture(autouse=True)
def _no_active_register() -> Any:
    """The register is absent by default and every test here says what it wants."""
    set_active_plan_alarms(None)
    yield
    set_active_plan_alarms(None)


def _ledger(key: ReachabilityKey = ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES) -> ContributionLedger:
    ledger = ContributionLedger(engagement_id="reach-test")
    ledger.declare(_SQLI, ComponentKind.METHODOLOGY, reachability=key.value)
    return ledger


# ---------------------------------------------------------------------------
# Every predicate names its producer
# ---------------------------------------------------------------------------


def test_every_predicate_declares_the_source_it_reads() -> None:
    """The guard-domain law: the DOMAIN is ``PREDICATES``, computed, not a list.

    A predicate with no source cannot tell "the producer said zero" from "the
    producer said nothing" — which is the whole defect — and a new one added
    without one must fail here rather than answer ``False`` in a client PDF.
    """
    for key, predicate in PREDICATES.items():
        assert isinstance(predicate.source, ReachabilitySource), (
            f"{key} declares no producer; it cannot say whose zero it is reading"
        )


def test_every_source_has_a_sentence_of_its_own() -> None:
    """A silent producer's reason is rendered to an operator, so it must exist."""
    empty = EngagementReachability()
    for source in ReachabilitySource:
        reason = empty.unreported_reason(source)
        assert reason and "not determined" in reason or "never measured" in reason, (
            f"{source} has no sentence explaining why nothing could be determined"
        )


def test_a_reported_source_reads_as_reported() -> None:
    state = EngagementReachability(reported_sources=frozenset({ReachabilitySource.EXPLOIT_PLAN}))
    assert state.unreported_reason(ReachabilitySource.EXPLOIT_PLAN) == ""
    assert state.unreported_reason(ReachabilitySource.EXPLOIT_PHASE)


# ---------------------------------------------------------------------------
# The gate at resolve_reachability
# ---------------------------------------------------------------------------


def test_a_silent_producer_leaves_the_component_undetermined_not_unreachable() -> None:
    """No alarm, no NOT-APPLICABLE, no target claim. The third answer."""
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())  # nothing reported

    assert not ledger.alarming(), "an undetermined predicate must never alarm"
    assert not ledger.unreachable(), (
        "'the engagement could not reach it' is a claim about the target, and no "
        "producer made an observation that supports it"
    )
    (record,) = ledger.reachability_undetermined()
    assert record.reachable is None
    assert record.reachability_reason == ""
    assert "not determined" in record.reachability_undetermined


def test_the_undetermined_reason_never_describes_the_target() -> None:
    """The predicate's own sentence is exactly what must NOT be substituted."""
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())
    (record,) = ledger.reachability_undetermined()
    predicate = PREDICATES[ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES]
    target_claim = predicate.describe(EngagementReachability(), _SQLI)
    assert "no endpoint" in target_claim  # the sentence that used to be written
    assert record.reachability_undetermined != target_claim
    assert "no endpoint" not in record.reachability_undetermined


def test_a_reported_producer_still_answers_normally() -> None:
    """The gate only withholds; it never changes an answer a producer supports."""
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    (record,) = ledger.unreachable()
    assert record.reachable is False
    assert "no endpoint" in record.reachability_reason
    assert not ledger.reachability_undetermined()


def test_a_source_gate_is_per_predicate_not_per_run() -> None:
    """A dead exploit phase must not cost the answers a live scan supports.

    Over-suppression is its own defect: the scan's HTTP-surface predicate and the
    resolver's tool predicate read producers that spoke, and withholding those
    would lose real information to fix a different producer's silence.
    """
    ledger = ContributionLedger(engagement_id="reach-mixed")
    ledger.declare(
        _SQLI, ComponentKind.METHODOLOGY, reachability=ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES
    )
    ledger.declare(
        "discoverer:graphql",
        ComponentKind.DISCOVERER,
        reachability=ReachabilityKey.HTTP_SURFACE_DISCOVERED,
    )
    ledger.resolve_reachability(
        EngagementReachability(
            http_endpoints_discovered=0,
            reported_sources=frozenset({ReachabilitySource.SCAN_PHASE}),
        )
    )
    undetermined = {r.name for r in ledger.reachability_undetermined()}
    unreachable = {r.name for r in ledger.unreachable()}
    assert undetermined == {_SQLI}
    assert unreachable == {"discoverer:graphql"}


def test_the_undetermined_state_is_serialized_and_counted() -> None:
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())
    payload = ledger.to_dict()
    assert payload["unreachable"] == []
    (entry,) = payload["reachability_undetermined"]
    assert entry["component"] == _SQLI
    assert entry["predicate"] == ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES.value
    assert payload["summary"]["unreachable_components"] == 0
    assert payload["summary"]["reachability_undetermined_components"] == 1


def test_never_evaluated_is_still_distinct_from_undetermined() -> None:
    """``None`` has two causes and only one of them was a decision.

    A replay or a direct invocation never calls ``resolve_reachability`` at all,
    and that is not the same fact as a producer having gone silent during a real
    engagement.
    """
    ledger = _ledger()
    (record,) = ledger.records()
    assert record.reachable is None
    assert record.reachability_undetermined == ""
    assert not ledger.reachability_undetermined()


# ---------------------------------------------------------------------------
# Door 1: the exploit phase delivered nothing
# ---------------------------------------------------------------------------


def _register_with_a_pass() -> PlanAlarmRegister:
    register = PlanAlarmRegister()
    register.record(
        PlanTruncation(
            stage="union", cap=150, kept=3, dropped_total=0, kept_by_class={"_test_sqli": 3}
        )
    )
    set_active_plan_alarms(register)
    return register


@pytest.mark.parametrize(
    "exploit_phase",
    [
        pytest.param({"status": "error", "error": "boom"}, id="phase-errored"),
        pytest.param({"status": "not_started"}, id="phase-never-started"),
        pytest.param({"status": "timeout", "agent": "exploit"}, id="killed-with-nothing-delivered"),
        pytest.param({}, id="absent-entirely"),
    ],
)
def test_an_absent_exploit_result_reports_no_exploit_producer(
    exploit_phase: dict[str, Any],
) -> None:
    _register_with_a_pass()
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        exploit_phase,
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PHASE not in state.reported_sources
    assert ReachabilitySource.SCAN_PHASE in state.reported_sources
    assert ReachabilitySource.ENGINE in state.reported_sources


def test_a_delivered_exploit_result_reports_the_exploit_producer() -> None:
    _register_with_a_pass()
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        {"status": "complete", "result": {"total_tests_run": 12, "plan": {"tasks": []}}},
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PHASE in state.reported_sources
    assert state.exploit_tasks_dispatched == 12


def test_a_partial_result_from_a_killed_phase_still_counts_as_delivered() -> None:
    """A stop is a reason to stop asking, not a reason to discard what arrived."""
    _register_with_a_pass()
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        {"status": "halted", "agent": "exploit", "result": {"total_tests_run": 4}},
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PHASE in state.reported_sources


# ---------------------------------------------------------------------------
# Door 2: the plan-alarm register said nothing
# ---------------------------------------------------------------------------


def test_no_register_installed_is_not_a_plan_with_no_candidates() -> None:
    """``plan_alarm_summary()`` returns the CLEAN shape when nothing installed one.

    Gating on the exploit result alone leaves this door wide open: the exploit
    phase can deliver a full result while the summary's
    ``classes_with_candidates: []`` came from a register that does not exist.
    """
    set_active_plan_alarms(None)
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        {"status": "complete", "result": {"total_tests_run": 9}},
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PLAN not in state.reported_sources
    assert ReachabilitySource.EXPLOIT_PHASE in state.reported_sources


def test_a_register_that_recorded_no_pass_has_said_nothing_about_the_plan() -> None:
    """Installed is not the same as having spoken.

    The planner records a pass on BOTH branches — truncated or not — so zero
    passes means no plan was ever built, and the empty candidate set that comes
    back is an absence rather than a measurement.
    """
    set_active_plan_alarms(PlanAlarmRegister())
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        {"status": "complete", "result": {"total_tests_run": 9}},
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PLAN not in state.reported_sources


def test_a_register_with_a_recorded_pass_reports_the_plan_producer() -> None:
    _register_with_a_pass()
    state = OrchestratorAgent._engagement_reachability(
        {"status": "complete", "result": {"service_scans": []}},
        {"status": "complete", "result": {"total_tests_run": 9}},
        ToolResolver(),
    )
    assert ReachabilitySource.EXPLOIT_PLAN in state.reported_sources
    assert state.classes_with_plan_candidates == frozenset({"_test_sqli"})


def test_an_absent_scan_result_reports_no_scan_producer() -> None:
    """Same rule, same reason: "the scan discovered no HTTP endpoint" is a claim."""
    _register_with_a_pass()
    state = OrchestratorAgent._engagement_reachability(
        {"status": "error", "error": "boom"},
        {"status": "complete", "result": {"total_tests_run": 9}},
        ToolResolver(),
    )
    assert ReachabilitySource.SCAN_PHASE not in state.reported_sources


def test_the_end_to_end_shape_of_the_defect() -> None:
    """The reported defect, reproduced against the real assembler.

    Exploit errored; the register holds a pass. Every methodology class used to
    come out NOT APPLICABLE with a sentence about the target's surface.
    """
    _register_with_a_pass()
    ledger = ContributionLedger(engagement_id="d1")
    for klass in ("_test_sqli", "_test_xss", "_test_idor"):
        ledger.declare(
            f"{METHODOLOGY_PREFIX}{klass}",
            ComponentKind.METHODOLOGY,
            reachability=ReachabilityKey.EXPLOIT_TASK_DISPATCHED.value,
        )
    ledger.resolve_reachability(
        OrchestratorAgent._engagement_reachability(
            {"status": "complete", "result": {"service_scans": []}},
            {"status": "error", "error": "All providers exhausted"},
            ToolResolver(),
        )
    )
    assert ledger.unreachable() == []
    assert len(ledger.reachability_undetermined()) == 3
    assert not ledger.alarming()


# ---------------------------------------------------------------------------
# Door 3: the run-completion banner
# ---------------------------------------------------------------------------


def _ledger_dict_with_one_unreachable() -> dict[str, Any]:
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    return ledger.to_dict()


def test_an_incomplete_run_may_not_carry_a_reachability_claim() -> None:
    payload = _ledger_dict_with_one_unreachable()
    assert payload["unreachable"], "precondition: the claim is there to be withdrawn"

    out = reconcile_reachability_claims(
        payload,
        run_completed=False,
        incomplete_reason="No LLM provider served the exploit stage.",
    )
    assert out["unreachable"] == []
    (entry,) = out["reachability_undetermined"]
    assert entry["component"] == _SQLI
    assert "did not complete" in entry["reason"]
    assert "exploit stage" in entry["reason"]
    assert "no endpoint" not in entry["reason"]
    assert out["summary"]["unreachable_components"] == 0
    assert out["summary"]["reachability_undetermined_components"] == 1


def test_a_completed_run_is_returned_unchanged() -> None:
    payload = _ledger_dict_with_one_unreachable()
    assert reconcile_reachability_claims(payload, run_completed=True) == payload


def test_the_reconciliation_never_mutates_its_input() -> None:
    payload = _ledger_dict_with_one_unreachable()
    reconcile_reachability_claims(payload, run_completed=False, incomplete_reason="x")
    assert len(payload["unreachable"]) == 1, "only ever returns a new dict"


def test_the_reconciliation_only_tightens() -> None:
    """It can withdraw a claim; there is no direction in which it adds one."""
    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())
    payload = ledger.to_dict()
    out = reconcile_reachability_claims(payload, run_completed=False, incomplete_reason="x")
    assert out["unreachable"] == []
    assert len(out["reachability_undetermined"]) == 1


def test_an_absent_ledger_reconciles_to_an_absent_ledger() -> None:
    assert reconcile_reachability_claims({}, run_completed=False) == {}
    assert reconcile_reachability_claims(None, run_completed=False) == {}


# ---------------------------------------------------------------------------
# The deliverable: it must SAY undetermined, and must not say the other thing
# ---------------------------------------------------------------------------


def _report_with(ledger_dict: dict[str, Any], **summary_kwargs: Any) -> Any:
    from datetime import UTC, datetime

    from clinkz.models.report import ExecutiveSummary, PentestReport

    now = datetime.now(UTC)
    return PentestReport(
        engagement_name="t",
        test_start=now,
        test_end=now,
        component_ledger=ledger_dict,
        executive_summary=ExecutiveSummary(
            overview="x", risk_rating="Not assessed", **summary_kwargs
        ),
    )


def test_the_markdown_says_not_determined_and_never_a_per_class_sentence() -> None:
    from clinkz.agents.report import ReportAgent

    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())
    lines: list[str] = []
    ReportAgent._render_component_ledger(lines, _report_with(ledger.to_dict()))
    rendered = "\n".join(lines)

    assert "### Reachability not determined" in rendered
    assert "not reachable on this target" not in rendered
    assert "no endpoint" not in rendered, (
        "the predicate's sentence is a claim about the client's application"
    )


def test_the_markdown_all_clear_does_not_absorb_an_undetermined_component() -> None:
    """ "or were not reachable on this target" is itself one of the claims."""
    from clinkz.agents.report import ReportAgent

    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability())
    lines: list[str] = []
    ReportAgent._render_component_ledger(lines, _report_with(ledger.to_dict()))
    rendered = "\n".join(lines)
    assert "reachability left undetermined" in rendered
    assert "| Component |" not in rendered, "nothing alarmed, so there is no table"


def test_the_markdown_reconciles_an_incomplete_run_at_the_render_seam() -> None:
    """A stored bundle written before the build-seam rule re-renders honestly."""
    from clinkz.agents.report import ReportAgent

    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    report = _report_with(
        ledger.to_dict(),
        run_completed=False,
        incomplete_reason="No LLM provider served the exploit stage.",
    )
    lines: list[str] = []
    ReportAgent._render_component_ledger(lines, report)
    rendered = "\n".join(lines)

    assert "Built, but not reachable on this target" not in rendered
    assert "### Reachability not determined" in rendered
    assert "no endpoint" not in rendered


def test_a_completed_run_still_renders_its_reachability_section() -> None:
    """The reconciliation only tightens; it must not cost a clean run anything."""
    from clinkz.agents.report import ReportAgent

    ledger = _ledger()
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    lines: list[str] = []
    ReportAgent._render_component_ledger(lines, _report_with(ledger.to_dict()))
    rendered = "\n".join(lines)
    assert "Built, but not reachable on this target" in rendered
    assert "### Reachability not determined" not in rendered
