"""The terminal classes' pass-0 plan-slot reservation, and what it costs.

The mirror image of the dependency→CVE reservation's defect, one layer earlier
and quieter. That source could never queue a task because every earlier pass had
already filled the cap. A terminal class is starved by the *ordering* instead:
the deterministic plan's per-class floor walks ``_DETERMINISTIC_CATEGORY_ORDER``
and stops at the cap, and the terminal classes are declared LAST in that order —
because the dispatcher runs them last — so a cap smaller than the applicable
class count removes exactly them, and removes them first.

Three properties are pinned here:

* **The reserved set is COMPUTED from ``TERMINAL_DISPATCH_CLASSES``.** Not a
  second table that agrees with it today. This is the guard-domain law, and it is
  the exact shape that has broken repeatedly in this codebase: a class added to
  the terminal table must be reserved for with nothing else edited.
* **A run with no terminal candidate plans byte-identically.** The reservation
  would otherwise be a coverage regression paid on every target that has no JSON
  merge endpoint and no write-crossing surface, to benefit the ones that do.
* **The reservation is a FLOOR, never a ceiling.** A terminal class the earlier
  passes already reached keeps every task they gave it, and its unspent slot goes
  back to the Tier-1 fill rather than shrinking the plan.
"""

from __future__ import annotations

import logging
import time

import pytest

from clinkz.agents._principal import Principal
from clinkz.agents.exploit import (
    _DETERMINISTIC_CATEGORY_ORDER,
    TERMINAL_DISPATCH_CLASSES,
    ExploitAgent,
    terminal_dispatch_rank,
)
from clinkz.models.scan import (
    Endpoint,
    HTTPScanResult,
    ParamLocation,
    ScanResult,
    ServiceScanResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

SCOPE = EngagementScope(
    name="terminal-reservation-test",
    targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.test")],
)


def _agent(max_plan_tasks: int = 150, *, principals: int = 2) -> ExploitAgent:
    """A bare agent — no LLM, no network, no state store."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.scope = SCOPE
    agent._logger = logging.getLogger("test.terminal.reservation")
    agent._max_plan_tasks = max_plan_tasks
    agent._session_headers = {}
    agent._session_cookies = {}
    agent._unproven_exploit_leads = []
    agent._component_cve_pending = {}
    agent.engagement_id = "terminal-reservation-test"
    agent._principals = tuple(
        Principal(role=f"role{i}", privilege=i * 10, primary=i == 0, username=f"u{i}")
        for i in range(principals)
    )
    return agent


def _terminal_surface(count: int) -> list[Endpoint]:
    """Endpoints BOTH terminal classes have a surface on.

    A JSON-body write endpoint: ``_test_prototype_pollution`` is queued by the
    observed JSON body and ``_test_write_crossing`` by the write shape, so one
    endpoint mix exercises the whole reserved set rather than half of it.
    """
    return [
        Endpoint(
            url=f"https://app.test/api/users/{i}",
            method="POST",
            params=["comment", "UserId"],
            content_type="application/json",
            param_locations={
                "comment": ParamLocation.JSON_BODY,
                "UserId": ParamLocation.JSON_BODY,
            },
            has_form=True,
        )
        for i in range(count)
    ]


def _flat_surface(count: int) -> list[Endpoint]:
    """Parameterised GETs — no write, no JSON body, so no terminal class applies."""
    return [
        Endpoint(url=f"https://app.test/page{i}?id={i}", method="GET", params=["id"])
        for i in range(count)
    ]


def _scan(endpoints: list[Endpoint]) -> ScanResult:
    return ScanResult(
        target="https://app.test",
        service_scans=[
            ServiceScanResult(
                port=443,
                service_type="http",
                result=HTTPScanResult(base_url="https://app.test/", endpoints=endpoints),
            )
        ],
    )


# ---------------------------------------------------------------------------
# The domain is computed, not declared twice
# ---------------------------------------------------------------------------


def test_the_reserved_set_is_computed_from_the_terminal_table() -> None:
    """Every terminal class with a surface reserves; nothing else does.

    Asserted against ``TERMINAL_DISPATCH_CLASSES`` itself rather than against a
    number, so adding a third terminal class raises the reservation without this
    test being edited — and a class removed from that table stops reserving on
    the same edit.
    """
    agent = _agent()
    agent._resolve_terminal_class_reservation(_scan(_terminal_surface(4)))
    assert agent._terminal_reserved == len(TERMINAL_DISPATCH_CLASSES), (
        "the reservation must be sized from the terminal table, not from a second "
        f"list — reserved {agent._terminal_reserved} for "
        f"{sorted(TERMINAL_DISPATCH_CLASSES)}"
    )


def test_a_surface_only_one_terminal_class_reaches_reserves_only_one() -> None:
    """A slot for a class with no bucket is a slot nothing can be queued into.

    The same narrowness the CVE reservation applies to a match that can only ever
    become a lead.
    """
    # A form POST with no JSON body: the write-crossing class is queued by the
    # write shape, prototype pollution abstains because its carrier is JSON only.
    endpoints = [
        Endpoint(url="https://app.test/feedback", method="POST", params=["comment"], has_form=True)
    ]
    agent = _agent()
    agent._resolve_terminal_class_reservation(_scan(endpoints))
    assert agent._terminal_reserved == 1


def test_a_flat_surface_reserves_nothing() -> None:
    agent = _agent()
    agent._resolve_terminal_class_reservation(_scan(_flat_surface(10)))
    assert agent._terminal_reserved == 0
    assert agent._tier1_plan_task_cap() == agent._max_plan_task_cap()


def test_no_scan_at_all_reserves_nothing() -> None:
    """A directly invoked agent — a smoke cell, a replay, a driver."""
    agent = _agent()
    agent._resolve_terminal_class_reservation(None)
    assert agent._terminal_reserved == 0


# ---------------------------------------------------------------------------
# The no-candidate case: byte-identical, not merely similar
# ---------------------------------------------------------------------------


def test_a_run_with_no_terminal_candidate_plans_byte_identically() -> None:
    """The pinning test the reservation had to earn.

    A reservation that cost a Tier-1 task on a target with no terminal surface
    would be a coverage regression paid on most engagements to benefit a few, so
    the plan is compared field for field rather than by length.
    """
    endpoints = _flat_surface(40)
    scan = _scan(endpoints)

    baseline = _agent(max_plan_tasks=25)
    baseline_plan = baseline._build_deterministic_plan(endpoints, [], [])
    baseline_merged = baseline._merge_terminal_class_tasks(baseline_plan)

    reserved = _agent(max_plan_tasks=25)
    reserved._resolve_terminal_class_reservation(scan)
    assert reserved._terminal_reserved == 0
    reserved_plan = reserved._build_deterministic_plan(endpoints, [], [])
    reserved_merged = reserved._merge_terminal_class_tasks(reserved_plan)

    assert reserved_merged.model_dump(mode="json") == baseline_merged.model_dump(mode="json"), (
        "a run whose surface reaches no terminal class must plan exactly what it "
        "planned before the reservation existed"
    )


# ---------------------------------------------------------------------------
# The reservation spends where the cap had removed the class entirely
# ---------------------------------------------------------------------------


def test_a_cap_below_the_class_count_used_to_lose_the_terminal_classes() -> None:
    """The defect, reproduced: without the reservation they are simply gone.

    The floor walks the category order and stops at the cap. The terminal classes
    are declared last there — because the dispatcher runs them last — so they are
    exactly what a small cap removes, and a class that was never planned is
    indistinguishable in every artifact from a class that ran and found nothing.
    """
    agent = _agent(max_plan_tasks=6)
    plan = agent._build_deterministic_plan(_terminal_surface(20), [], [])
    assert not {t.test_method for t in plan.tasks} & set(TERMINAL_DISPATCH_CLASSES), (
        "this test asserts a starvation the planner no longer produces, so it is measuring nothing"
    )


def test_the_reservation_gives_every_terminal_class_a_task_back() -> None:
    """The fix: a floor for the classes the cap removed first."""
    endpoints = _terminal_surface(20)
    agent = _agent(max_plan_tasks=6)
    agent._resolve_terminal_class_reservation(_scan(endpoints))
    assert agent._terminal_reserved == len(TERMINAL_DISPATCH_CLASSES)

    plan = agent._build_deterministic_plan(endpoints, [], [])
    merged = agent._merge_terminal_class_tasks(plan)

    planned = {t.test_method for t in merged.tasks}
    assert set(TERMINAL_DISPATCH_CLASSES) <= planned, (
        f"the reservation did not reach every terminal class — planned {sorted(planned)}"
    )
    assert len(merged.tasks) <= agent._max_plan_task_cap()


def test_the_reservation_is_a_floor_and_returns_what_it_does_not_spend() -> None:
    """A class the earlier passes already reached keeps its tasks; the slot goes back.

    The ordinary case on a full-sized cap. A reservation that shrank the plan on
    every run where it was unnecessary would cost more coverage than it bought.
    """
    endpoints = _terminal_surface(30)
    agent = _agent(max_plan_tasks=150)
    agent._resolve_terminal_class_reservation(_scan(endpoints))
    assert agent._terminal_reserved == len(TERMINAL_DISPATCH_CLASSES)

    plan = agent._build_deterministic_plan(endpoints, [], [])
    before = len(plan.tasks)
    merged = agent._merge_terminal_class_tasks(plan)

    assert set(TERMINAL_DISPATCH_CLASSES) <= {t.test_method for t in plan.tasks}, (
        "the cap was never binding here, so the terminal classes were already planned"
    )
    assert len(merged.tasks) == before + agent._terminal_reserved, (
        "an unspent reserved slot must return to the Tier-1 fill rather than shrink "
        f"the plan — {before} tasks before, {len(merged.tasks)} after"
    )
    assert len(merged.tasks) <= agent._max_plan_task_cap()


def test_an_unspent_reservation_costs_the_plan_nothing_at_all() -> None:
    """Not "roughly the same plan" — the same TASKS.

    The reservation comes out of the Tier-1 cap, so on every run where the
    terminal classes were reachable anyway it has to hand its slots back to the
    tasks the interleave would have taken next. Handing them back in BUCKET order
    instead was measured giving up an on-surface ``_test_nosqli`` and
    ``_test_idor`` task at a cap of 150 and buying two ``_test_security_headers``
    tasks with them — a reservation that cost coverage on exactly the runs where
    it was unnecessary, which is worse than the starvation it exists to fix.
    """
    endpoints = _terminal_surface(30)
    cap = 150

    baseline = _agent(max_plan_tasks=cap)
    baseline_plan = baseline._build_deterministic_plan(endpoints, [], [])

    reserved = _agent(max_plan_tasks=cap)
    reserved._resolve_terminal_class_reservation(_scan(endpoints))
    assert reserved._terminal_reserved, "this test needs a live reservation to be about"
    merged = reserved._merge_terminal_class_tasks(
        reserved._build_deterministic_plan(endpoints, [], [])
    )

    def keys(plan) -> set[tuple[str, str]]:
        return {(t.test_method, t.endpoint_url) for t in plan.tasks}

    assert keys(merged) == keys(baseline_plan), (
        "the reservation was fully unspent and still changed which tasks the plan "
        f"holds — gave up {sorted(keys(baseline_plan) - keys(merged))} and took "
        f"{sorted(keys(merged) - keys(baseline_plan))}"
    )
    assert len(merged.tasks) == len(baseline_plan.tasks) == cap


def test_what_the_reservation_displaces_when_it_does_spend() -> None:
    """And when the cap IS binding, it displaces exactly what it reserved.

    Two tasks give way, and what they buy is two classes that were otherwise
    absent from the plan entirely — not under-covered, absent. That is the trade
    the reservation makes, stated as a number rather than as a claim.
    """
    endpoints = _terminal_surface(30)
    cap = 12

    baseline = _agent(max_plan_tasks=cap)
    baseline_plan = baseline._build_deterministic_plan(endpoints, [], [])
    assert not {t.test_method for t in baseline_plan.tasks} & set(TERMINAL_DISPATCH_CLASSES)

    reserved = _agent(max_plan_tasks=cap)
    reserved._resolve_terminal_class_reservation(_scan(endpoints))
    merged = reserved._merge_terminal_class_tasks(
        reserved._build_deterministic_plan(endpoints, [], [])
    )

    before = {(t.test_method, t.endpoint_url) for t in baseline_plan.tasks}
    after = {(t.test_method, t.endpoint_url) for t in merged.tasks}
    assert len(before - after) == reserved._terminal_reserved
    assert len(after - before) == reserved._terminal_reserved
    assert {m for m, _ in after - before} == set(TERMINAL_DISPATCH_CLASSES)
    assert len(merged.tasks) == cap


# ---------------------------------------------------------------------------
# The reservation changes plan membership, not dispatch reach
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_early_deadline_still_costs_the_terminal_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``test_breadth_survives_dispatch_deadline``'s exclusion, on a RESERVED plan.

    The two bounds are separate and stay separate. The reservation decides
    whether a terminal class is in the PLAN; the cooperative deadline decides
    whether the dispatcher reaches it. The rotation yields a terminal class only
    once no transient task is left, so a stop before that point costs it whatever
    the plan holds — which is the correct trade, and it is why the reservation
    does not weaken the exclusion the breadth test asserts.

    What the reservation DID change is that the loss is now always a dispatch
    loss. Before it, a small cap could cost the class one stage earlier, silently,
    and the two were indistinguishable in every artifact a run produces.
    """
    endpoints = _terminal_surface(30)
    agent = _agent(max_plan_tasks=12)
    agent._resolve_terminal_class_reservation(_scan(endpoints))
    plan = agent._merge_terminal_class_tasks(agent._build_deterministic_plan(endpoints, [], []))
    assert set(TERMINAL_DISPATCH_CLASSES) <= {t.test_method for t in plan.tasks}, (
        "this test asserts an exclusion on a plan that HOLDS the terminal classes; "
        "without the reservation there would be nothing to exclude"
    )

    agent._tests_run = 0
    agent._stopped_early = False
    agent._stop_margin = 0.0
    agent._deadline_ts = None
    agent._category_max_findings = 5
    agent._category_time_budget = 90.0

    dispatched: list[str] = []
    transient_planned = {t.test_method for t in plan.tasks} - set(TERMINAL_DISPATCH_CLASSES)

    async def _execute(task, cache):  # noqa: ANN001, ANN202 — test double
        dispatched.append(task.test_method)
        if len(dispatched) >= len(transient_planned):
            agent._deadline_ts = time.monotonic() - 1
        return []

    monkeypatch.setattr(agent, "_execute_task", _execute)
    monkeypatch.setattr(agent, "_trace_dispatch_ordinal", lambda task, ordinal: None)
    await agent._step_execute_exploits(plan, None)

    assert agent._stopped_early
    assert not set(dispatched) & set(TERMINAL_DISPATCH_CLASSES), (
        "a terminal class ran while other classes still had work, so every "
        f"observation after it measured a changed target: {dispatched}"
    )


# ---------------------------------------------------------------------------
# Declaration order, in the plan as well as at the dispatch seam
# ---------------------------------------------------------------------------


def test_the_category_order_lists_the_terminal_classes_in_declaration_order() -> None:
    """The dispatcher enforces the order; the plan should not disagree with it.

    A wrong position here is caught rather than obeyed — but a reader who checks
    one table against the other should find them saying the same thing.
    """
    positions = [
        _DETERMINISTIC_CATEGORY_ORDER.index(m)
        for m in TERMINAL_DISPATCH_CLASSES
        if m in _DETERMINISTIC_CATEGORY_ORDER
    ]
    assert positions == sorted(positions), (
        "the deterministic category order lists the terminal classes in a different "
        "order from the table the dispatcher enforces"
    )
    tail = _DETERMINISTIC_CATEGORY_ORDER[-len(TERMINAL_DISPATCH_CLASSES) :]
    assert list(tail) == sorted(TERMINAL_DISPATCH_CLASSES, key=terminal_dispatch_rank), (
        f"the terminal classes must be the TAIL of the category order — got {tail}"
    )
