"""The plan cap removes the tail, never a class's own observed surface.

The previous interleave was round-robin over **position inside each class's
bucket** — round N took the Nth-ranked task of every class. It never compared
two tasks from different classes, so the cut fell at the same depth in all of
them: a class holding twenty endpoints where its own attack surface was observed
kept nine and lost eleven, while another class's ninth task — an endpoint nothing
pointed at — survived. That is an ordering defect wearing a budget's clothes, and
the engine's own RANKING FAILURE check reported it in the recorded runs.

The fix bands the interleave by relevance: every class's grade-0 candidates
round-robin first, then every class's grade-1, and so on. Breadth inside a band
is unchanged; what changes is that a band is exhausted before the next begins.

Measured offline against the endpoint sets rebuilt from the recorded DVWA and
Juice Shop engagements (URLs and methods from ``clinkz.db``, ``sets_cookies`` and
``has_form`` re-derived from the recorded ``tool_invocations/`` responses),
on-surface drops go 3/3/3/10/8 → 0 and the worst-kept grade falls from 3 to 2.
That replay is **lossy in one direction**: the state store keeps no
``param_locations``, ``has_dom_source``, ``session_setters`` or ``content_type``,
so preconditions like ``body_param`` and ``dom_source`` cannot be reconstructed
and the replay *under*-counts grade-0 candidates. The fixtures here therefore
carry the full observed feature set a live scan populates, which is where the
mechanism can be proven at the scale the live runs reported.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.agents.exploit import (
    _CLASS_SURFACE_GRADE,
    _DETERMINISTIC_CATEGORY_ORDER,
    ExploitAgent,
    _endpoint_class_relevance,
    _endpoint_class_sort_key,
)
from clinkz.models.scan import Endpoint, ParamLocation


def _agent(cap: int = 150) -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.plan.bands")
    agent._max_plan_tasks = cap
    agent._session_headers = {}
    agent._session_cookies = {}
    agent._unproven_exploit_leads = []
    return agent


def _wide_surface(*, surface_per_class: int = 30) -> list[Endpoint]:
    """A crawl wide enough that the cap binds, with real per-class surface.

    Shaped like the live targets that exposed the defect: a large tail of
    ordinary pages, plus a smaller set of endpoints where a specific class's own
    precondition or parameter shape was OBSERVED. No benchmark's vocabulary —
    the parameter names are the generic ones each class's own ranking vocabulary
    already describes.

    ``surface_per_class`` selects the regime. Small (the default) is the shape
    the recorded DVWA and Juice Shop runs are in: on-surface candidates fit
    inside the cap, so zero on-surface drops is achievable and is the target.
    Large pushes the on-surface work alone past the cap, where drops are the
    budget binding rather than the ordering failing — a different outcome that
    must be reported differently.
    """
    eps: list[Endpoint] = []

    # 1. The tail: plain parameterised pages every class is merely
    #    shape-compatible with. Large enough to fill the cap on its own.
    #    The path is deliberately meaningless: a word like "page" is in
    #    _test_ssti's own path vocabulary, so naming the tail with one would
    #    make 120 tail endpoints that class's observed surface and measure
    #    the fixture rather than the ordering.
    for i in range(120):
        eps.append(
            Endpoint(
                url=f"http://t/n{i}?ref={i}",
                method="GET",
                params=["ref"],
                param_locations={"ref": ParamLocation.QUERY},
            )
        )

    # 2. A DEEP surface for a narrow set of classes: many endpoints carrying a
    #    URL-shaped parameter, which is the fetch/redirect family's own observed
    #    parameter shape and almost nothing else's. This is the shape that
    #    exposed the defect on the live runs — _test_javascript_attacks and
    #    _test_weak_session each held far more on-surface endpoints than the
    #    old round-robin's uniform depth (cap / classes) could reach, so their
    #    surface was cut while other classes' shallow tails survived.
    for i in range(surface_per_class):
        eps.append(
            Endpoint(
                url=f"http://t/outbound{i}?url=https://elsewhere.test/x",
                method="GET",
                params=["url"],
                param_locations={"url": ParamLocation.QUERY},
            )
        )
    return eps


def _buckets(agent: ExploitAgent, endpoints: list[Endpoint]):
    from clinkz.models.finding import ExploitTask

    unique = agent._collapse_structural_duplicates(endpoints)
    buckets: dict[str, list[ExploitTask]] = {}
    for ep in unique:
        for method_name in agent._applicable_methods_for_endpoint(ep):
            buckets.setdefault(method_name, []).append(
                ExploitTask(
                    test_method=method_name,
                    endpoint_url=ep.url,
                    endpoint_params=ep.params,
                    tier=1,
                    priority=0,
                    **agent._endpoint_request_shape(ep),
                )
            )
    by_key = {agent._endpoint_structural_key(ep): ep for ep in unique}
    for method_name, bucket in buckets.items():
        bucket.sort(
            key=lambda t, m=method_name: _endpoint_class_sort_key(
                m, agent._task_endpoint(t, by_key)
            )
        )
    ordered = [m for m in _DETERMINISTIC_CATEGORY_ORDER if m in buckets]
    ordered += [m for m in buckets if m not in _DETERMINISTIC_CATEGORY_ORDER]
    return buckets, ordered, by_key


def _select_by_position(buckets, ordered, cap):
    """The ordering that shipped: round N takes the Nth task of every class."""
    chosen = []
    round_idx = 0
    while len(chosen) < cap:
        progressed = False
        for method_name in ordered:
            bucket = buckets[method_name]
            if round_idx < len(bucket):
                chosen.append(bucket[round_idx])
                progressed = True
                if len(chosen) >= cap:
                    break
        if not progressed:
            break
        round_idx += 1
    return chosen


def _on_surface_drops(agent, buckets, chosen, by_key) -> dict[str, int]:
    kept = {id(t) for t in chosen}
    drops: dict[str, int] = {}
    for method_name, bucket in buckets.items():
        for task in bucket:
            if id(task) in kept:
                continue
            grade = _endpoint_class_relevance(method_name, agent._task_endpoint(task, by_key))
            if grade <= _CLASS_SURFACE_GRADE:
                drops[method_name] = drops.get(method_name, 0) + 1
    return drops


class TestBandedInterleaveRemovesTheTailNotTheSurface:
    def test_the_previous_ordering_dropped_on_surface_tasks(self) -> None:
        """The defect, reproduced — otherwise the fix proves nothing."""
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = _select_by_position({k: list(v) for k, v in buckets.items()}, ordered, 150)
        drops = _on_surface_drops(agent, buckets, chosen, by_key)
        assert sum(drops.values()) > 0, "fixture no longer reproduces the ordering defect"

    def test_the_banded_ordering_drops_none(self) -> None:
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        drops = _on_surface_drops(agent, buckets, chosen, by_key)
        assert drops == {}, f"on-surface tasks still dropped: {drops}"

    def test_the_cap_is_respected(self) -> None:
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        assert len(chosen) == 150

    def test_no_worse_graded_task_is_kept_over_a_better_one(self) -> None:
        """The property the whole change exists to establish.

        Bands are exhausted in order, so outside the per-class floor the worst
        grade kept can never beat the best grade dropped. The floor is excluded
        because it reserves a class's best endpoint *whatever its grade* — that
        is the coverage guarantee, not an ordering failure.
        """
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        floor_keys = agent._last_plan_floor_keys
        kept_ids = {id(t) for t in chosen}
        kept_grades = [
            _endpoint_class_relevance(t.test_method, agent._task_endpoint(t, by_key))
            for t in chosen
            if agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
            not in floor_keys
        ]
        dropped_grades = [
            _endpoint_class_relevance(m, agent._task_endpoint(t, by_key))
            for m, bucket in buckets.items()
            for t in bucket
            if id(t) not in kept_ids
        ]
        if dropped_grades and kept_grades:
            assert max(kept_grades) <= min(dropped_grades), (
                f"kept a grade-{max(kept_grades)} task while dropping a "
                f"grade-{min(dropped_grades)} one"
            )


class TestWhenTheSurfaceItselfExceedsTheCap:
    """Drops are then the budget binding, and must be reported as such."""

    def test_on_surface_work_alone_can_exhaust_the_budget(self) -> None:
        agent = _agent()
        endpoints = _wide_surface(surface_per_class=90)
        buckets, ordered, by_key = _buckets(agent, endpoints)
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        drops = _on_surface_drops(agent, buckets, chosen, by_key)
        assert sum(drops.values()) > 0, "fixture no longer saturates the cap with on-surface work"

    def test_saturation_is_not_reported_as_a_ranking_inversion(self) -> None:
        """An ordering defect reads nothing like a budget ceiling; keep them apart."""
        agent = _agent()
        endpoints = _wide_surface(surface_per_class=90)
        plan = agent._build_deterministic_plan(endpoints, [], [])
        buckets, _ordered, by_key = _buckets(agent, endpoints)

        kept_keys = {
            agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
            for t in plan.tasks
        }
        dropped: dict[str, list[str]] = {}
        grades: dict[str, list[int]] = {}
        for method_name, bucket in buckets.items():
            missed = [
                t
                for t in bucket
                if agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
                not in kept_keys
            ]
            if missed:
                dropped[method_name] = [t.endpoint_url for t in missed]
                grades[method_name] = [
                    _endpoint_class_relevance(method_name, agent._task_endpoint(t, by_key))
                    for t in missed
                ]
        assert agent._ranking_inversions(plan.tasks, dropped, grades, by_key) == []


class TestTheFloorSurvivesTheBanding:
    def test_every_applicable_class_still_gets_a_task(self) -> None:
        """Banding must not starve a class whose whole bucket grades poorly."""
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        planned = {t.test_method for t in chosen}
        assert planned == set(buckets), f"classes with no task at all: {set(buckets) - planned}"

    def test_a_cap_below_the_class_count_says_so(self, caplog: pytest.LogCaptureFixture) -> None:
        """Silent truncation of the floor itself would be the worst kind."""
        agent = _agent(cap=3)
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        with caplog.at_level("WARNING"):
            chosen = agent._interleave_by_relevance_band(
                {k: list(v) for k, v in buckets.items()}, ordered, 3, by_key
            )
        assert len(chosen) == 3
        assert "Plan floor TRUNCATED" in caplog.text


class TestOrderingIsAFunctionOfTheSetNotTheCrawl:
    def test_shuffling_the_endpoint_order_changes_nothing(self) -> None:
        """A concurrent crawler emits a different sequence every run."""
        agent = _agent()
        endpoints = _wide_surface()

        def plan_for(eps: list[Endpoint]) -> list[str]:
            buckets, ordered, by_key = _buckets(agent, eps)
            chosen = agent._interleave_by_relevance_band(
                {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
            )
            return [f"{t.test_method} {t.endpoint_url}" for t in chosen]

        assert plan_for(endpoints) == plan_for(list(reversed(endpoints)))

    def test_priority_is_dense_and_in_dispatch_order(self) -> None:
        agent = _agent()
        buckets, ordered, by_key = _buckets(agent, _wide_surface())
        chosen = agent._interleave_by_relevance_band(
            {k: list(v) for k, v in buckets.items()}, ordered, 150, by_key
        )
        assert [t.priority for t in chosen] == list(range(len(chosen)))


class TestTheWholeDeterministicPlanBenefits:
    def test_the_built_plan_reports_no_ranking_inversion(self) -> None:
        """End to end through the real builder, not just the selection helper."""
        agent = _agent()
        endpoints = _wide_surface()
        plan = agent._build_deterministic_plan(endpoints, [], [])
        buckets, _ordered, by_key = _buckets(agent, endpoints)

        kept_keys = {
            agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
            for t in plan.tasks
        }
        dropped: dict[str, list[str]] = {}
        grades: dict[str, list[int]] = {}
        for method_name, bucket in buckets.items():
            missed = [
                t
                for t in bucket
                if agent._coverage_key(t.test_method, t.endpoint_url, t.endpoint_params)
                not in kept_keys
            ]
            if missed:
                dropped[method_name] = [t.endpoint_url for t in missed]
                grades[method_name] = [
                    _endpoint_class_relevance(method_name, agent._task_endpoint(t, by_key))
                    for t in missed
                ]
        inversions = agent._ranking_inversions(plan.tasks, dropped, grades, by_key)
        assert inversions == [], f"the engine's own check still reports inversions: {inversions}"
