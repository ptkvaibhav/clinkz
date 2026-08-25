"""What this engine HAS, declared before the run — and whether the run could reach it.

The contribution ledger measures what each component contributed. It cannot
measure a component that never registers, and the module's own docstring says
so: *"a component absent from the ledger reads exactly like one that was never
built."* Exactly one call site in the whole engine called ``declare_component``,
for LLM providers. Everything else appeared only if something invoked it — so
the class that never dispatched, the discoverer that never ran, and the tool the
resolver never found produced identical artifacts: nothing at all.

Declaring is only half the fix. "Declared and never invoked" is a fact with two
opposite readings:

* the component was **reachable** this engagement and did not run — a defect;
* the component's **precondition was absent** — a GraphQL discoverer on an app
  with no GraphQL, a SQL class on a target with no parameterised surface — which
  is the component working perfectly.

Reporting the second as a defect is how an alarm section stops being read, and
the ledger already refuses that conflation for *invoked* components
(``correctly_empty``). This module extends the same discipline to components
that never ran at all.

**Reachability is a computed predicate, never a string.** A free-text
``reachable_because`` on each entry is a hand-maintained excuse list, and every
hand-maintained guard domain in this repo has drifted — six times in six weeks,
most recently a completeness assertion whose domain held 27 of 30 dispatchable
classes, so the three that most needed it exited the check instead of failing
it. A sentence describing a predicate cannot go stale in the same way, because
it describes the FUNCTION, not the component: one description per predicate, not
one per entry.

**The timing is split, because it has to be.** Existence is knowable at
engagement start — the engine's own dispatch table, discoverer set and tool
chains are static. Reachability is not: whether the target has a SQL surface is
something only Scan can answer, and the exploit plan does not exist yet. So:

* :func:`declare_all` runs at engagement start, right after ``set_active_ledger``;
* :func:`engagement_reachability` is assembled at REPORT time, when the phases
  have finished, and handed to ``ContributionLedger.resolve_reachability``.

Three rendered states then fall out of one boolean:

===========================  ==========  ===================================
predicate                    invoked     rendering
===========================  ==========  ===================================
``True``                     no          **ALARM** — built, reachable, never ran
``False``                    no          NOT APPLICABLE, the predicate is the reason
(any)                        yes         the ledger's ordinary accounting
===========================  ==========  ===================================

A component with no declarable predicate is the fourth state, and it does not
exist: :data:`STATIC_EXPLOIT_COMPONENTS` entries carry a predicate key from a
closed vocabulary and the computed sources assign one per source, so a member
that cannot state its reachability cannot be added at all.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from clinkz.observability.ledger import ComponentKind, get_active_ledger

logger = logging.getLogger(__name__)

#: Prefix for a per-vuln-class methodology component. The suffix is the
#: ``_test_*`` name VERBATIM — never a derived "skill" — because guessing
#: ``_test_x -> "x"`` is right 23 times and wrong for ``_test_javascript_attacks``,
#: and a mis-derived key reports zero coverage, which reads exactly like a class
#: that never ran.
METHODOLOGY_PREFIX = "methodology:"

#: Prefix the route-discovery seam already registers under.
DISCOVERER_PREFIX = "discoverer:"


class ReachabilityKey(StrEnum):
    """The closed vocabulary of reachability predicates.

    Closed on purpose. Each member is a QUESTION about engagement state that a
    function answers; adding a component means choosing one of these, and adding
    a new question means writing the function that answers it. Neither is
    something a component can opt out of.
    """

    #: The exploit plan held at least one candidate task for this vuln class —
    #: i.e. some endpoint carried the surface the class attacks. Pre-cap, so
    #: "the cap dropped them all" still counts as reachable.
    CLASS_HAD_PLAN_CANDIDATES = "class_had_plan_candidates"
    #: The scan discovered at least one HTTP endpoint for route discovery to mine.
    HTTP_SURFACE_DISCOVERED = "http_surface_discovered"
    #: Some phase asked the resolver for a capability this tool is chained under,
    #: AND this tool was the first available tool in that chain.
    TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY = "tool_chosen_for_a_requested_capability"
    #: The exploit phase built a plan (it reached step 1).
    EXPLOIT_PLAN_BUILT = "exploit_plan_built"
    #: The exploit phase dispatched at least one task.
    EXPLOIT_TASK_DISPATCHED = "exploit_task_dispatched"
    #: At least one methodology produced a candidate finding, so the emission
    #: chokepoint had something to examine.
    EXPLOIT_PRODUCED_A_CANDIDATE_FINDING = "exploit_produced_a_candidate_finding"
    #: At least one never-sent control arm refused to refuse — the only event
    #: the control-arm component registers on.
    CONTROL_ARM_KILLED_A_CANDIDATE = "control_arm_killed_a_candidate"
    #: The planner produced at least one Tier-2/3 research technique task.
    TIER23_TECHNIQUE_PLANNED = "tier23_technique_planned"


@dataclass(frozen=True)
class EngagementReachability:
    """Engagement state complete enough to answer every predicate.

    Assembled at report time, from phase results the orchestrator already holds.
    Every field defaults to the "nothing happened" value, so a partially
    completed engagement — a halt, a phase that errored — evaluates predicates
    to ``False`` and reports its unreached components as NOT APPLICABLE rather
    than as a wall of alarms about work a kill switch stopped.
    """

    classes_with_plan_candidates: frozenset[str] = frozenset()
    http_endpoints_discovered: int = 0
    requested_capabilities: frozenset[str] = frozenset()
    #: Capability → the tool chain filtered to what was actually available, in
    #: declared preference order. Read for BOTH halves of the tool predicate.
    available_chain_by_capability: dict[str, tuple[str, ...]] = field(default_factory=dict)
    exploit_plan_tasks: int = 0
    exploit_tasks_dispatched: int = 0
    exploit_candidate_findings: int = 0
    control_arm_kills: int = 0
    tier23_tasks_planned: int = 0


@dataclass(frozen=True)
class ReachabilityPredicate:
    """One question about engagement state, and how to say the answer.

    ``describe`` takes the component name because the sentence names the
    component — but the SENTENCE is the predicate's, written once, so it cannot
    drift entry by entry the way a per-component reason does.
    """

    key: ReachabilityKey
    holds: Callable[[EngagementReachability, str], bool]
    describe: Callable[[EngagementReachability, str], str]


def _class_had_candidates(state: EngagementReachability, name: str) -> bool:
    return name.removeprefix(METHODOLOGY_PREFIX) in state.classes_with_plan_candidates


def _describe_class_candidates(state: EngagementReachability, name: str) -> str:
    method = name.removeprefix(METHODOLOGY_PREFIX)
    return (
        f"the exploit plan held no candidate for {method}: no endpoint the scan "
        f"discovered carried this class's surface, so there was nothing to dispatch "
        f"it against ({len(state.classes_with_plan_candidates)} class(es) did have one)"
    )


def _chosen_tool_capabilities(state: EngagementReachability, tool: str) -> list[str]:
    """Capabilities the run asked for where *tool* was the first available choice."""
    return sorted(
        capability
        for capability in state.requested_capabilities
        if (chain := state.available_chain_by_capability.get(capability)) and chain[0] == tool
    )


def _tool_was_chosen(state: EngagementReachability, name: str) -> bool:
    return bool(_chosen_tool_capabilities(state, name))


def _describe_tool_not_chosen(state: EngagementReachability, name: str) -> str:
    asked_for = sorted(
        capability
        for capability, chain in state.available_chain_by_capability.items()
        if name in chain and capability in state.requested_capabilities
    )
    if not asked_for:
        chained_under = sorted(
            capability
            for capability, chain in state.available_chain_by_capability.items()
            if name in chain
        )
        if not chained_under:
            return (
                f"{name} was not available in this execution mode, so no chain it is "
                "declared in could resolve to it"
            )
        return (
            f"no phase asked the resolver for {' or '.join(chained_under)}, the "
            f"capability {name} implements"
        )
    preferred = {
        capability: state.available_chain_by_capability[capability][0] for capability in asked_for
    }
    return f"{name} is a declared fallback, not this run's choice: " + "; ".join(
        f"{cap} resolved to {tool}" for cap, tool in sorted(preferred.items())
    )


def _describe_no_http_surface(state: EngagementReachability, name: str) -> str:
    return (
        f"the scan discovered no HTTP endpoint, so route discovery never ran and "
        f"{name} had no input of any kind to read"
    )


def _counter_predicate(
    key: ReachabilityKey,
    read: Callable[[EngagementReachability], int],
    absent: str,
) -> ReachabilityPredicate:
    """A predicate that holds when an engagement counter is non-zero."""
    return ReachabilityPredicate(
        key=key,
        holds=lambda state, _name: read(state) > 0,
        describe=lambda _state, _name: absent,
    )


#: Every predicate, by key. The one place a reachability question is answered.
PREDICATES: dict[ReachabilityKey, ReachabilityPredicate] = {
    ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES: ReachabilityPredicate(
        key=ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
        holds=_class_had_candidates,
        describe=_describe_class_candidates,
    ),
    ReachabilityKey.HTTP_SURFACE_DISCOVERED: ReachabilityPredicate(
        key=ReachabilityKey.HTTP_SURFACE_DISCOVERED,
        holds=lambda state, _name: state.http_endpoints_discovered > 0,
        describe=_describe_no_http_surface,
    ),
    ReachabilityKey.TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY: ReachabilityPredicate(
        key=ReachabilityKey.TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY,
        holds=_tool_was_chosen,
        describe=_describe_tool_not_chosen,
    ),
    ReachabilityKey.EXPLOIT_PLAN_BUILT: _counter_predicate(
        ReachabilityKey.EXPLOIT_PLAN_BUILT,
        lambda state: state.exploit_plan_tasks,
        "the exploit phase produced no plan, so nothing downstream of planning was reached",
    ),
    ReachabilityKey.EXPLOIT_TASK_DISPATCHED: _counter_predicate(
        ReachabilityKey.EXPLOIT_TASK_DISPATCHED,
        lambda state: state.exploit_tasks_dispatched,
        "the exploit phase dispatched no task, so this component was never on a live path",
    ),
    ReachabilityKey.EXPLOIT_PRODUCED_A_CANDIDATE_FINDING: _counter_predicate(
        ReachabilityKey.EXPLOIT_PRODUCED_A_CANDIDATE_FINDING,
        lambda state: state.exploit_candidate_findings,
        "no methodology produced a candidate finding, so the emission path had nothing to examine",
    ),
    ReachabilityKey.CONTROL_ARM_KILLED_A_CANDIDATE: _counter_predicate(
        ReachabilityKey.CONTROL_ARM_KILLED_A_CANDIDATE,
        lambda state: state.control_arm_kills,
        "no control arm refused to refuse this run, which is the only event this "
        "component registers on — every dispatched arm behaved",
    ),
    ReachabilityKey.TIER23_TECHNIQUE_PLANNED: _counter_predicate(
        ReachabilityKey.TIER23_TECHNIQUE_PLANNED,
        lambda state: state.tier23_tasks_planned,
        "the plan held no Tier-2/3 research technique task",
    ),
}


@dataclass(frozen=True)
class DeclaredComponent:
    """One component this engine has, and the question that decides its zero."""

    name: str
    kind: ComponentKind
    reachability: ReachabilityKey


#: The statically-named exploit components, DECLARED — the only part of the
#: registry a human maintains, and the reason
#: ``test_component_registry`` asserts it against an AST walk in BOTH
#: directions: ``computed - declared`` catches a new ``record_contribution``
#: site nobody declared, ``declared - computed`` catches an entry that outlived
#: the call site it described. Every other source below is computed.
#:
#: Not here on purpose: ``llm:<provider>``, which ``llm/fallback.py`` already
#: declares at the seam that knows which providers a run's chain actually holds,
#: and the prompt-cache component, which is off by default.
STATIC_EXPLOIT_COMPONENTS: tuple[DeclaredComponent, ...] = (
    DeclaredComponent(
        name="exploit.plan_llm",
        kind=ComponentKind.LLM,
        reachability=ReachabilityKey.EXPLOIT_PLAN_BUILT,
    ),
    DeclaredComponent(
        name="exploit.component_cve_match",
        kind=ComponentKind.METHODOLOGY,
        reachability=ReachabilityKey.EXPLOIT_PLAN_BUILT,
    ),
    DeclaredComponent(
        name="exploit.fp_cross_check",
        kind=ComponentKind.LLM,
        reachability=ReachabilityKey.EXPLOIT_TASK_DISPATCHED,
    ),
    DeclaredComponent(
        name="exploit.methodology_checkpoint",
        kind=ComponentKind.LLM,
        reachability=ReachabilityKey.EXPLOIT_TASK_DISPATCHED,
    ),
    DeclaredComponent(
        name="exploit.emission_gate",
        kind=ComponentKind.METHODOLOGY,
        reachability=ReachabilityKey.EXPLOIT_PRODUCED_A_CANDIDATE_FINDING,
    ),
    DeclaredComponent(
        name="exploit.control_arm",
        kind=ComponentKind.METHODOLOGY,
        reachability=ReachabilityKey.CONTROL_ARM_KILLED_A_CANDIDATE,
    ),
    DeclaredComponent(
        name="exploit.tier23_technique",
        kind=ComponentKind.METHODOLOGY,
        reachability=ReachabilityKey.TIER23_TECHNIQUE_PLANNED,
    ),
    DeclaredComponent(
        name="chain_planner",
        kind=ComponentKind.COMPOSER,
        reachability=ReachabilityKey.EXPLOIT_PRODUCED_A_CANDIDATE_FINDING,
    ),
)


def declared_components() -> list[DeclaredComponent]:
    """Every component this engine has, computed from the engine's own tables.

    Four sources, three of them COMPUTED so a new member fails loudly rather
    than silently missing from the ledger:

    * :data:`~clinkz.agents.exploit.DISPATCHABLE_TEST_METHODS` — the table the
      dispatcher itself reads, so a new vuln class is declared the moment it can
      be dispatched;
    * :func:`~clinkz.agents._route_discovery.default_discoverers` — instantiated
      and asked for its own ``name``, never a literal list of four;
    * :data:`~clinkz.tools.resolver.TOOL_CHAINS` — every tool named in a chain,
      including the fallbacks that only fire when a preferred tool is absent;
    * :data:`STATIC_EXPLOIT_COMPONENTS` — the declared half.

    Imports are deferred into the function body. ``observability`` is a leaf that
    ``agents`` and ``tools`` both import, so pulling them in at module scope
    would invert the layering and cycle.
    """
    from clinkz.agents._route_discovery import default_discoverers
    from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS
    from clinkz.tools.resolver import TOOL_CHAINS

    components: list[DeclaredComponent] = [
        DeclaredComponent(
            name=f"{METHODOLOGY_PREFIX}{method}",
            kind=ComponentKind.METHODOLOGY,
            reachability=ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
        )
        for method in sorted(DISPATCHABLE_TEST_METHODS)
    ]
    components += [
        DeclaredComponent(
            name=f"{DISCOVERER_PREFIX}{getattr(d, 'name', type(d).__name__)}",
            kind=ComponentKind.DISCOVERER,
            reachability=ReachabilityKey.HTTP_SURFACE_DISCOVERED,
        )
        for d in default_discoverers()
    ]
    components += [
        DeclaredComponent(
            name=tool,
            kind=ComponentKind.TOOL,
            reachability=ReachabilityKey.TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY,
        )
        for tool in sorted({t for chain in TOOL_CHAINS.values() for t in chain})
    ]
    components += list(STATIC_EXPLOIT_COMPONENTS)
    return components


def declare_all() -> int:
    """Declare every component on the active ledger. Called at engagement start.

    No-ops when no ledger is installed, like every other hook here: a smoke
    cell, a replay or a directly invoked methodology is byte-identical.

    Returns:
        How many components were declared (``0`` when there is no ledger).
    """
    ledger = get_active_ledger()
    if ledger is None:
        return 0
    declared = 0
    try:
        for component in declared_components():
            ledger.declare(
                component.name,
                component.kind,
                reachability=component.reachability.value,
            )
            declared += 1
    except Exception as exc:  # noqa: BLE001 — never raise from the data path
        logger.debug("Component declaration failed after %d: %s", declared, exc)
    return declared


__all__ = [
    "DISCOVERER_PREFIX",
    "METHODOLOGY_PREFIX",
    "PREDICATES",
    "STATIC_EXPLOIT_COMPONENTS",
    "DeclaredComponent",
    "EngagementReachability",
    "ReachabilityKey",
    "ReachabilityPredicate",
    "declare_all",
    "declared_components",
]
