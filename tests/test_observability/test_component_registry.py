"""The ledger's component registry, and the guard that keeps it honest.

The registry has two halves and only one of them is hand-written. The computed
half — every dispatchable vuln class, every route discoverer, every tool named
in a chain — goes red on its own when a member is added. The declared half is
:data:`STATIC_EXPLOIT_COMPONENTS`, and this file is where it earns the right to
be hand-written: an AST walk over ``src/`` collects every statically-named
``record_contribution`` / ``record_dead_seam`` / ``declare_component`` call site
and both differences are asserted.

* ``computed - declared`` catches a new statically-named component nobody
  declared — the one the ledger would then only know about if it happened to
  run.
* ``declared - computed`` catches an entry that outlived the call site it
  described, which is how a guard rots into documentation of a wish.

Only the first half of that pair is the obvious one, and a guard with only the
first half is exactly what this repo has shipped six times.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS
from clinkz.observability.component_registry import (
    DISCOVERER_PREFIX,
    METHODOLOGY_PREFIX,
    PREDICATES,
    STATIC_EXPLOIT_COMPONENTS,
    EngagementReachability,
    ReachabilityKey,
    ReachabilitySource,
    declare_all,
    declared_components,
)
from clinkz.observability.ledger import (
    ComponentKind,
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)
from clinkz.tools.resolver import TOOL_CHAINS

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "clinkz"

_LEDGER_CALLS = {"record_contribution", "record_dead_seam", "declare_component"}


def _statically_named_ledger_components() -> set[str]:
    """Every ledger call site whose ``name=`` is a plain string literal.

    f-string names (``f"discoverer:{name}"``, ``f"llm:{provider}"``) are excluded
    by construction: they are the computed sources, and their members come from
    the same tables the registry computes from.
    """
    found: set[str] = set()
    for path in sorted(_SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name not in _LEDGER_CALLS:
                continue
            for kw in node.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        found.add(kw.value.value)
    return found


def test_the_ast_walk_finds_call_sites_at_all() -> None:
    """A walk that finds nothing passes both directions vacuously."""
    found = _statically_named_ledger_components()
    assert len(found) >= 5, (
        "the AST walk found almost no statically-named ledger call sites — the "
        f"walk is broken, not the registry: {sorted(found)}"
    )


def test_every_statically_named_component_is_declared() -> None:
    """``computed - declared``: a new call site nobody added to the registry."""
    computed = _statically_named_ledger_components()
    declared = {c.name for c in declared_components()}
    undeclared = computed - declared
    assert not undeclared, (
        "these components record to the ledger under a fixed name but are not "
        "declared at engagement start, so the ledger only learns they exist if "
        "they happen to run — which is precisely the blindness the declaration "
        f"exists to remove. Add them to STATIC_EXPLOIT_COMPONENTS: {sorted(undeclared)}"
    )


def test_every_declared_static_component_still_has_a_call_site() -> None:
    """``declared - computed``: an entry that outlived what it described."""
    computed = _statically_named_ledger_components()
    stale = {c.name for c in STATIC_EXPLOIT_COMPONENTS} - computed
    assert not stale, (
        "these are declared in STATIC_EXPLOIT_COMPONENTS but nothing in src/ "
        "records under that name any more. A declared component with no call "
        "site can only ever be reported as never invoked — a permanent line in "
        f"the deliverable about a component that no longer exists: {sorted(stale)}"
    )


# ---------------------------------------------------------------------------
# The computed sources
# ---------------------------------------------------------------------------


def test_every_dispatchable_class_is_declared() -> None:
    """Domain = the table the dispatcher itself reads, never a curated copy."""
    declared = {c.name for c in declared_components()}
    missing = {f"{METHODOLOGY_PREFIX}{m}" for m in DISPATCHABLE_TEST_METHODS} - declared
    assert not missing, missing


def test_every_chained_tool_is_declared() -> None:
    declared = {c.name for c in declared_components()}
    missing = {t for chain in TOOL_CHAINS.values() for t in chain} - declared
    assert not missing, missing


def test_every_default_discoverer_is_declared() -> None:
    from clinkz.agents._route_discovery import default_discoverers

    declared = {c.name for c in declared_components()}
    missing = {
        f"{DISCOVERER_PREFIX}{getattr(d, 'name', type(d).__name__)}" for d in default_discoverers()
    } - declared
    assert not missing, missing


def test_no_component_can_be_declared_without_a_predicate() -> None:
    """The fourth state — "no predicate declarable" — is a build failure.

    Not a runtime branch: a component whose zero cannot be explained would leave
    the ledger with a fact it can only report as ambiguous, which is the thing
    the split exists to end.
    """
    for component in declared_components():
        assert component.reachability in PREDICATES, (
            f"{component.name} declares reachability={component.reachability!r}, "
            f"which is not in the predicate vocabulary {sorted(PREDICATES)}"
        )


def test_declared_names_are_unique() -> None:
    names = [c.name for c in declared_components()]
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, (
        f"a name declared twice produces one record with whichever kind won: {sorted(duplicates)}"
    )


# ---------------------------------------------------------------------------
# The three rendered states
# ---------------------------------------------------------------------------


#: Every producer reported. The predicates below are being tested on what they
#: SAY, so the source gate has to be open; the gate itself is tested in
#: ``test_reachability_determination.py``.
_ALL_REPORTED = frozenset(ReachabilitySource)


def _ledger_with(name: str, kind: ComponentKind, key: ReachabilityKey) -> ContributionLedger:
    ledger = ContributionLedger(engagement_id="registry-test")
    ledger.declare(name, kind, reachability=key.value)
    return ledger


def test_reachable_and_not_invoked_is_an_alarm() -> None:
    ledger = _ledger_with(
        f"{METHODOLOGY_PREFIX}_test_sqli",
        ComponentKind.METHODOLOGY,
        ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
    )
    ledger.resolve_reachability(
        EngagementReachability(
            classes_with_plan_candidates=frozenset({"_test_sqli"}),
            reported_sources=_ALL_REPORTED,
        )
    )
    alarming = {r.name: r.alarms for r in ledger.alarming()}
    assert alarming[f"{METHODOLOGY_PREFIX}_test_sqli"] == [LedgerAlarm.BUILT_BUT_NOT_RUN]


def test_unreachable_and_not_invoked_is_not_an_alarm_and_states_the_predicate() -> None:
    ledger = _ledger_with(
        f"{METHODOLOGY_PREFIX}_test_sqli",
        ComponentKind.METHODOLOGY,
        ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
    )
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    assert not ledger.alarming(), (
        "a class the target has no surface for is the component working, not a "
        "defect — reporting it as one is how an alarm section stops being read"
    )
    (record,) = ledger.unreachable()
    assert record.reachable is False
    assert "_test_sqli" in record.reachability_reason
    assert "no endpoint" in record.reachability_reason


def test_an_invoked_component_is_never_evaluated_at_all() -> None:
    ledger = _ledger_with("nmap", ComponentKind.TOOL, ReachabilityKey.EXPLOIT_PLAN_BUILT)
    ledger.record(name="nmap", kind=ComponentKind.TOOL, items=3)
    ledger.resolve_reachability(EngagementReachability(reported_sources=_ALL_REPORTED))
    (record,) = ledger.records()
    assert record.reachable is None, (
        "for a component that ran, the ledger's ordinary accounting is the answer; "
        "a predicate would add a second, weaker one"
    )
    assert not record.alarms


def test_an_unevaluated_predicate_never_alarms() -> None:
    """``None`` is not ``False`` and it is not ``True``.

    A direct methodology invocation, a replay, a run that stopped before the
    report — none of them evaluate anything, and an observability layer must not
    manufacture a defect out of its own absence.
    """
    ledger = _ledger_with(
        f"{METHODOLOGY_PREFIX}_test_sqli",
        ComponentKind.METHODOLOGY,
        ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
    )
    assert not ledger.alarming()
    (record,) = ledger.records()
    assert record.reachable is None


def test_a_predicate_that_raises_leaves_the_record_unevaluated() -> None:
    ledger = _ledger_with(
        f"{METHODOLOGY_PREFIX}_test_sqli",
        ComponentKind.METHODOLOGY,
        ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES,
    )
    ledger.resolve_reachability(object())  # not an EngagementReachability
    (record,) = ledger.records()
    assert record.reachable is None
    assert not record.alarms


# ---------------------------------------------------------------------------
# The tool predicate — the one with three distinct "no" answers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "expected_fragment"),
    [
        (
            EngagementReachability(
                requested_capabilities=frozenset(),
                available_chain_by_capability={"directory_fuzzing": ("ffuf", "gobuster")},
            ),
            "no phase asked the resolver for directory_fuzzing",
        ),
        (
            EngagementReachability(
                requested_capabilities=frozenset({"directory_fuzzing"}),
                available_chain_by_capability={"directory_fuzzing": ("ffuf", "gobuster")},
            ),
            "declared fallback",
        ),
        (
            EngagementReachability(
                requested_capabilities=frozenset({"directory_fuzzing"}),
                available_chain_by_capability={"directory_fuzzing": ()},
            ),
            "not available in this execution mode",
        ),
    ],
)
def test_a_tool_that_did_not_run_says_which_kind_of_no_it_was(
    state: EngagementReachability, expected_fragment: str
) -> None:
    """Three reasons a tool never ran, three different follow-ups.

    Nobody asked for its capability (nuclei, subfinder — both deliberately
    unwired); it is a declared fallback and the preferred tool answered; or it is
    not installed here. Collapsing them into "did not run" is what would make
    this a permanent alarm for the first kind.
    """
    predicate = PREDICATES[ReachabilityKey.TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY]
    assert not predicate.holds(state, "gobuster")
    assert expected_fragment in predicate.describe(state, "gobuster")


def test_the_chosen_tool_is_reachable() -> None:
    predicate = PREDICATES[ReachabilityKey.TOOL_CHOSEN_FOR_A_REQUESTED_CAPABILITY]
    state = EngagementReachability(
        requested_capabilities=frozenset({"directory_fuzzing"}),
        available_chain_by_capability={"directory_fuzzing": ("ffuf", "gobuster")},
    )
    assert predicate.holds(state, "ffuf")


def test_asking_the_resolver_for_a_chain_at_report_time_is_not_a_request() -> None:
    """A question ABOUT the run must not become part of what the run did."""
    from clinkz.tools.resolver import ToolResolver

    resolver = ToolResolver()
    resolver.available_chain("port_scanning")
    assert "port_scanning" not in resolver.requested_capabilities
    resolver.find_tools_ranked("port_scanning")
    assert "port_scanning" in resolver.requested_capabilities


# ---------------------------------------------------------------------------
# Absent by default
# ---------------------------------------------------------------------------


def test_declaring_with_no_active_ledger_is_a_no_op() -> None:
    set_active_ledger(None)
    assert declare_all() == 0


def test_declare_all_declares_everything_on_the_active_ledger() -> None:
    ledger = ContributionLedger(engagement_id="declare-all")
    set_active_ledger(ledger)
    try:
        count = declare_all()
    finally:
        set_active_ledger(None)
    assert count == len(declared_components())
    assert {r.name for r in ledger.records()} == {c.name for c in declared_components()}
    assert not ledger.alarming(), (
        "declaration alone must not alarm — nothing has been evaluated yet"
    )
