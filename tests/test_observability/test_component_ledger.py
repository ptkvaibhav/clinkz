"""The component-contribution ledger — the gate the three silent defects evaded.

Every test here starves a component deliberately and asserts the run says so.
That is the whole point: each of the three defects produced a healthy-looking
run, so a test that only checks the happy path re-creates the blindness.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.observability.ledger import (
    ComponentKind,
    ContributionLedger,
    LedgerAlarm,
    declare_component,
    get_active_ledger,
    record_contribution,
    record_dead_seam,
    record_fallback,
    set_active_ledger,
)


@pytest.fixture
def ledger() -> ContributionLedger:
    """An installed ledger, uninstalled again afterwards."""
    led = ContributionLedger(engagement_id="test-engagement")
    set_active_ledger(led)
    try:
        yield led
    finally:
        set_active_ledger(None)


# ---------------------------------------------------------------------------
# Absent by default
# ---------------------------------------------------------------------------


def test_no_ledger_installed_means_every_helper_is_a_no_op() -> None:
    """A direct invocation installs no ledger and must be byte-identical.

    The governor's rule, applied here: a smoke cell, a replay, or a driver runs
    with no engagement, and an observability layer that changes behaviour in
    that case has changed the black-box floor.
    """
    set_active_ledger(None)
    assert get_active_ledger() is None
    # None of these may raise, and none may create a ledger.
    record_contribution(name="ffuf", kind=ComponentKind.TOOL, items=3)
    record_dead_seam(name="ffuf", kind=ComponentKind.TOOL, note="x")
    record_fallback(component="a", covered_by="b", reason="c")
    declare_component(name="nuclei", kind=ComponentKind.TOOL)
    assert get_active_ledger() is None


# ---------------------------------------------------------------------------
# Defect 1 — the LLM planner returned nothing and the class floor covered
# ---------------------------------------------------------------------------


def test_starved_llm_planner_is_reported_as_contributing_zero(
    ledger: ContributionLedger,
) -> None:
    """Planner invoked, succeeded, produced no tasks — the run must say so."""
    record_contribution(name="exploit.plan_llm", kind=ComponentKind.LLM, items=0, ok=True)
    record_fallback(
        component="exploit.plan_llm",
        covered_by="exploit.class_floor",
        reason="LLM plan was empty",
    )

    alarming = ledger.alarming()
    names = [r.name for r in alarming]
    assert "exploit.plan_llm" in names

    rec = next(r for r in alarming if r.name == "exploit.plan_llm")
    assert LedgerAlarm.SILENT in rec.alarms, "a succeeded-but-empty planner is SILENT"
    assert LedgerAlarm.FALLBACK_ACTIVATED in rec.alarms, "the floor covering for it is recorded"
    assert rec.invocations == 1
    assert rec.items_contributed == 0

    payload = ledger.to_dict()
    assert payload["summary"]["silent_components"] == 1
    assert payload["summary"]["fallback_activations"] == 1
    assert payload["fallbacks"][0]["covered_by"] == "exploit.class_floor"


def test_a_planner_that_contributed_tasks_does_not_alarm(ledger: ContributionLedger) -> None:
    """The control. A working component must produce no alarm at all."""
    record_contribution(name="exploit.plan_llm", kind=ComponentKind.LLM, items=12, ok=True)
    assert ledger.alarming() == []
    assert ledger.to_dict()["summary"]["components_alarming"] == 0


# ---------------------------------------------------------------------------
# Defect 2 — a provider timed out and the fallback chain covered
# ---------------------------------------------------------------------------


def test_provider_rotation_names_who_failed_and_who_covered(
    ledger: ContributionLedger,
) -> None:
    """A timeout absorbed by fallback still produced an answer. Record both."""
    record_contribution(
        name="llm:anthropic", kind=ComponentKind.LLM_PROVIDER, ok=False, note="LLMTimeoutError"
    )
    record_contribution(name="llm:gemini", kind=ComponentKind.LLM_PROVIDER, items=1, ok=True)
    record_fallback(component="llm:anthropic", covered_by="llm:gemini", reason="LLMTimeoutError")

    payload = ledger.to_dict()
    primary = next(c for c in payload["components"] if c["component"] == "llm:anthropic")
    backup = next(c for c in payload["components"] if c["component"] == "llm:gemini")

    assert primary["invocations"] == 1 and primary["successes"] == 0
    assert LedgerAlarm.ALL_FAILED.value in primary["alarms"]
    # A provider that only ever failed is ALL_FAILED, never SILENT — conflating
    # them would report "produced nothing" about a component that never ran to
    # completion, which is a different defect with a different fix.
    assert LedgerAlarm.SILENT.value not in primary["alarms"]
    assert backup["alarms"] == []
    assert payload["fallbacks"] == [
        {"component": "llm:anthropic", "covered_by": "llm:gemini", "reason": "LLMTimeoutError"}
    ]


# ---------------------------------------------------------------------------
# Defect 3 — the ffuf seam: a structurally unsatisfiable contract
# ---------------------------------------------------------------------------


def test_dead_seam_outranks_a_merely_silent_component(ledger: ContributionLedger) -> None:
    """A seam that CANNOT contribute is a louder fact than one that did not."""
    record_dead_seam(
        name="ffuf",
        kind=ComponentKind.TOOL,
        note="FfufOutput declares no discovered_urls() contract",
    )
    record_contribution(name="katana", kind=ComponentKind.TOOL, items=0, ok=True)

    alarming = ledger.alarming()
    assert alarming[0].name == "ffuf", "dead seams sort ahead of silent components"
    assert LedgerAlarm.DEAD_SEAM in alarming[0].alarms
    assert LedgerAlarm.SILENT in next(r for r in alarming if r.name == "katana").alarms
    assert ledger.to_dict()["summary"]["dead_seams"] == 1


# ---------------------------------------------------------------------------
# Declared-but-never-invoked is a different fact
# ---------------------------------------------------------------------------


def test_declared_but_never_invoked_is_not_reported_as_silent(
    ledger: ContributionLedger,
) -> None:
    """A capability the run never reached for did not degrade — it never ran.

    Reporting it as "contributed zero" would bury the real alarms under noise
    from every tool that simply was not applicable to this target.
    """
    declare_component(name="llm:openai", kind=ComponentKind.LLM_PROVIDER)
    record_contribution(name="llm:gemini", kind=ComponentKind.LLM_PROVIDER, items=1, ok=True)

    assert [r.name for r in ledger.never_invoked()] == ["llm:openai"]
    assert ledger.alarming() == []
    assert ledger.to_dict()["never_invoked"] == ["llm:openai"]


# ---------------------------------------------------------------------------
# The report has to be LOUD
# ---------------------------------------------------------------------------


def test_summary_logs_silent_components_at_warning(
    ledger: ContributionLedger, caplog: pytest.LogCaptureFixture
) -> None:
    """A silent component logged at DEBUG is still a silent component."""
    record_contribution(name="ffuf", kind=ComponentKind.TOOL, items=0, ok=True)
    log = logging.getLogger("test.ledger")
    with caplog.at_level(logging.WARNING, logger="test.ledger"):
        ledger.log_summary(log)

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("COMPONENT LEDGER" in m for m in warnings)
    assert any("CONTRIBUTED 0" in m and "ffuf" in m for m in warnings)


def test_summary_is_quiet_when_every_component_contributed(
    ledger: ContributionLedger, caplog: pytest.LogCaptureFixture
) -> None:
    """A gate that cries wolf is a gate nobody reads."""
    record_contribution(name="katana", kind=ComponentKind.TOOL, items=40, ok=True)
    log = logging.getLogger("test.ledger.quiet")
    with caplog.at_level(logging.DEBUG, logger="test.ledger.quiet"):
        ledger.log_summary(log)

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# ---------------------------------------------------------------------------
# The ledger must never break a run
# ---------------------------------------------------------------------------


def test_notes_are_bounded(ledger: ContributionLedger) -> None:
    """A run makes thousands of calls; the ledger is a summary, not a trace."""
    for i in range(50):
        record_contribution(name="ffuf", kind=ComponentKind.TOOL, items=0, note=f"note-{i}")
    rec = next(r for r in ledger.records() if r.name == "ffuf")
    assert len(rec.notes) <= 8
    assert rec.invocations == 50


def test_a_broken_ledger_never_propagates_into_the_data_path() -> None:
    """Observability that can abort a scan is worse than the blindness it fixes."""

    class Exploding(ContributionLedger):
        def record(self, **kwargs: object) -> None:
            raise RuntimeError("ledger is broken")

    set_active_ledger(Exploding())
    try:
        record_contribution(name="ffuf", kind=ComponentKind.TOOL, items=1)
    finally:
        set_active_ledger(None)


# ---------------------------------------------------------------------------
# The serialized shape: which keys are populations and which are views
# ---------------------------------------------------------------------------


def test_alarms_are_a_subset_view_not_a_second_population(
    ledger: ContributionLedger,
) -> None:
    """An alarming component appears in BOTH keys, and that is containment.

    ``exploit.component_cve_match`` was reported as a duplicate registration on
    the first non-benchmark run: it appears twice in ``component_ledger`` with
    byte-identical content. It has exactly one ``record_contribution`` site. The
    duplication is ``alarms`` being a re-serialized view of the alarming subset
    of ``components``, kept in full because four consumers render a row straight
    from it.

    Pinned because the containment is what decides whether a consumer may sum.
    Nothing unions the two today, and every alarming component has contributed
    zero items by definition, so a union would be invisible until the moment a
    component alarms while carrying real items -- which is exactly what a
    populated CVE inventory would produce.
    """
    record_contribution(name="silent.tool", kind=ComponentKind.TOOL, items=0, ok=True)
    record_contribution(name="healthy.tool", kind=ComponentKind.TOOL, items=3, ok=True)

    payload = ledger.to_dict()
    population = {c["component"] for c in payload["components"]}
    alarming = {a["component"] for a in payload["alarms"]}

    # A view, never a second population: every alarm names a tracked component.
    assert alarming <= population
    assert alarming == {"silent.tool"}
    # And it is the SAME record, not a parallel one that could drift.
    assert next(a for a in payload["alarms"] if a["component"] == "silent.tool") == next(
        c for c in payload["components"] if c["component"] == "silent.tool"
    )
    # The count a reader trusts comes from the population, so it is unaffected
    # by the alarming subset being rendered a second time.
    assert payload["summary"]["components_tracked"] == len(payload["components"]) == 2
    # The sibling views are references by name, and stay that way.
    assert all(isinstance(n, str) for n in payload["never_invoked"])
    assert all(set(c) == {"component", "reasons"} for c in payload["correctly_empty"])
