"""A dispatch-table entry that can never emit is a capability claim.

``_test_tier2_technique`` and ``_test_tier3_technique`` are both in
:data:`~clinkz.agents.exploit.DISPATCHABLE_TEST_METHODS`. Both delegate to
``_apply_technique``, which has three exits and returns ``[]`` from all of them:
it sends no request to the target and constructs no ``Finding``. It asks the LLM
how the technique *would* be applied and logs the answer.

Nothing said so. Neither class had a vuln-registry entry, so neither appeared in
the report's *What was NOT tested* section, in the dry-run's class list, or
anywhere else a client reads — while the planner spent plan slots on them and the
coverage account expected verdicts from them. A capability the engine claims and
does not have is the one thing a pentest deliverable must never do quietly.

These tests pin the two halves of the disclosure: the registry says the classes
are not implemented, and the run's own ledger says so for the tasks it actually
dispatched.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from clinkz.agents.exploit import (
    DISPATCHABLE_TEST_METHODS,
    ExploitAgent,
    PageAnalysis,
)
from clinkz.models.finding import ExploitTask
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.vuln_classes import (
    DISCOVERY_CLASSES,
    UNIMPLEMENTED_CLASSES,
    VULN_CLASSES,
    ConfirmationCapability,
)
from clinkz.observability.ledger import (
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)

SCOPE = EngagementScope(
    name="tier23",
    targets=[ScopeEntry(type=ScopeType.IP, value="10.0.0.1")],
)

_TIER23 = ("_test_tier2_technique", "_test_tier3_technique")


def _agent() -> ExploitAgent:
    """A bare agent — no LLM client, no network, no state store."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.scope = SCOPE
    agent._logger = logging.getLogger("test.tier23")
    return agent


def _page() -> PageAnalysis:
    return PageAnalysis(url="http://10.0.0.1/x", body="", status=200, input_params=["id"])


def _task(tier: int, steps: list[str] | None) -> ExploitTask:
    return ExploitTask(
        test_method=f"_test_tier{tier}_technique",
        endpoint_url="http://10.0.0.1/x",
        tier=tier,
        technique_name="CVE-2024-0000 exploit chain",
        technique_steps=steps or [],
    )


async def _run(agent: ExploitAgent, tier: int, steps: list[str] | None) -> Any:
    handler = getattr(agent, f"_test_tier{tier}_technique")
    return await handler(_page(), None, _task(tier, steps))


# ---------------------------------------------------------------------------
# The registry half — the client-facing disclosure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", _TIER23)
def test_the_class_is_registered_not_implemented(method: str) -> None:
    entry = next((vc for vc in UNIMPLEMENTED_CLASSES if vc.test_method == method), None)
    assert entry is not None, (
        f"{method} is dispatchable and can never emit, but no registry entry says so — "
        "it is invisible in the report's 'what was NOT tested' section"
    )
    assert entry.capability is ConfirmationCapability.NOT_IMPLEMENTED


@pytest.mark.parametrize("method", _TIER23)
def test_the_limitation_reads_as_a_sentence_a_client_can_act_on(method: str) -> None:
    """It is rendered verbatim into the deliverable."""
    entry = next(vc for vc in UNIMPLEMENTED_CLASSES if vc.test_method == method)
    assert entry.limitation.strip().endswith(".")
    assert len(entry.limitation) > 40
    assert "not" in entry.limitation.lower(), (
        "the limitation has to say the technique was NOT carried out — a client "
        "reading it must not come away thinking the class was tested"
    )


def test_every_dispatchable_method_either_claims_a_capability_or_disclaims_one() -> None:
    """The generalisation: no dispatch-table entry is silent about what it can do.

    The domain is :data:`DISPATCHABLE_TEST_METHODS` — the table the dispatcher
    itself reads — so a method added there is a red build until somebody says
    which side of this line it is on.
    """
    claimed = {
        vc.test_method
        for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES)
        if vc.test_method and vc.capability is not ConfirmationCapability.NOT_IMPLEMENTED
    }
    disclaimed = {
        vc.test_method
        for vc in UNIMPLEMENTED_CLASSES
        if vc.test_method and vc.capability is ConfirmationCapability.NOT_IMPLEMENTED
    }
    undeclared = sorted(set(DISPATCHABLE_TEST_METHODS) - claimed - disclaimed)
    assert undeclared == [], (
        f"{undeclared} are dispatchable but neither claim a confirmation capability "
        "nor disclaim one; a name in the dispatch table is a capability claim"
    )
    assert not (claimed & disclaimed), "a class cannot both claim and disclaim"


# ---------------------------------------------------------------------------
# The run half — the ledger says it for the tasks actually dispatched
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tier", (2, 3))
async def test_a_dispatched_technique_task_is_recorded_as_contributing_nothing(
    tier: int,
) -> None:
    """Steps arrived and nothing was emitted. That stays SILENT.

    A task carrying technique steps is input of exactly this component's kind,
    so the zero is the ffuf shape, not a precondition that was absent — and no
    reason string is allowed to talk it away.
    """
    agent = _agent()
    agent._llm_analyze = _never_called  # type: ignore[method-assign]
    ledger = ContributionLedger(engagement_id="tier23-test")
    set_active_ledger(ledger)
    try:
        findings = await _run(agent, tier, ["step one", "step two"])
    finally:
        set_active_ledger(None)

    assert findings == [], "the applier constructs no Finding — that is the whole point"
    rec = next(r for r in ledger.records() if r.name == "exploit.tier23_technique")
    assert rec.invocations == 1
    assert rec.items_contributed == 0
    assert rec.not_applicable == 0
    assert rec.alarms == [LedgerAlarm.SILENT]
    assert any("UNIMPLEMENTED" in n for n in rec.notes), (
        f"the note must name why the zero is a zero — got {rec.notes}"
    )


@pytest.mark.parametrize("tier", (2, 3))
async def test_a_task_with_no_steps_is_correctly_empty_not_an_alarm(tier: int) -> None:
    """Nothing of this component's kind arrived, so there was nothing to apply."""
    agent = _agent()
    agent._llm_analyze = _never_called  # type: ignore[method-assign]
    ledger = ContributionLedger(engagement_id="tier23-test")
    set_active_ledger(ledger)
    try:
        findings = await _run(agent, tier, [])
    finally:
        set_active_ledger(None)

    assert findings == []
    rec = next(r for r in ledger.records() if r.name == "exploit.tier23_technique")
    assert rec.not_applicable == 1
    assert rec.correctly_empty
    assert rec.alarms == []


async def _never_called(question: str) -> str:
    """Stands in for the methodology LLM. Returning '' takes the logged-guidance exit.

    The exit does not matter — all three return ``[]``. What matters is that the
    ledger row is written before any of them is chosen, so a run cannot spend
    plan slots here and stay quiet about it because the model happened to answer
    ``NOT_APPLICABLE``.
    """
    return ""
