"""Deliberately starve a component and prove the run says so, loudly.

The unit tests in ``test_component_ledger.py`` prove the ledger's own logic. This
proves the WIRING: a real seam, a real starved tool, and the alarm arriving in
all three places an operator looks — the run log, ``report.json``, and the
Markdown deliverable.

This is the gate none of the three silent defects would have survived, so it is
tested by reproducing a silent defect rather than by checking a happy path.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.scan import ScanAgent
from clinkz.models.report import PentestReport
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.ledger import (
    ComponentKind,
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.ffuf import FfufOutput, FfufTool


def _report(**kwargs: Any) -> PentestReport:
    """A minimal PentestReport — only the ledger field is under test here."""
    now = datetime.now(UTC)
    return PentestReport(engagement_name="t", test_start=now, test_end=now, **kwargs)


@pytest.fixture
def scope() -> EngagementScope:
    return EngagementScope(
        name="starvation",
        targets=[ScopeEntry(type=ScopeType.IP, value="172.20.0.2")],
    )


class _StarvedFuzzer(FfufTool):
    """A fuzzer that runs successfully and finds nothing.

    The honest empty result: it declares the contract and returns no URLs.
    Indistinguishable from a real target with no hidden content — which is
    precisely why the run has to SAY it contributed nothing rather than let the
    crawler's endpoints paper over it.
    """

    async def execute(self, args: dict[str, Any]) -> str:
        return json.dumps({"commandline": "ffuf ...", "results": []})


class _BrokenSeamFuzzer(FfufTool):
    """A fuzzer whose output type forgot the contract — the ffuf defect itself."""

    class _Undeclared(ToolOutput):
        results: list[dict[str, Any]] = []

    async def execute(self, args: dict[str, Any]) -> str:
        return "{}"

    def parse_output(self, raw_output: str) -> ToolOutput:
        # It found three paths. None of them can reach the surface map.
        return self._Undeclared(
            tool_name="ffuf",
            success=True,
            results=[{"url": f"http://172.20.0.2/secret{i}"} for i in range(3)],
        )


class _WorkingFuzzer(FfufTool):
    """The control."""

    async def execute(self, args: dict[str, Any]) -> str:
        return json.dumps(
            {
                "commandline": "ffuf ...",
                "results": [
                    {
                        "url": "http://172.20.0.2/admin",
                        "status": 301,
                        "length": 169,
                        "words": 5,
                        "lines": 8,
                    }
                ],
            }
        )


class _FakeMatch:
    def __init__(self, tool_class: type[ToolBase]) -> None:
        self.tool_class = tool_class
        self.available = True
        self.name = "ffuf"


class _FakeResolver:
    def __init__(self, tool_class: type[ToolBase]) -> None:
        self._cls = tool_class

    def find_tool(self, capability: str) -> _FakeMatch:
        return _FakeMatch(self._cls)

    def find_tool_by_name(self, tool_name: str) -> _FakeMatch:
        return _FakeMatch(self._cls)


def _agent(scope: EngagementScope, tool_class: type[ToolBase]) -> ScanAgent:
    agent = ScanAgent.__new__(ScanAgent)
    agent.scope = scope
    agent._resolver = _FakeResolver(tool_class)
    agent._session_cookies = {}
    agent._logger = logging.getLogger("test.starve")
    return agent


async def _run_with_ledger(
    scope: EngagementScope, tool_class: type[ToolBase]
) -> tuple[list[str], ContributionLedger]:
    ledger = ContributionLedger(engagement_id="starve")
    set_active_ledger(ledger)
    try:
        urls = await _agent(scope, tool_class)._run_fuzz_tool("ffuf", "http://172.20.0.2")
    finally:
        set_active_ledger(None)
    return urls, ledger


# ---------------------------------------------------------------------------
# Starve it: succeeded, contributed nothing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_starved_tool_is_reported_as_contributing_zero(
    scope: EngagementScope, caplog: pytest.LogCaptureFixture
) -> None:
    urls, ledger = await _run_with_ledger(scope, _StarvedFuzzer)
    assert urls == []

    rec = next(r for r in ledger.records() if r.name == "ffuf")
    assert rec.invocations == 1 and rec.successes == 1 and rec.items_contributed == 0
    assert LedgerAlarm.SILENT in rec.alarms

    log = logging.getLogger("test.starve.summary")
    with caplog.at_level(logging.WARNING, logger="test.starve.summary"):
        ledger.log_summary(log)
    messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("COMPONENT LEDGER" in m for m in messages)
    assert any("CONTRIBUTED 0" in m and "ffuf" in m for m in messages)


@pytest.mark.asyncio
async def test_a_broken_seam_is_reported_as_structurally_inert(
    scope: EngagementScope, caplog: pytest.LogCaptureFixture
) -> None:
    """The original defect: three paths found, none able to reach the surface."""
    with caplog.at_level(logging.WARNING, logger="test.starve"):
        urls, ledger = await _run_with_ledger(scope, _BrokenSeamFuzzer)

    assert urls == []
    rec = next(r for r in ledger.records() if r.name == "ffuf")
    assert rec.dead_seam
    assert LedgerAlarm.DEAD_SEAM in rec.alarms
    assert any("DEAD SEAM" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_the_working_control_produces_no_alarm(scope: EngagementScope) -> None:
    """A gate that fires on a healthy run is a gate nobody reads."""
    urls, ledger = await _run_with_ledger(scope, _WorkingFuzzer)
    assert urls == ["http://172.20.0.2/admin"]
    assert ledger.alarming() == []


# ---------------------------------------------------------------------------
# The alarm has to reach the deliverable, not just the log
# ---------------------------------------------------------------------------


def test_the_report_renders_the_starved_component(tmp_path: Path) -> None:
    ledger = ContributionLedger(engagement_id="starve")
    ledger.record(name="ffuf", kind=ComponentKind.TOOL, items=0, ok=True)
    ledger.record(name="exploit.plan_llm", kind=ComponentKind.LLM, items=0, ok=True)
    ledger.record_fallback(
        component="exploit.plan_llm",
        covered_by="exploit.class_floor",
        reason="LLM plan was empty",
    )

    report = _report(component_ledger=ledger.to_dict())
    lines: list[str] = []
    from clinkz.agents.report import ReportAgent

    ReportAgent._render_component_ledger(lines, report)
    rendered = "\n".join(lines)

    assert "## Component contribution" in rendered
    assert "ffuf" in rendered
    assert "exploit.plan_llm" in rendered
    assert "exploit.class_floor" in rendered, "the reader must see WHO covered"
    assert "silent" in rendered


def test_the_report_is_silent_when_no_ledger_was_installed() -> None:
    """A direct ReportAgent invocation renders exactly as it did before."""
    lines: list[str] = []
    from clinkz.agents.report import ReportAgent

    ReportAgent._render_component_ledger(lines, _report())
    assert lines == []


def test_the_report_says_so_plainly_when_everything_contributed() -> None:
    ledger = ContributionLedger(engagement_id="ok")
    ledger.record(name="katana", kind=ComponentKind.TOOL, items=40, ok=True)

    lines: list[str] = []
    from clinkz.agents.report import ReportAgent

    ReportAgent._render_component_ledger(lines, _report(component_ledger=ledger.to_dict()))
    rendered = "\n".join(lines)
    assert "contributed at least one item" in rendered
    assert "| Component |" not in rendered, "no alarm table when there is no alarm"


def test_the_ledger_serialises_into_report_json() -> None:
    """report.json must carry it — the log scrolls away, the artifact does not."""
    ledger = ContributionLedger(engagement_id="x")
    ledger.record(name="ffuf", kind=ComponentKind.TOOL, items=0, ok=True)

    report = _report(component_ledger=ledger.to_dict())
    payload = json.loads(json.dumps(report.model_dump(mode="json")))

    assert payload["component_ledger"]["summary"]["silent_components"] == 1
    assert payload["component_ledger"]["alarms"][0]["component"] == "ffuf"


# ---------------------------------------------------------------------------
# The producer-side contract, asserted across every discovery wrapper
# ---------------------------------------------------------------------------


def test_a_discovery_wrapper_that_forgets_the_contract_is_detectable() -> None:
    """The invariant CONTRIBUTING.md now states, enforced.

    Not a list of which wrappers declare it — that would need updating with every
    new tool — but the property that lets the seam tell the two cases apart.
    """
    assert FfufOutput.declares_discovery()
    assert not ToolOutput.declares_discovery()
    assert ToolOutput(tool_name="t", success=True).discovered_urls() == []
