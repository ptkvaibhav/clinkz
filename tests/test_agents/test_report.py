"""Tests for ReportAgent — simple zero-LLM report generation.

Coverage:
- No LLM calls (generate_text, reason, research never called)
- PentestReport assembled with correct fields (engagement_name, findings, hosts)
- ExecutiveSummary populated with correct severity counts
- JSON and Markdown files written to disk
- Empty findings handled gracefully (report still generated)
- Lifecycle manager sends RESULT to Orchestrator bus
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage
from clinkz.models.finding import CrossServiceResearchLead, Finding, FindingStatus, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="report-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mock LLM — verifies no LLM calls are made
# ---------------------------------------------------------------------------


class MockReportLLM(LLMClient):
    """Mock LLM that tracks calls — ReportAgent should make zero calls."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.generate_text_calls: list[str] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise AssertionError("ReportAgent must not call reason()")

    async def research(self, query: str) -> str:
        raise AssertionError("ReportAgent must not call research()")

    async def generate_text(self, prompt: str) -> str:
        self.generate_text_calls.append(prompt)
        return "Should not be called."


# ---------------------------------------------------------------------------
# Helper — seed state store with findings + targets
# ---------------------------------------------------------------------------


async def _seed_state(
    state: StateStore, engagement_id: str, validate: bool = True
) -> tuple[Finding, Finding, Host]:
    """Insert two findings and one host into the state store."""
    sqli = Finding(
        title="SQL Injection in /api/users",
        description="Error-based SQL injection via id parameter.",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        target="http://example.com/api/users",
        evidence=["GET /api/users?id=1' Response: MySQL error 1064"],
        cvss_score=9.8,
        remediation="Use parameterized queries.",
    )
    xss = Finding(
        title="Reflected XSS in /search",
        description="Reflected XSS via search parameter.",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        target="http://example.com/search",
        evidence=["GET /search?q=<script>alert(1)</script> — script executes"],
        cvss_score=6.1,
        remediation="Encode output.",
    )
    host = Host(ip="93.184.216.34", hostnames=["example.com"])

    sqli_id = await state.add_finding(engagement_id, sqli.model_dump(mode="json"))
    xss_id = await state.add_finding(engagement_id, xss.model_dump(mode="json"))

    if validate:
        await state.mark_finding_validated(sqli_id)
        await state.mark_finding_validated(xss_id)

    await state.upsert_target(engagement_id, host.model_dump(mode="json"))

    aid = await state.log_action(engagement_id, "recon", "ReconAgent", "subfinder", {})
    await state.complete_action(aid)
    aid2 = await state.log_action(engagement_id, "exploit", "ExploitAgent", "sqlmap", {})
    await state.complete_action(aid2)

    return sqli, xss, host


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zero_llm_calls(tmp_path: Path) -> None:
    """ReportAgent makes zero LLM calls in simple mode."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test Engagement", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"engagement_name": "Test Engagement"})

    assert len(llm.generate_text_calls) == 0
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_report_assembled_with_correct_fields(tmp_path: Path) -> None:
    """PentestReport has correct engagement_name, finding count, and scope."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("ACME Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run(
            {
                "engagement_name": "ACME Test",
                "test_start": "2025-01-01T00:00:00+00:00",
                "test_end": "2025-01-05T00:00:00+00:00",
            }
        )

    report = result["report"]
    assert report["engagement_name"] == "ACME Test"
    assert len(report["findings"]) == 2
    assert len(report["hosts"]) == 1
    assert "example.com" in report["target_scope"]
    assert report["test_start"] == "2025-01-01T00:00:00Z"
    assert report["test_end"] == "2025-01-05T00:00:00Z"


@pytest.mark.asyncio
async def test_executive_summary_severity_counts(tmp_path: Path) -> None:
    """ExecutiveSummary has correct severity counts (no LLM)."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    summary = result["report"]["executive_summary"]
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 0
    assert summary["risk_rating"] == "Critical"
    assert "example.com" in summary["overview"]


@pytest.mark.asyncio
async def test_finding_descriptions_preserved(tmp_path: Path) -> None:
    """Findings in the report keep their original descriptions (no LLM enhancement)."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    descriptions = {f["description"] for f in result["report"]["findings"]}
    assert "Error-based SQL injection via id parameter." in descriptions
    assert "Reflected XSS via search parameter." in descriptions


@pytest.mark.asyncio
async def test_unvalidated_findings_still_included(tmp_path: Path) -> None:
    """Report includes all findings regardless of validation status (no Critic in v2)."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid, validate=False)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    assert len(result["report"]["findings"]) == 2
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_empty_findings_no_crash(tmp_path: Path) -> None:
    """ReportAgent handles engagements with no findings gracefully."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Empty Engagement", SCOPE.model_dump())

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"engagement_name": "Empty Engagement"})

    assert result["status"] == "complete"
    assert result["report"]["findings"] == []
    assert result["report"]["executive_summary"]["risk_rating"] == "Informational"


@pytest.mark.asyncio
async def test_cross_service_research_leads_render_separately_never_counted(
    tmp_path: Path,
) -> None:
    """A research-lead (design §5) renders in its OWN section, never among findings.

    Structural separation, end-to-end through the state store: a lead is written to
    the ``research_leads`` table, read into ``report.research_leads`` (a different
    field than ``findings``), rendered under the dedicated UNCONFIRMED heading, and
    NOT counted in the finding totals / severity counts.
    """
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)  # 2 real findings (1 critical, 1 high)
        lead = CrossServiceResearchLead(
            candidate_chain="url@A(http://a/fetch) → egress(A) → A→B[recon] → SSRF at http://b/admin",
            why_unconfirmed="egress_confirmed_but_B_reach_not_observed",
            a_endpoint="http://a/fetch",
            a_channel="url",
            b_target="http://b/admin",
            topology_source="recon",
            raw_probe="GET http://a/fetch — url=http://collab/NONCE",
            raw_null_observation="callback at generic collaborator, not co-located with B",
        )
        await state.add_research_lead(eid, lead.model_dump(mode="json"))

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    report = result["report"]
    # Findings totals are UNCHANGED by the lead (never counted in coverage).
    assert len(report["findings"]) == 2
    assert report["executive_summary"]["critical_count"] == 1
    assert report["executive_summary"]["high_count"] == 1
    # The lead lives in its own field, structurally separate from findings.
    assert len(report["research_leads"]) == 1
    assert report["research_leads"][0]["why_unconfirmed"] == (
        "egress_confirmed_but_B_reach_not_observed"
    )
    # The markdown carries the dedicated UNCONFIRMED section, and the lead's chain is
    # under it — NOT in any confirmed-finding heading.
    md_path = Path(result["markdown_path"])
    md = md_path.read_text(encoding="utf-8")
    assert "Cross-service research leads (candidate chains — UNCONFIRMED)" in md
    assert "**NOT findings**" in md
    lead_heading_idx = md.index("Cross-service research leads")
    # Every confirmed-finding heading precedes the research-leads section.
    assert md.index("SQL Injection") < lead_heading_idx
    assert md.index("Reflected XSS") < lead_heading_idx


@pytest.mark.asyncio
async def test_research_leads_render_even_with_no_findings(tmp_path: Path) -> None:
    """A research-lead surfaces even when there are zero confirmed findings."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        lead = CrossServiceResearchLead(
            candidate_chain="chain-x", why_unconfirmed="blind_unconfirmed_within_window"
        )
        await state.add_research_lead(eid, lead.model_dump(mode="json"))

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    assert result["report"]["findings"] == []
    md = Path(result["markdown_path"]).read_text(encoding="utf-8")
    assert "No validated findings." in md
    assert "Cross-service research leads (candidate chains — UNCONFIRMED)" in md
    assert "chain-x" in md


@pytest.mark.asyncio
async def test_json_and_markdown_files_written(tmp_path: Path) -> None:
    """Report writes JSON and Markdown files to disk."""
    import os

    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)

        # Run from tmp_path so output files land there
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = await agent.run({})
        finally:
            os.chdir(old_cwd)

    # Reports are written under outputs/<engagement_id>/ relative to the cwd
    # at run time (tmp_path here), not the repo root.
    json_path = Path(result["json_path"])
    md_path = Path(result["markdown_path"])
    assert json_path.parent == Path("outputs") / eid
    assert (tmp_path / json_path).exists()
    assert (tmp_path / md_path).exists()

    # JSON is valid and contains findings
    data = json.loads((tmp_path / json_path).read_text())
    assert len(data["findings"]) == 2

    # Markdown contains finding titles
    md_content = (tmp_path / md_path).read_text()
    assert "SQL Injection" in md_content
    assert "Reflected XSS" in md_content


@pytest.mark.asyncio
async def test_no_methodology_narrative(tmp_path: Path) -> None:
    """Report has no LLM-generated methodology/narrative."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    # methodology should be empty (no LLM narrative)
    assert result["report"]["methodology"] == ""


@pytest.mark.asyncio
async def test_lifecycle_manager_sends_result_to_bus(tmp_path: Path) -> None:
    """AgentLifecycleManager routes the RESULT from ReportAgent to the Orchestrator bus."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        bus = MessageBus(state=state)
        llm = MockReportLLM()

        mgr = AgentLifecycleManager(bus=bus, llm=llm, scope=SCOPE, state=state, engagement_id=eid)
        task_msg = AgentMessage.task(
            from_agent=ORCHESTRATOR,
            to_agent="report",
            engagement_id=eid,
            content={"engagement_name": "Lifecycle Test"},
        )
        await mgr.spin_up("report", task_msg)

        # Wait for the agent to finish and post its RESULT
        import asyncio

        deadline = asyncio.get_event_loop().time() + 10.0
        result_msg: AgentMessage | None = None
        while asyncio.get_event_loop().time() < deadline:
            msgs = await bus.get_pending(ORCHESTRATOR)
            for m in msgs:
                if m.message_type == MessageType.RESULT and m.from_agent == "report":
                    result_msg = m
                    break
            if result_msg is not None:
                break
            await asyncio.sleep(0.05)

    assert result_msg is not None, "ReportAgent should post a RESULT to the Orchestrator"
    assert "report" in result_msg.content
    assert result_msg.content["status"] == "complete"
