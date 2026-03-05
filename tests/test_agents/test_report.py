"""Tests for ReportAgent — multi-pass LLM report generation.

Coverage:
- generate_text() called once for Pass 1 (executive summary)
- generate_text() called twice per finding in Pass 2 (description + remediation)
- generate_text() called once for Pass 3 (attack narrative)
- PentestReport assembled with correct fields (engagement_name, findings, hosts)
- ExecutiveSummary populated with correct severity counts
- Inbox mid-run QUERY messages are processed between passes
- _query_orchestrator() enqueues to outbox and waits for inbox RESPONSE
- Empty findings handled gracefully (report still generated)
- reason() and research() are never called
- Lifecycle manager sends RESULT to Orchestrator bus
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage
from clinkz.models.finding import Finding, FindingStatus, Severity
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

# Canned responses the mock LLM returns in order of generate_text() calls.
_EXEC_SUMMARY = (
    "The engagement against example.com revealed two critical vulnerabilities. "
    "SQL injection in the /api/users endpoint could allow full database compromise. "
    "Overall risk rating is Critical."
)
_DESC_SQLI = (
    "The /api/users endpoint is vulnerable to error-based SQL injection via the "
    "'id' parameter. Discovered through automated testing with sqlmap."
)
_REM_SQLI = "Replace string concatenation with parameterized queries (OWASP A03:2021)."
_DESC_XSS = (
    "A reflected XSS vulnerability exists in the search parameter of /search. "
    "Payload <script>alert(1)</script> executes in the browser without sanitization."
)
_REM_XSS = "Apply output encoding using OWASP's encoder library (OWASP A03:2021)."
_NARRATIVE = (
    "Testing began with passive reconnaissance against example.com. "
    "Port scanning revealed two web services on ports 80 and 443. "
    "Automated vulnerability scanning identified SQL injection and XSS vulnerabilities, "
    "both subsequently confirmed through manual exploitation."
)


# ---------------------------------------------------------------------------
# Mock LLM — controls generate_text() call sequence
# ---------------------------------------------------------------------------


class MockReportLLM(LLMClient):
    """Deterministic mock LLM for ReportAgent tests.

    Returns canned responses from a queue; raises AssertionError if
    reason() or research() are unexpectedly called.

    Call sequence (for 2 findings):
      generate_text #1  → _EXEC_SUMMARY          (Pass 1: executive summary)
      generate_text #2  → _DESC_SQLI             (Pass 2: SQLi description)
      generate_text #3  → _REM_SQLI              (Pass 2: SQLi remediation)
      generate_text #4  → _DESC_XSS              (Pass 2: XSS description)
      generate_text #5  → _REM_XSS               (Pass 2: XSS remediation)
      generate_text #6  → _NARRATIVE             (Pass 3: attack narrative)
    """

    def __init__(self, responses: list[str] | None = None) -> None:
        default_responses = [
            _EXEC_SUMMARY,
            _DESC_SQLI,
            _REM_SQLI,
            _DESC_XSS,
            _REM_XSS,
            _NARRATIVE,
        ]
        self._responses = iter(responses if responses is not None else default_responses)
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
        return next(self._responses, "Default LLM response.")


# ---------------------------------------------------------------------------
# Helper — seed state store with findings + targets
# ---------------------------------------------------------------------------


async def _seed_state(
    state: StateStore, engagement_id: str, validate: bool = True
) -> tuple[Finding, Finding, Host]:
    """Insert two findings and one host into the state store.

    Args:
        state: Connected state store.
        engagement_id: Engagement UUID.
        validate: If True, mark both findings as validated so
                  get_findings(validated_only=True) returns them.

    Returns:
        Tuple of (sqli_finding, xss_finding, host).
    """
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

    # Log a couple of actions for the narrative pass
    aid = await state.log_action(engagement_id, "recon", "ReconAgent", "subfinder", {})
    await state.complete_action(aid)
    aid2 = await state.log_action(engagement_id, "exploit", "ExploitAgent", "sqlmap", {})
    await state.complete_action(aid2)

    return sqli, xss, host


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_text_call_count(tmp_path: Path) -> None:
    """generate_text() is called the expected number of times across 3 passes."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test Engagement", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"engagement_name": "Test Engagement"})

    # Pass 1: 1 call (exec summary)
    # Pass 2: 2 calls per finding × 2 findings = 4 calls
    # Pass 3: 1 call (narrative)
    # Total: 6 calls
    assert len(llm.generate_text_calls) == 6
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_exec_summary_prompt_contains_findings(tmp_path: Path) -> None:
    """Pass 1 prompt includes the engagement name, scope, and finding titles."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("ACME Corp Q1", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        await agent.run({"engagement_name": "ACME Corp Q1"})

    exec_summary_prompt = llm.generate_text_calls[0]
    assert "ACME Corp Q1" in exec_summary_prompt
    assert "SQL Injection" in exec_summary_prompt


@pytest.mark.asyncio
async def test_finding_enhancement_prompts(tmp_path: Path) -> None:
    """Pass 2 prompts include finding title and evidence."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        await agent.run({})

    # Calls 1 and 2 are description+remediation for the first finding
    assert "SQL Injection" in llm.generate_text_calls[1]
    assert "SQL Injection" in llm.generate_text_calls[2]


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
    """ExecutiveSummary.from_findings() computes correct severity counts."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    summary = result["report"]["executive_summary"]
    # 1 critical (SQLi), 1 high (XSS)
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 0
    assert summary["risk_rating"] == "Critical"
    assert summary["overview"] == _EXEC_SUMMARY


@pytest.mark.asyncio
async def test_narrative_is_llm_generated(tmp_path: Path) -> None:
    """Pass 3 produces the narrative from generate_text() output."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    assert result["report"]["methodology"] == _NARRATIVE


@pytest.mark.asyncio
async def test_finding_descriptions_enhanced(tmp_path: Path) -> None:
    """Findings in the report carry the LLM-enhanced descriptions."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    descriptions = {f["description"] for f in result["report"]["findings"]}
    assert _DESC_SQLI in descriptions
    assert _DESC_XSS in descriptions


@pytest.mark.asyncio
async def test_only_validated_findings_included(tmp_path: Path) -> None:
    """Report only includes findings that were marked validated in state store."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        # Seed WITHOUT validating
        await _seed_state(state, eid, validate=False)

        llm = MockReportLLM(responses=["Summary.", "Narrative."])
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({})

    # No validated findings → report has 0 findings
    assert len(result["report"]["findings"]) == 0
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_empty_findings_no_crash(tmp_path: Path) -> None:
    """ReportAgent handles engagements with no findings gracefully."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Empty Engagement", SCOPE.model_dump())

        # Single generate_text call: exec summary; Pass 2 = 0 calls; Pass 3 = 1 call
        llm = MockReportLLM(responses=["No issues found.", "No attack narrative."])
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"engagement_name": "Empty Engagement"})

    assert result["status"] == "complete"
    assert result["report"]["findings"] == []
    assert result["report"]["executive_summary"]["risk_rating"] == "Informational"


@pytest.mark.asyncio
async def test_mid_run_query_injected_into_inbox(tmp_path: Path) -> None:
    """QUERY message injected via receive_message() is processed between passes."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        llm = MockReportLLM()
        agent = ReportAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)

        # Inject a QUERY message before run() starts
        query_msg = AgentMessage.query(
            from_agent="orchestrator",
            to_agent="report",
            engagement_id=eid,
            content={"query": "Is finding X a false positive?"},
        )
        agent.receive_message(query_msg)

        result = await agent.run({})

    # Report generation still completes despite the mid-run message
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_query_orchestrator_sends_to_outbox(tmp_path: Path) -> None:
    """_query_orchestrator() enqueues a QUERY message in the outbox."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())

        outbox: asyncio.Queue[AgentMessage] = asyncio.Queue()
        llm = MockReportLLM(responses=["Summary.", "Narrative."])
        agent = ReportAgent(
            llm=llm,
            tools=[],
            scope=SCOPE,
            state=state,
            engagement_id=eid,
            outbox=outbox,
        )

        # Inject the RESPONSE into the inbox before calling _query_orchestrator
        response_msg = AgentMessage.response(
            from_agent="orchestrator",
            to_agent="report",
            engagement_id=eid,
            content={"answer": "The finding is confirmed, not a false positive."},
        )
        agent.receive_message(response_msg)

        answer = await agent._query_orchestrator(
            "Is the SQLi finding confirmed?", finding_id="finding-123"
        )

    # Outbox received the QUERY message
    assert not outbox.empty()
    queued: AgentMessage = outbox.get_nowait()
    assert queued.message_type == MessageType.QUERY
    assert queued.from_agent == "report"
    assert queued.to_agent == "orchestrator"
    assert queued.content["query"] == "Is the SQLi finding confirmed?"
    assert queued.content["finding_id"] == "finding-123"

    # The answer is the response content
    assert "confirmed" in answer


@pytest.mark.asyncio
async def test_query_orchestrator_timeout(tmp_path: Path) -> None:
    """_query_orchestrator() returns a timeout notice when no response arrives."""
    import clinkz.agents.report as report_module

    original_timeout = report_module._QUERY_TIMEOUT_SECONDS
    report_module._QUERY_TIMEOUT_SECONDS = 0.05  # Speed up test

    try:
        async with StateStore(tmp_path / "test.db") as state:
            eid = await state.create_engagement("Test", SCOPE.model_dump())

            llm = MockReportLLM(responses=["Summary.", "Narrative."])
            agent = ReportAgent(
                llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid
            )
            answer = await agent._query_orchestrator("Any clarification needed?")
    finally:
        report_module._QUERY_TIMEOUT_SECONDS = original_timeout

    assert "[No response received" in answer


@pytest.mark.asyncio
async def test_lifecycle_manager_sends_result_to_bus(tmp_path: Path) -> None:
    """AgentLifecycleManager routes the RESULT from ReportAgent to the Orchestrator bus."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        await _seed_state(state, eid)

        bus = MessageBus(state=state)
        llm = MockReportLLM()

        mgr = AgentLifecycleManager(
            bus=bus, llm=llm, scope=SCOPE, state=state, engagement_id=eid
        )
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
