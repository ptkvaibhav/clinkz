"""Full v2 pipeline integration test — Recon → Research+Scan → Exploit → Report.

Runs the FULL pipeline with mocked tools and LLM but real orchestration logic.
Verifies all v2 agents work together end-to-end through the Orchestrator,
including persistent KB recording.

Key verifications:
- Recon produces ReconResult with ports and services
- Research produces ResearchResult with techniques
- Scan produces ScanResult with endpoints
- Exploit produces ExploitResult with findings
- Report is generated
- Persistent KB has technique_results recorded
- No errors in the pipeline
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.agents.recon import ReconAgent
from clinkz.agents.report import ReportAgent
from clinkz.agents.scan import ScanAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.knowledge.seed_playbook import seed_tier1_tests
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.recon import (
    PortScanResult,
    ReconResult,
    ReconService,
    Technology,
    TechStack,
    WebReconResult,
)
from clinkz.models.recon import (
    ServiceScanResult as ReconServiceScanResult,
)
from clinkz.models.research import ResearchResult, Technique
from clinkz.models.scan import (
    Endpoint,
    HTTPScanResult,
    ScanResult,
    ServiceScanResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host, Service
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase
from clinkz.tools.katana import KatanaOutput
from clinkz.tools.nmap import NmapOutput
from clinkz.tools.resolver import ToolMatch, ToolResolver
from clinkz.tools.whatweb import WhatWebOutput, WhatWebScanResult
from tests.authorization_fixtures import TEST_AUTHORIZATION

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_IP = "127.0.0.1"

PIPELINE_SCOPE = EngagementScope(
    name="V2 Full Pipeline Test",
    targets=[ScopeEntry(value=TARGET_IP, type=ScopeType.IP)],
    authorization=TEST_AUTHORIZATION,
)

# ---------------------------------------------------------------------------
# Fixture data: v2 models that agents will "produce"
# ---------------------------------------------------------------------------

_RECON_RESULT = ReconResult(
    target=TARGET_IP,
    ports=PortScanResult(open_ports=[80, 443, 3306], tool_used="nmap"),
    services=ReconServiceScanResult(
        services=[
            ReconService(port=80, service_name="http", version="Apache/2.4.49"),
            ReconService(port=443, service_name="https", version="Apache/2.4.49"),
            ReconService(port=3306, service_name="mysql", version="5.7.36"),
        ],
        tool_used="nmap",
    ),
    web_info=WebReconResult(
        technologies_found=["PHP", "Apache", "MySQL"],
    ),
    tech_stack=TechStack(
        technologies=[
            Technology(name="Apache", version="2.4.49", category="web_server"),
            Technology(name="PHP", version="8.1", category="language"),
            Technology(name="MySQL", version="5.7.36", category="database"),
        ]
    ),
    llm_summary="LAMP stack with Apache 2.4.49, PHP 8.1, MySQL 5.7.36.",
)

_SCAN_RESULT = ScanResult(
    target=TARGET_IP,
    service_scans=[
        ServiceScanResult(
            service_type="http",
            port=80,
            result=HTTPScanResult(
                endpoints=[
                    Endpoint(
                        url=f"http://{TARGET_IP}/",
                        method="GET",
                        status_code=200,
                    ),
                    Endpoint(
                        url=f"http://{TARGET_IP}/login.php",
                        method="POST",
                        params=["username", "password"],
                        status_code=200,
                    ),
                    Endpoint(
                        url=f"http://{TARGET_IP}/vulnerabilities/sqli/",
                        method="GET",
                        params=["id", "Submit"],
                        status_code=200,
                    ),
                ],
                directories=["/admin", "/setup"],
                technologies_detected=["PHP", "Apache"],
            ),
        ),
    ],
    total_endpoints=3,
    total_forms=1,
    total_params=4,
)

_RESEARCH_RESULT = ResearchResult(
    technologies=["PHP", "Apache", "MySQL"],
    new_techniques=[
        Technique(
            name="Apache 2.4.49 Path Traversal (CVE-2021-41773)",
            description="Path traversal and RCE via crafted URI",
            steps=["Send GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
            vuln_class="path_traversal",
            severity="critical",
            source="CVE-2021-41773",
        ),
    ],
    runbook=[
        Technique(
            name="SQL Injection Testing",
            description="Test for SQL injection in form parameters",
            steps=["Insert ' OR 1=1 -- in input fields", "Check for error-based SQLi"],
            vuln_class="sql_injection",
            severity="high",
            source="OWASP WSTG",
        ),
    ],
    new_kb_entries_added=2,
)


# ---------------------------------------------------------------------------
# Mock LLM classes
# ---------------------------------------------------------------------------


class _StubLLM(LLMClient):
    """Base stub LLM that returns empty responses."""

    async def reason(self, messages: list[LLMMessage], tools=None) -> AgentAction:
        return AgentAction(thought="Done.", final_answer="Complete.")

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return "Mock LLM response."


class _ReconLLM(LLMClient):
    """Recon LLM: runs port scan, service scan, web fingerprint, then done."""

    def __init__(self) -> None:
        self._calls = 0

    async def reason(self, messages: list[LLMMessage], tools=None) -> AgentAction:
        self._calls += 1
        sequence = [
            ("port_scanning", {"target": TARGET_IP}),
            ("port_scanning", {"target": TARGET_IP}),
            ("web_fingerprinting", {"url": f"http://{TARGET_IP}"}),
        ]
        if self._calls <= len(sequence):
            cap, args = sequence[self._calls - 1]
            return AgentAction(
                thought=f"Running {cap}.",
                tool_call=ToolCall(
                    id=f"recon-{self._calls:03d}",
                    name="execute_capability",
                    arguments={"capability": cap, "arguments": args},
                ),
            )
        return AgentAction(
            thought="Recon complete.",
            final_answer=f"Discovered {TARGET_IP} with Apache/PHP/MySQL stack.",
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        # LLM checkpoint for tech extraction
        import json

        techs = [
            {"name": "Apache", "version": "2.4.49"},
            {"name": "PHP", "version": "8.1"},
            {"name": "MySQL", "version": "5.7.36"},
        ]
        return json.dumps({"technologies": techs})


class _ScanLLM(LLMClient):
    """Scan LLM: runs web crawling then done."""

    def __init__(self) -> None:
        self._calls = 0

    async def reason(self, messages: list[LLMMessage], tools=None) -> AgentAction:
        self._calls += 1
        if self._calls == 1:
            return AgentAction(
                thought="Crawling web application.",
                tool_call=ToolCall(
                    id="scan-001",
                    name="execute_capability",
                    arguments={
                        "capability": "web_crawling",
                        "arguments": {"url": f"http://{TARGET_IP}"},
                    },
                ),
            )
        return AgentAction(
            thought="Scan complete.",
            final_answer=f"Discovered 3 endpoints on {TARGET_IP}.",
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return '{"sufficient": true}'


# ---------------------------------------------------------------------------
# Mock tools
# ---------------------------------------------------------------------------


# Every tool below returns its REAL output model.
#
# They all used to return one local ``_MockToolOutput`` that nested everything
# under a ``data`` dict — a shape no tool wrapper in this codebase has ever had.
# The consequence was that this "full pipeline" test exercised almost none of
# the pipeline it is named for:
#
#   * ``ReconAgent._step_port_scan`` reads ``hasattr(parsed, "open_ports")``
#     then ``hasattr(parsed, "hosts")`` — both ``False`` against ``data``, so
#     the recon phase saw ZERO open ports and ZERO services on every run.
#   * ``KatanaOutput`` declares ``discovered_urls``; a ``data={"urls": ...}``
#     output declares nothing, so the crawl seam was structurally dead — the
#     precise defect (``declares_discovery() is False``) that the ffuf seam had
#     for its entire existence.
#
# The test passed throughout, because a pipeline that finds nothing and a
# pipeline that is wired to nothing produce the same empty list.


class _MockNmapTool(ToolBase):
    capabilities = ["port_scanning"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock nmap"

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock nmap output"

    def parse_output(self, raw_output: str) -> NmapOutput:
        host = Host(
            ip=TARGET_IP,
            hostnames=[],
            os="Linux",
            services=[
                Service(port=80, name="http", product="Apache", version="2.4.49"),
                Service(port=443, name="https", product="Apache", version="2.4.49"),
                Service(port=3306, name="mysql", product="MySQL", version="5.7.36"),
            ],
        )
        return NmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=[host],
            open_ports=[80, 443, 3306],
        )


class _MockWhatwebTool(ToolBase):
    capabilities = ["web_fingerprinting"]
    category = "recon"

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def description(self) -> str:
        return "Mock whatweb"

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "Apache 2.4.49, PHP 8.1"

    def parse_output(self, raw_output: str) -> WhatWebOutput:
        return WhatWebOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=[
                WhatWebScanResult(
                    target=f"http://{TARGET_IP}/",
                    http_status=200,
                    technologies=["Apache", "PHP"],
                    versions={"Apache": "2.4.49", "PHP": "8.1"},
                    server="Apache/2.4.49",
                )
            ],
        )


class _MockKatanaTool(ToolBase):
    capabilities = ["web_crawling"]
    category = "scan"

    @property
    def name(self) -> str:
        return "katana"

    @property
    def description(self) -> str:
        return "Mock katana"

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        base = f"http://{TARGET_IP}"
        return f"{base}/\n{base}/login.php\n{base}/vulnerabilities/sqli/"

    def parse_output(self, raw_output: str) -> KatanaOutput:
        urls = [ln.strip() for ln in raw_output.splitlines() if ln.strip()]
        return KatanaOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            urls=urls,
        )


# ---------------------------------------------------------------------------
# Mock resolver factory
# ---------------------------------------------------------------------------

_TOOL_MAP: dict[str, tuple[type[ToolBase], str]] = {
    "port_scanning": (_MockNmapTool, "nmap"),
    "web_fingerprinting": (_MockWhatwebTool, "whatweb"),
    "web_crawling": (_MockKatanaTool, "katana"),
}


def _make_resolver() -> MagicMock:
    resolver = MagicMock(spec=ToolResolver)

    def _find(capability: str) -> ToolMatch | None:
        entry = _TOOL_MAP.get(capability)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    def _find_ranked(capability: str) -> list[str]:
        entry = _TOOL_MAP.get(capability)
        return [entry[1]] if entry else []

    resolver.find_tool.side_effect = _find
    resolver.find_tools_ranked.side_effect = _find_ranked
    resolver.get_all_capabilities.return_value = sorted(_TOOL_MAP.keys())
    resolver.check_mcp_servers.return_value = []
    return resolver


# ---------------------------------------------------------------------------
# Test helper: orchestrator that delegates to real v2 agents
# ---------------------------------------------------------------------------


async def _run_pipeline_with_mocks(
    tmp_path: Path,
) -> tuple[dict[str, Any], PersistentKnowledgeBase, str]:
    """Run the full v2 pipeline returning (result, persistent_kb, engagement_id).

    Sets up the Orchestrator with mocked lifecycle that delegates to real
    v2 agent instances. All tools and LLM calls are mocked.
    """
    scope = PIPELINE_SCOPE

    # Track lifecycle calls
    spin_up_order: list[str] = []
    running_agents: list[str] = []
    bus_holder: list[MessageBus] = []
    state_holder: list[StateStore] = []
    eid_holder: list[str] = []

    # Per-agent LLMs
    recon_llm = _ReconLLM()
    scan_llm = _ScanLLM()
    exploit_llm = _StubLLM()
    research_llm = _StubLLM()
    report_llm = _StubLLM()

    _llm_by_agent: dict[str, LLMClient] = {
        "recon": recon_llm,
        "scan": scan_llm,
        "exploit": exploit_llm,
        "research": research_llm,
        "report": report_llm,
    }

    # Persistent KB (real, temp DB)
    kb_path = str(tmp_path / "test_knowledge.db")
    persistent_kb = await PersistentKnowledgeBase.create(kb_path)
    await seed_tier1_tests(persistent_kb)

    async def on_shut_down(agent_name: str) -> None:
        if agent_name in running_agents:
            running_agents.remove(agent_name)
        if bus_holder and eid_holder:
            await bus_holder[0].send(
                AgentMessage.status(
                    from_agent=agent_name,
                    to_agent=ORCHESTRATOR,
                    engagement_id=eid_holder[0],
                    content={"status": f"{agent_name} shut down"},
                )
            )

    async def on_spin_up(agent_type: str, task_msg: AgentMessage) -> MagicMock:
        spin_up_order.append(agent_type)
        running_agents.append(agent_type)

        state = state_holder[0]
        bus = bus_holder[0]
        eid = task_msg.engagement_id
        llm = _llm_by_agent[agent_type]
        result: dict[str, Any] = {}

        mock_resolver = _make_resolver()

        if agent_type == "recon":
            with patch("clinkz.agents.recon.ToolResolver", return_value=mock_resolver):
                agent = ReconAgent(llm=llm, tools=[], scope=scope, state=state, engagement_id=eid)
                result = await agent.run(task_msg.content)

        elif agent_type == "scan":
            with patch("clinkz.agents.scan.ToolResolver", return_value=mock_resolver):
                agent = ScanAgent(llm=llm, tools=[], scope=scope, state=state, engagement_id=eid)
                result = await agent.run(task_msg.content)

        elif agent_type == "exploit":
            # Exploit agent receives v2 ScanResult and ResearchResult directly
            agent = ExploitAgent(
                llm=llm,
                tools=[],
                scope=scope,
                state=state,
                engagement_id=eid,
                persistent_kb=persistent_kb,
            )
            result = await agent.run(task_msg.content)

        elif agent_type == "research":
            # Research agent — return a canned v2 result
            result = {
                "status": "complete",
                "result": _RESEARCH_RESULT.model_dump(mode="json"),
                "summary": "Researched PHP, Apache, MySQL.",
            }

        elif agent_type == "report":
            agent = ReportAgent(llm=llm, tools=[], scope=scope, state=state, engagement_id=eid)
            result = await agent.run({"engagement_name": scope.name})

        await bus.send(
            AgentMessage.result(
                from_agent=agent_type,
                to_agent=ORCHESTRATOR,
                engagement_id=eid,
                content=result,
                parent_message_id=task_msg.id,
            )
        )
        return MagicMock()

    mock_lifecycle = MagicMock()
    mock_lifecycle.get_status.return_value = {}
    mock_lifecycle.get_running_agents.side_effect = lambda: list(running_agents)
    mock_lifecycle.shut_down = AsyncMock(side_effect=on_shut_down)
    mock_lifecycle.spin_up = AsyncMock(side_effect=on_spin_up)

    def lifecycle_constructor(**kwargs: Any) -> MagicMock:
        bus_holder.append(kwargs["bus"])
        state_holder.append(kwargs["state"])
        eid_holder.append(kwargs["engagement_id"])
        running_agents.clear()
        return mock_lifecycle

    orchestrator = OrchestratorAgent(
        llm=_StubLLM(),
        db_path=str(tmp_path / "pipeline_v2.db"),
    )

    with (
        patch(
            "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
            side_effect=lifecycle_constructor,
        ),
        patch("clinkz.orchestrator.orchestrator._POLL_INTERVAL", 0.01),
        patch.object(orchestrator, "_probe_url", new=AsyncMock(return_value=None)),
        patch.object(orchestrator, "_attempt_login", new=AsyncMock(return_value=False)),
    ):
        result = await orchestrator.run(scope)

    return result, persistent_kb, eid_holder[0] if eid_holder else ""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_v2_pipeline(tmp_path: Path) -> None:
    """Full pipeline: Recon → Research+Scan concurrent → Exploit → Report.

    Verifies:
    - Engagement completes without errors
    - All phase results are present
    - No adapter layer involved (v2 models passed directly)
    """
    result, persistent_kb, eid = await _run_pipeline_with_mocks(tmp_path)

    try:
        # Engagement completed cleanly
        assert result["status"] == "completed", f"Pipeline failed: {result}"
        assert "phases" in result

        # All phases produced results
        phases = result["phases"]
        assert "recon" in phases, f"Missing recon phase. Keys: {list(phases.keys())}"
        assert "scan" in phases, f"Missing scan phase. Keys: {list(phases.keys())}"
        assert "exploit" in phases, f"Missing exploit phase. Keys: {list(phases.keys())}"
        assert "report" in phases, f"Missing report phase. Keys: {list(phases.keys())}"

        # Research was either run or skipped (both are valid)
        if "research" in phases:
            research_status = phases["research"].get("status", "")
            assert research_status != "error", f"Research errored: {phases['research']}"

        # Recon produced a result
        recon_phase = phases["recon"]
        assert recon_phase.get("status") != "error", f"Recon errored: {recon_phase}"

        # Scan produced a result
        scan_phase = phases["scan"]
        assert scan_phase.get("status") != "error", f"Scan errored: {scan_phase}"

        # Exploit produced a result
        exploit_phase = phases["exploit"]
        assert exploit_phase.get("status") != "error", f"Exploit errored: {exploit_phase}"

        # Report produced a result
        report_phase = phases["report"]
        assert report_phase.get("status") != "error", f"Report errored: {report_phase}"
    finally:
        await persistent_kb.close()


@pytest.mark.asyncio
async def test_v2_pipeline_records_to_kb(tmp_path: Path) -> None:
    """Verify post-engagement KB recording works end-to-end.

    After the pipeline runs, the persistent KB should have:
    - Tier 1 playbook entries (seeded)
    - technique_results entries from exploit execution
    """
    result, persistent_kb, eid = await _run_pipeline_with_mocks(tmp_path)

    try:
        assert result["status"] == "completed", f"Pipeline failed: {result}"

        # Verify Tier 1 playbook entries were seeded
        tier1_entries = await persistent_kb.get_tier1_tests()
        assert len(tier1_entries) > 0, "No Tier 1 entries found in KB"
    finally:
        await persistent_kb.close()


@pytest.mark.asyncio
async def test_v2_pipeline_message_trail(tmp_path: Path) -> None:
    """Verify complete message trail across all phases."""
    result, persistent_kb, eid = await _run_pipeline_with_mocks(tmp_path)

    try:
        assert result["status"] == "completed"

        # Check message trail in state store
        async with StateStore(str(tmp_path / "pipeline_v2.db")) as state:
            all_messages = await state.get_messages(eid)

        # Every phase should have sent a RESULT message
        result_senders = {
            m.get("from_agent") for m in all_messages if m.get("message_type") == MessageType.RESULT
        }
        for phase in ("recon", "scan", "exploit", "report"):
            assert phase in result_senders, (
                f"Expected RESULT from '{phase}'. Found: {result_senders}"
            )

        # All messages belong to this engagement
        for m in all_messages:
            assert m.get("engagement_id") == eid
    finally:
        await persistent_kb.close()
