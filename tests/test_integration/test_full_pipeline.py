"""Integration test: complete pentest pipeline — recon through report.

Exercises the full 5-phase agent lifecycle mediated by the OrchestratorAgent:

    Recon → Scan → Exploit → Critic → Report

Orchestrator LLM sequence:
    1. spin_up recon  → receives RESULT → shut_down recon
    2. spin_up scan   → receives RESULT → shut_down scan
    3. spin_up exploit → receives RESULT → shut_down exploit
    4. spin_up critic (with exploit findings) → receives validated findings
    5. spin_up report → receives final report → complete_engagement

Each phase agent uses a mock LLM returning fixture-based tool results.
No real network calls, no external tools, no LLM API keys required.

Assertions
----------
- Hosts discovered in recon are available (in state store) before scan runs
- Findings from exploit are validated by critic (mark_finding_validated called)
- Final PentestReport contains executive_summary, methodology narrative,
  and findings list
- Complete message trail in state store across all phases
- Engagement completes cleanly (status='completed', not timeout or forced)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from clinkz.agents.critic import CriticAgent
from clinkz.agents.exploit import ExploitAgent
from clinkz.agents.recon import ReconAgent
from clinkz.agents.report import ReportAgent
from clinkz.agents.scan import ScanAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host, Service
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolMatch, ToolResolver

# ---------------------------------------------------------------------------
# Engagement scope
# ---------------------------------------------------------------------------

TARGET_IP = "192.168.1.100"

PIPELINE_SCOPE = EngagementScope(
    name="Full Pipeline Test",
    targets=[ScopeEntry(value=TARGET_IP, type=ScopeType.IP)],
)


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------


def _tc(name: str, **kwargs: Any) -> ToolCall:
    """Shorthand: create a ToolCall with the given name and kwargs as arguments."""
    return ToolCall(id=f"call-{name}-{id(kwargs)}", name=name, arguments=kwargs)


# ---------------------------------------------------------------------------
# Orchestrator LLM — deterministic action sequence
# ---------------------------------------------------------------------------


class _SequenceLLM(LLMClient):
    """Returns a predetermined sequence of AgentActions, then complete_engagement."""

    def __init__(self, actions: list[AgentAction]) -> None:
        self._actions = iter(actions)

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        try:
            return next(self._actions)
        except StopIteration:
            return AgentAction(
                thought="Sequence exhausted — forcing complete.",
                tool_call=_tc("complete_engagement", summary="Sequence exhausted."),
            )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Recon agent LLM — 3 capability calls then final_answer
# (identical to the one in test_orchestrator_recon.py)
# ---------------------------------------------------------------------------


class _ReconSequenceLLM(LLMClient):
    """Recon agent LLM: subdomain_enumeration → port_scanning → web_fingerprinting → done."""

    def __init__(self, host_arg: str = TARGET_IP) -> None:
        self._calls = 0
        self._host = host_arg

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._calls += 1
        sequence = [
            ("subdomain_enumeration", {"domain": self._host}),
            ("port_scanning", {"target": self._host}),
            ("web_fingerprinting", {"url": f"http://{self._host}"}),
        ]
        if self._calls <= len(sequence):
            cap, args = sequence[self._calls - 1]
            return AgentAction(
                thought=f"Executing capability: {cap}.",
                tool_call=ToolCall(
                    id=f"recon-{self._calls:03d}",
                    name="execute_capability",
                    arguments={"capability": cap, "arguments": args},
                ),
            )
        return AgentAction(
            thought="Recon complete.",
            final_answer=(
                f"Discovered host {self._host} with ports 22/80/443/8080. "
                "Subdomains enumerated. Web stack: nginx 1.24 + Apache Tomcat 9.0."
            ),
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Scan agent LLM — web_crawling capability then final_answer
# ---------------------------------------------------------------------------


class _ScanSequenceLLM(LLMClient):
    """Scan agent LLM: web_crawling → final_answer."""

    def __init__(self) -> None:
        self._calls = 0

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._calls += 1
        if self._calls == 1:
            return AgentAction(
                thought="Crawling target web application.",
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
            final_answer=(
                f"Discovered 3 endpoints on {TARGET_IP}: "
                "/login, /api/users, /admin."
            ),
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Exploit agent LLM — report_finding then final_answer
# ---------------------------------------------------------------------------


class _ExploitSequenceLLM(LLMClient):
    """Exploit agent LLM: report a confirmed HIGH SQL injection finding, then done."""

    def __init__(self) -> None:
        self._calls = 0

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._calls += 1
        if self._calls == 1:
            return AgentAction(
                thought="Reporting confirmed SQL injection.",
                tool_call=ToolCall(
                    id="exploit-001",
                    name="report_finding",
                    arguments={
                        "title": "SQL Injection in /api/users",
                        "description": (
                            "The /api/users endpoint accepts unsanitized user input "
                            "in the 'id' parameter, enabling SQL injection. "
                            "An attacker can extract all database rows."
                        ),
                        "severity": "high",
                        "target": f"http://{TARGET_IP}/api/users",
                        "evidence": [
                            "GET /api/users?id=1%27+OR+%271%27%3D%271 HTTP/1.1 → "
                            "200 OK, 150 rows returned instead of 1"
                        ],
                        "cvss_score": 8.5,
                        "cve_ids": [],
                        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                        "remediation": (
                            "Use parameterised queries (prepared statements). "
                            "Apply input validation. Limit DB user privileges."
                        ),
                        "confirmed": True,
                    },
                ),
            )
        return AgentAction(
            thought="Exploitation phase complete.",
            final_answer=(
                f"Found 1 HIGH-severity vulnerability on http://{TARGET_IP}: "
                "SQL Injection in /api/users."
            ),
        )

    async def research(self, query: str) -> str:
        return (
            "nginx 1.24.0: no known critical RCE CVEs in this version. "
            "Apache Tomcat 9.0.70: check CVE-2023-41080 (open redirect). "
            "Recommend OWASP Top 10 testing on web application."
        )

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Critic agent LLM — VALID for all findings
# ---------------------------------------------------------------------------


class _CriticLLM(LLMClient):
    """Critic LLM: always returns VALID for generate_text() calls."""

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise NotImplementedError("CriticAgent does not use reason()")

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return (
            "VALID: The finding is well-documented with evidence, a CVSS score, "
            "a clear description, and actionable remediation."
        )


# ---------------------------------------------------------------------------
# Report agent LLM — mock text for each generation pass
# ---------------------------------------------------------------------------

_EXEC_SUMMARY = (
    "The penetration test of 192.168.1.100 identified one high-severity SQL injection "
    "vulnerability in the /api/users endpoint. This finding poses a significant risk "
    "of data exfiltration. Immediate remediation is strongly recommended."
)
_FINDING_DESCRIPTION_ENHANCED = (
    "The /api/users endpoint accepts unsanitised input in the id parameter, enabling "
    "blind and union-based SQL injection. During testing, an attacker-controlled "
    "payload returned all 150 database rows, confirming data exfiltration is possible."
)
_FINDING_REMEDIATION_ENHANCED = (
    "Implement parameterised queries using prepared statements in all database "
    "interactions. Apply strict input validation and enforce least-privilege DB access. "
    "Reference OWASP ASVS V5 for input validation requirements."
)
_ATTACK_NARRATIVE = (
    "The assessment commenced with passive and active reconnaissance of 192.168.1.100, "
    "identifying four open ports and the nginx/Tomcat web stack. Web crawling revealed "
    "three endpoints including /api/users. Exploitation testing confirmed a SQL injection "
    "vulnerability, enabling full database read access. No further attack chains were "
    "identified in the time-boxed engagement."
)


class _ReportLLM(LLMClient):
    """Report LLM: cycles through the four expected generate_text() calls in order."""

    def __init__(self) -> None:
        self._responses = iter([
            _EXEC_SUMMARY,
            _FINDING_DESCRIPTION_ENHANCED,
            _FINDING_REMEDIATION_ENHANCED,
            _ATTACK_NARRATIVE,
        ])

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise NotImplementedError("ReportAgent does not use reason()")

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        try:
            return next(self._responses)
        except StopIteration:
            return "Additional report text generated by mock."


# ---------------------------------------------------------------------------
# Mock tool output models
# ---------------------------------------------------------------------------


class _SubfinderOutput(ToolOutput):
    subdomains: list[str] = []


class _NmapOutput(ToolOutput):
    hosts: list[Host] = []
    open_ports: list[int] = []


class _WebFingerprintOutput(ToolOutput):
    tech_stack: list[str] = []


class _KatanaCrawlOutput(ToolOutput):
    urls: list[str] = []


# ---------------------------------------------------------------------------
# Mock tool classes — no subprocess, no network
# ---------------------------------------------------------------------------


class _IntTestSubfinderTool(ToolBase):
    """Mock subfinder: returns three hardcoded subdomains."""

    capabilities = ["subdomain_enumeration"]
    category = "recon"

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def description(self) -> str:
        return "Mock passive subdomain enumerator."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "api.target.com\nwww.target.com\nmail.target.com"

    def parse_output(self, raw_output: str) -> _SubfinderOutput:
        subdomains = [ln.strip() for ln in raw_output.splitlines() if ln.strip()]
        return _SubfinderOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            subdomains=subdomains,
        )


class _IntTestNmapTool(ToolBase):
    """Mock nmap: returns one host at 192.168.1.100 with 4 open ports."""

    capabilities = ["port_scanning"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock port scanner."

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
        return "mock nmap xml output"

    def parse_output(self, raw_output: str) -> _NmapOutput:
        host = Host(
            ip=TARGET_IP,
            hostnames=["webserver.example.com"],
            os="Linux",
            os_version="5.15",
            services=[
                Service(port=22, name="ssh", product="OpenSSH", version="8.9p1"),
                Service(port=80, name="http", product="nginx", version="1.24.0"),
                Service(port=443, name="https", product="nginx", version="1.24.0"),
                Service(
                    port=8080,
                    name="http-proxy",
                    product="Apache Tomcat",
                    version="9.0.70",
                ),
            ],
        )
        return _NmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=[host],
            open_ports=[22, 80, 443, 8080],
        )


class _IntTestWhatwebTool(ToolBase):
    """Mock WhatWeb: returns nginx + Bootstrap + jQuery tech stack."""

    capabilities = ["web_fingerprinting"]
    category = "recon"

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def description(self) -> str:
        return "Mock web technology fingerprinter."

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
        return "nginx 1.24, Bootstrap 5, jQuery 3"

    def parse_output(self, raw_output: str) -> _WebFingerprintOutput:
        return _WebFingerprintOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            tech_stack=["nginx 1.24", "Bootstrap 5", "jQuery 3"],
        )


class _IntTestKatanaTool(ToolBase):
    """Mock Katana: returns three hardcoded crawled URLs."""

    capabilities = ["web_crawling"]
    category = "scan"

    @property
    def name(self) -> str:
        return "katana"

    @property
    def description(self) -> str:
        return "Mock web crawler."

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
        return f"{base}/login\n{base}/api/users\n{base}/admin"

    def parse_output(self, raw_output: str) -> _KatanaCrawlOutput:
        urls = [ln.strip() for ln in raw_output.splitlines() if ln.strip()]
        return _KatanaCrawlOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            urls=urls,
        )


# ---------------------------------------------------------------------------
# Mock resolver factories
# ---------------------------------------------------------------------------


def _make_mock_recon_resolver() -> MagicMock:
    """Resolver for the recon phase: subfinder / nmap / whatweb."""
    _MAP: dict[str, tuple[type[ToolBase], str]] = {
        "subdomain_enumeration": (_IntTestSubfinderTool, "subfinder"),
        "port_scanning": (_IntTestNmapTool, "nmap"),
        "web_fingerprinting": (_IntTestWhatwebTool, "whatweb"),
    }
    resolver = MagicMock(spec=ToolResolver)

    def _find(capability: str) -> ToolMatch | None:
        entry = _MAP.get(capability)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find
    resolver.get_all_capabilities.return_value = sorted(_MAP.keys())
    resolver.check_mcp_servers.return_value = []
    return resolver


def _make_mock_scan_resolver() -> MagicMock:
    """Resolver for the scan phase: katana (web_crawling)."""
    _MAP: dict[str, tuple[type[ToolBase], str]] = {
        "web_crawling": (_IntTestKatanaTool, "katana"),
    }
    resolver = MagicMock(spec=ToolResolver)

    def _find(capability: str) -> ToolMatch | None:
        entry = _MAP.get(capability)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find
    resolver.get_all_capabilities.return_value = sorted(_MAP.keys())
    resolver.check_mcp_servers.return_value = []
    return resolver


def _make_mock_exploit_resolver() -> MagicMock:
    """Resolver for the exploit phase — no tools actually called in this test."""
    resolver = MagicMock(spec=ToolResolver)
    resolver.find_tool.return_value = None
    resolver.get_all_capabilities.return_value = []
    resolver.check_mcp_servers.return_value = []
    return resolver


# ---------------------------------------------------------------------------
# THE FULL PIPELINE TEST
# ---------------------------------------------------------------------------


async def test_complete_pentest_pipeline(tmp_path: Path) -> None:
    """Complete pentest pipeline: Recon → Scan → Exploit → Critic → Report.

    Orchestrator follows a scripted action sequence driven by a mock LLM.
    Each phase agent runs against mock tool resolvers and mock LLMs.

    Asserts:
    - All five phases are spun up in order
    - recon/scan/exploit are explicitly shut down between phases
    - Hosts discovered in recon are persisted before scan runs
    - Exploit finding passes critic validation (mark_finding_validated called)
    - PentestReport has executive_summary, narrative, and findings list
    - Full message trail in state store (RESULT from every phase agent)
    - Engagement completes cleanly (status='completed', no timeout)
    """
    scope = PIPELINE_SCOPE

    # Shared mutable state captured across hooks
    spin_up_calls: list[tuple[str, AgentMessage]] = []
    shut_down_calls: list[str] = []
    running_agents: list[str] = []
    bus_holder: list[MessageBus] = []
    state_holder: list[StateStore] = []
    eid_holder: list[str] = []

    # Snapshot of state-store targets taken just before the scan agent runs
    # (proves recon hosts are available to scan phase)
    targets_at_scan_start: list[dict[str, Any]] = []

    # One LLM per phase agent
    recon_llm = _ReconSequenceLLM()
    scan_llm = _ScanSequenceLLM()
    exploit_llm = _ExploitSequenceLLM()
    critic_llm = _CriticLLM()
    report_llm = _ReportLLM()

    _llm_by_agent: dict[str, LLMClient] = {
        "recon": recon_llm,
        "scan": scan_llm,
        "exploit": exploit_llm,
        "critic": critic_llm,
        "report": report_llm,
    }

    async def on_shut_down(agent_name: str) -> None:
        """Remove the agent from running and send a STATUS so the orchestrator
        has a pending message to act on — triggering the next spin_up call."""
        shut_down_calls.append(agent_name)
        if agent_name in running_agents:
            running_agents.remove(agent_name)
        # Deliver a STATUS message so the orchestrator loop calls the LLM again
        # for the next phase action (e.g., spin_up scan after shut_down recon).
        if bus_holder and eid_holder:
            await bus_holder[0].send(
                AgentMessage.status(
                    from_agent=agent_name,
                    to_agent=ORCHESTRATOR,
                    engagement_id=eid_holder[0],
                    content={"status": f"{agent_name} shut down cleanly"},
                )
            )

    async def on_spin_up(agent_type: str, task_msg: AgentMessage) -> MagicMock:
        """Run the appropriate phase agent with its mock LLM, then send RESULT."""
        spin_up_calls.append((agent_type, task_msg))
        running_agents.append(agent_type)

        state = state_holder[0]
        bus = bus_holder[0]
        eid = task_msg.engagement_id
        llm = _llm_by_agent[agent_type]
        result: dict[str, Any] = {}

        if agent_type == "recon":
            mock_resolver = _make_mock_recon_resolver()
            with patch("clinkz.agents.recon.ToolResolver", return_value=mock_resolver):
                agent = ReconAgent(
                    llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
                )
                result = await agent.run(task_msg.content)

        elif agent_type == "scan":
            # Snapshot hosts persisted by recon before the scan agent begins
            targets_at_scan_start.extend(await state.get_targets(eid))

            mock_resolver = _make_mock_scan_resolver()
            with patch("clinkz.agents.scan.ToolResolver", return_value=mock_resolver):
                agent = ScanAgent(
                    llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
                )
                result = await agent.run(task_msg.content)

        elif agent_type == "exploit":
            mock_resolver = _make_mock_exploit_resolver()
            with patch("clinkz.agents.exploit.ToolResolver", return_value=mock_resolver):
                agent = ExploitAgent(
                    llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
                )
                result = await agent.run(task_msg.content)

        elif agent_type == "critic":
            # Fetch findings (with DB IDs) so critic can call mark_finding_validated
            findings = await state.get_findings(eid)
            agent = CriticAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
            )
            result = await agent.run({"findings": findings})

        elif agent_type == "report":
            agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
            )
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

    # ------------------------------------------------------------------
    # Orchestrator LLM sequence — 9 actions for the full pipeline
    #
    # Phases:
    #   1. spin_up recon    ← first_iteration trigger
    #   2. shut_down recon  ← triggered by recon RESULT in pending
    #      on_shut_down → STATUS message put on bus
    #   3. spin_up scan     ← triggered by STATUS from shut_down
    #   4. shut_down scan   ← triggered by scan RESULT
    #   5. spin_up exploit  ← triggered by STATUS from shut_down
    #   6. shut_down exploit ← triggered by exploit RESULT
    #   7. spin_up critic   ← triggered by STATUS from shut_down
    #   8. spin_up report   ← triggered by critic RESULT
    #   9. complete         ← triggered by report RESULT
    # ------------------------------------------------------------------

    orch_llm = _SequenceLLM([
        # 1. Kick off reconnaissance
        AgentAction(
            thought="Starting reconnaissance phase.",
            tool_call=_tc(
                "spin_up_agent",
                agent_type="recon",
                task=(
                    f"Perform full reconnaissance on {TARGET_IP}: "
                    "subdomain enumeration, port scanning, service fingerprinting."
                ),
            ),
        ),
        # 2. Recon RESULT received → shut down recon agent
        AgentAction(
            thought="Recon complete. Shutting down recon agent.",
            tool_call=_tc("shut_down_agent", agent_name="recon"),
        ),
        # 3. STATUS (recon shut down) received → start scan phase
        AgentAction(
            thought="Recon agent stopped. Starting scan phase.",
            tool_call=_tc(
                "spin_up_agent",
                agent_type="scan",
                task=(
                    f"Map the attack surface on {TARGET_IP}: "
                    "crawl web application, fuzz directories, discover parameters."
                ),
            ),
        ),
        # 4. Scan RESULT received → shut down scan agent
        AgentAction(
            thought="Scan complete. Shutting down scan agent.",
            tool_call=_tc("shut_down_agent", agent_name="scan"),
        ),
        # 5. STATUS (scan shut down) received → start exploitation phase
        AgentAction(
            thought="Scan agent stopped. Starting exploitation phase.",
            tool_call=_tc(
                "spin_up_agent",
                agent_type="exploit",
                task=(
                    f"Test all discovered services on {TARGET_IP} for vulnerabilities. "
                    "Focus on web endpoints: /login, /api/users, /admin."
                ),
            ),
        ),
        # 6. Exploit RESULT received → shut down exploit agent
        AgentAction(
            thought="Exploitation complete. Shutting down exploit agent.",
            tool_call=_tc("shut_down_agent", agent_name="exploit"),
        ),
        # 7. STATUS (exploit shut down) received → critic validates findings
        AgentAction(
            thought="Exploit agent stopped. Spinning up critic to validate findings.",
            tool_call=_tc(
                "spin_up_agent",
                agent_type="critic",
                task="Validate all findings reported by the exploit agent.",
            ),
        ),
        # 8. Critic RESULT received → generate final report
        AgentAction(
            thought="Critic validation complete. Spinning up report agent.",
            tool_call=_tc(
                "spin_up_agent",
                agent_type="report",
                task="Generate the final penetration test report.",
            ),
        ),
        # 9. Report RESULT received → declare engagement complete
        AgentAction(
            thought="Report delivered. Declaring engagement complete.",
            tool_call=_tc(
                "complete_engagement",
                summary=(
                    "Engagement complete. Found 1 HIGH-severity SQL injection vulnerability "
                    f"on {TARGET_IP}. Report generated and delivered."
                ),
            ),
        ),
    ])

    orchestrator = OrchestratorAgent(
        llm=orch_llm,
        db_path=str(tmp_path / "pipeline.db"),
    )

    with patch(
        "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
        side_effect=lifecycle_constructor,
    ):
        with patch("clinkz.orchestrator.orchestrator._POLL_INTERVAL", 0.01):
            result = await orchestrator.run(scope)

    # ── Assertion 1: engagement completed cleanly ─────────────────────────
    assert result["status"] == "completed", (
        f"Expected status='completed'. Got: {result}"
    )
    assert "1 HIGH" in result.get("summary", ""), (
        f"Expected summary to mention the HIGH finding. Got: {result.get('summary')}"
    )

    # ── Assertion 2: all five phases were spun up in the correct order ────
    spun_up_types = [agent_type for agent_type, _ in spin_up_calls]
    assert spun_up_types == ["recon", "scan", "exploit", "critic", "report"], (
        f"Expected spin_up order: recon→scan→exploit→critic→report. "
        f"Actual: {spun_up_types}"
    )

    # ── Assertion 3: recon/scan/exploit were explicitly shut down ─────────
    for phase in ("recon", "scan", "exploit"):
        assert phase in shut_down_calls, (
            f"Expected '{phase}' in shut_down_calls. Actual: {shut_down_calls}"
        )

    # ── Assertion 4: hosts discovered in recon are available to scan ──────
    assert len(targets_at_scan_start) > 0, (
        "targets_at_scan_start is empty — recon results were not persisted "
        "before the scan phase started."
    )
    ips_at_scan_start = {t.get("ip") for t in targets_at_scan_start}
    assert TARGET_IP in ips_at_scan_start, (
        f"Expected {TARGET_IP} to be in the state store before scan started. "
        f"Found IPs: {ips_at_scan_start}"
    )
    # Verify recon host has correct OS and service count
    nmap_host = next(
        (t for t in targets_at_scan_start if t.get("ip") == TARGET_IP), None
    )
    assert nmap_host is not None
    assert nmap_host.get("os") == "Linux", (
        f"Expected os='Linux' for {TARGET_IP}. Got: {nmap_host.get('os')}"
    )
    assert len(nmap_host.get("services", [])) == 4, (
        f"Expected 4 services for {TARGET_IP}. Got: {nmap_host.get('services')}"
    )

    # Open state store for remaining assertions
    assert eid_holder, "Engagement ID was never captured."
    eid = eid_holder[0]

    async with StateStore(str(tmp_path / "pipeline.db")) as state:
        all_findings = await state.get_findings(eid)
        validated_findings = await state.get_findings(eid, validated_only=True)
        all_messages = await state.get_messages(eid)

    # ── Assertion 5: exploit persisted a finding ──────────────────────────
    assert len(all_findings) >= 1, (
        f"Expected at least 1 finding from exploit phase. Found: {len(all_findings)}"
    )
    sqli_finding = next(
        (f for f in all_findings if "SQL Injection" in f.get("title", "")), None
    )
    assert sqli_finding is not None, (
        f"Expected 'SQL Injection' finding. Titles found: "
        f"{[f.get('title') for f in all_findings]}"
    )
    assert sqli_finding.get("severity") == "high"
    assert sqli_finding.get("cvss_score") == 8.5

    # ── Assertion 6: critic validated the exploit finding ─────────────────
    assert len(validated_findings) >= 1, (
        "Expected ≥1 validated finding after critic review. "
        "CriticAgent may not have called mark_finding_validated()."
    )
    validated_titles = [f.get("title") for f in validated_findings]
    assert any("SQL Injection" in t for t in validated_titles), (
        f"Expected the SQL Injection finding to be validated. "
        f"Validated: {validated_titles}"
    )

    # ── Assertion 7: final report contains required sections ──────────────
    report_result_msgs = [
        m for m in all_messages
        if m.get("from_agent") == "report"
        and m.get("message_type") == MessageType.RESULT
    ]
    assert len(report_result_msgs) >= 1, (
        "Expected at least 1 RESULT message from report agent in state store. "
        f"Message senders: {[m.get('from_agent') for m in all_messages]}"
    )
    report_content = json.loads(report_result_msgs[0]["content_json"])
    assert report_content.get("status") == "complete", (
        f"Expected report status='complete'. Got: {report_content.get('status')}"
    )

    report_dict = report_content.get("report", {})
    # Executive summary
    exec_summary = report_dict.get("executive_summary")
    assert exec_summary is not None, "PentestReport is missing executive_summary."
    assert exec_summary.get("overview"), (
        "executive_summary.overview is empty."
    )
    # Narrative (methodology)
    methodology = report_dict.get("methodology", "")
    assert methodology, "PentestReport.methodology (attack narrative) is empty."
    # Findings list in report (may be subset of all findings)
    assert "findings" in report_dict, "PentestReport dict is missing 'findings' key."

    # ── Assertion 8: complete message trail in state store ────────────────
    result_senders = {
        m.get("from_agent")
        for m in all_messages
        if m.get("message_type") == MessageType.RESULT
    }
    for phase in ("recon", "scan", "exploit", "critic", "report"):
        assert phase in result_senders, (
            f"Expected RESULT message from '{phase}' in state store. "
            f"RESULT senders found: {result_senders}"
        )

    # All persisted messages belong to this engagement
    for m in all_messages:
        assert m.get("engagement_id") == eid, (
            f"Message {m.get('id')} has engagement_id={m.get('engagement_id')}, "
            f"expected {eid}"
        )

    # ── Assertion 9: engagement completed cleanly (no forced timeout) ─────
    # The orchestrator loop exited via complete_engagement (not via force-complete
    # or idle timeout). Verified by status='completed' and expected summary text.
    assert result["status"] == "completed"
    # Critic and report were not shut down (per spec — no shut_down calls for them),
    # so they remain in running_agents. The engagement completion is clean because
    # the loop exited via the explicit complete_engagement tool call.
    assert "recon" not in running_agents, (
        f"recon should have been shut down. running_agents: {running_agents}"
    )
    assert "scan" not in running_agents, (
        f"scan should have been shut down. running_agents: {running_agents}"
    )
    assert "exploit" not in running_agents, (
        f"exploit should have been shut down. running_agents: {running_agents}"
    )
