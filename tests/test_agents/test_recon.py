"""Tests for ReconAgent — dynamic tool discovery and recon workflow.

Coverage:
- resolver.find_tool() is called with capability strings, never tool names
- Discovered hosts (nmap) and subdomains (subfinder) are persisted to state store
- run() returns the correct result structure
- All tool executions are logged as actions in the state store
- execute_capability schema is the only schema passed to the LLM
- Mid-run QUERY messages are handled without crashing
- Mid-run QUERY messages are injected into the LLM conversation
- Lifecycle manager sends RESULT message to Orchestrator bus after completion
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from clinkz.agents.recon import ReconAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host, Service
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolMatch, ToolResolver

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="recon-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mock LLM — deterministic sequence of capability requests then done
# ---------------------------------------------------------------------------


class MockReconLLM(LLMClient):
    """Deterministic LLM: calls execute_capability 3 times then returns done.

    Call sequence:
      1 → execute_capability(subdomain_enumeration, {domain: example.com})
      2 → execute_capability(port_scanning, {target: example.com})
      3 → execute_capability(web_fingerprinting, {url: http://example.com})
      4+ → final_answer
    """

    def __init__(self) -> None:
        self._calls = 0
        self.tool_schemas_received: list[list[dict[str, Any]]] = []
        self.capabilities_requested: list[str] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._calls += 1
        if tools is not None:
            self.tool_schemas_received.append(list(tools))

        sequence = [
            ("subdomain_enumeration", {"domain": "example.com"}),
            ("port_scanning", {"target": "example.com"}),
            ("web_fingerprinting", {"url": "http://example.com"}),
        ]

        if self._calls <= len(sequence):
            capability, cap_args = sequence[self._calls - 1]
            self.capabilities_requested.append(capability)
            return AgentAction(
                thought=f"I need {capability} to continue recon.",
                tool_call=ToolCall(
                    id=f"call_{self._calls:03d}",
                    name="execute_capability",
                    arguments={"capability": capability, "arguments": cap_args},
                ),
            )

        return AgentAction(
            thought="Recon complete — found subdomains and live services.",
            final_answer="Recon complete. Discovered: api.example.com, www.example.com, "
            "mail.example.com. Live host 1.2.3.4 on ports 80/443 running nginx 1.24.",
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Mock tool output models
# ---------------------------------------------------------------------------


class _SubfinderOutput(ToolOutput):
    """Mock subfinder output."""

    subdomains: list[str] = []


class _NmapOutput(ToolOutput):
    """Mock nmap output."""

    hosts: list[Host] = []
    open_ports: list[int] = []


class _WebFingerprintOutput(ToolOutput):
    """Mock web fingerprint output."""

    tech_stack: list[str] = []


# ---------------------------------------------------------------------------
# Mock tool classes (ToolBase subclasses, no subprocess)
# ---------------------------------------------------------------------------


class _MockSubfinderTool(ToolBase):
    """Returns 3 hardcoded subdomains."""

    capabilities = ["subdomain_enumeration", "passive_recon"]
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
        return "api.example.com\nwww.example.com\nmail.example.com"

    def parse_output(self, raw_output: str) -> _SubfinderOutput:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return _SubfinderOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            subdomains=subdomains,
        )


class _MockNmapTool(ToolBase):
    """Returns one host at 1.2.3.4 with ports 80/443."""

    capabilities = ["port_scanning", "service_detection", "host_discovery"]
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
        target = args.get("target", "")
        self._check_scope(target)
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock nmap xml output"

    def parse_output(self, raw_output: str) -> _NmapOutput:
        host = Host(
            ip="1.2.3.4",
            hostnames=["example.com"],
            services=[
                Service(port=80, name="http", product="nginx", version="1.24"),
                Service(port=443, name="https", product="nginx", version="1.24"),
            ],
        )
        return _NmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=[host],
            open_ports=[80, 443],
        )


class _MockWhatwebTool(ToolBase):
    """Returns a simple tech stack list."""

    # Note: intentionally omit 'technology_detection' to avoid conflicting
    # with HttpxTool's registered capabilities in the global ToolBase registry.
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
        return "nginx, Bootstrap, jQuery"

    def parse_output(self, raw_output: str) -> _WebFingerprintOutput:
        return _WebFingerprintOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            tech_stack=["nginx", "Bootstrap", "jQuery"],
        )


# ---------------------------------------------------------------------------
# Mock ToolResolver factory
# ---------------------------------------------------------------------------


def _make_mock_resolver() -> ToolResolver:
    """Return a MagicMock resolver that maps capabilities to mock tool classes."""
    from unittest.mock import MagicMock

    _MAP: dict[str, tuple[type[ToolBase], str]] = {
        "subdomain_enumeration": (_MockSubfinderTool, "subfinder"),
        "port_scanning": (_MockNmapTool, "nmap"),
        "web_fingerprinting": (_MockWhatwebTool, "whatweb"),
    }

    resolver = MagicMock(spec=ToolResolver)

    def _find_tool(capability: str) -> ToolMatch | None:
        entry = _MAP.get(capability)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find_tool
    return resolver


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _make_agent(
    db_path: Path,
    resolver: Any = None,
    llm: LLMClient | None = None,
) -> tuple[ReconAgent, StateStore, str]:
    """Spin up a fresh ReconAgent with an in-memory-SQLite state store."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("recon-test", SCOPE.model_dump())
    agent = ReconAgent(
        llm=llm or MockReconLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
        resolver=resolver if resolver is not None else _make_mock_resolver(),
    )
    return agent, state, eid


# ---------------------------------------------------------------------------
# Tests: resolver is called with capability strings, never tool names
# ---------------------------------------------------------------------------


async def test_resolver_called_with_capability_strings(tmp_path: Path) -> None:
    """resolver.find_tool() receives capability strings, never raw tool names."""
    resolver = _make_mock_resolver()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver)

    await agent.run({"targets": ["example.com"]})
    await state.close()

    called_with = [call.args[0] for call in resolver.find_tool.call_args_list]
    assert "subdomain_enumeration" in called_with
    assert "port_scanning" in called_with
    assert "web_fingerprinting" in called_with


async def test_resolver_never_called_with_tool_names(tmp_path: Path) -> None:
    """No call to find_tool() uses a bare tool name like 'subfinder' or 'nmap'."""
    resolver = _make_mock_resolver()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver)

    await agent.run({"targets": ["example.com"]})
    await state.close()

    called_with = [call.args[0] for call in resolver.find_tool.call_args_list]
    for tool_name in ("subfinder", "nmap", "whatweb", "httpx", "wafw00f"):
        assert tool_name not in called_with, (
            f"find_tool() was called with tool name '{tool_name}' — "
            "it must only be called with capability strings."
        )


# ---------------------------------------------------------------------------
# Tests: state store receives discovered hosts and subdomains
# ---------------------------------------------------------------------------


async def test_nmap_host_persisted_to_state_store(tmp_path: Path) -> None:
    """Host discovered by nmap is persisted to the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    ips = [t.get("ip") for t in targets]
    assert "1.2.3.4" in ips, f"Expected '1.2.3.4' in persisted IPs, got: {ips}"


async def test_subfinder_subdomains_persisted_to_state_store(tmp_path: Path) -> None:
    """Subdomains from subfinder are persisted as lightweight host entries."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    all_identifiers = {t.get("ip", "") for t in targets}
    assert "api.example.com" in all_identifiers
    assert "www.example.com" in all_identifiers
    assert "mail.example.com" in all_identifiers


async def test_all_targets_in_state_store(tmp_path: Path) -> None:
    """State store contains both nmap host and all discovered subdomains."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    # 3 subdomains + 1 nmap host = 4 entries
    assert len(targets) >= 4, (
        f"Expected at least 4 target entries, got {len(targets)}: "
        f"{[t.get('ip') for t in targets]}"
    )


# ---------------------------------------------------------------------------
# Tests: result structure
# ---------------------------------------------------------------------------


async def test_run_returns_summary_hosts_status(tmp_path: Path) -> None:
    """run() returns a dict with 'summary', 'hosts', and 'status' keys."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"targets": ["example.com"]})
    await state.close()

    assert "summary" in result
    assert "hosts" in result
    assert "status" in result
    assert result["status"] == "complete"
    assert result["summary"], "summary must be non-empty"
    assert isinstance(result["hosts"], list)


async def test_run_hosts_match_state_store(tmp_path: Path) -> None:
    """run() returns the same host data as the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"targets": ["example.com"]})
    db_targets = await state.get_targets(eid)
    await state.close()

    assert len(result["hosts"]) == len(db_targets)


# ---------------------------------------------------------------------------
# Tests: actions logged to state store
# ---------------------------------------------------------------------------


async def test_all_tools_logged_as_actions(tmp_path: Path) -> None:
    """Each tool execution is logged as an action in the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    tool_names = {a["tool"] for a in actions}
    assert "subfinder" in tool_names
    assert "nmap" in tool_names
    assert "whatweb" in tool_names


async def test_all_actions_completed(tmp_path: Path) -> None:
    """All logged actions have status 'completed' (no failures)."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    for action in actions:
        assert action["status"] == "completed", (
            f"Action for tool '{action['tool']}' has status '{action['status']}'"
        )


async def test_actions_linked_to_recon_phase(tmp_path: Path) -> None:
    """All actions are tagged with the 'recon' phase."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"targets": ["example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    for action in actions:
        assert action["phase"] == "recon", (
            f"Expected phase='recon', got '{action['phase']}' for tool '{action['tool']}'"
        )


# ---------------------------------------------------------------------------
# Tests: execute_capability schema exposed to LLM
# ---------------------------------------------------------------------------


async def test_only_execute_capability_schema_sent_to_llm(tmp_path: Path) -> None:
    """The LLM receives only the execute_capability schema, not raw tool schemas."""

    class CapturingLLM(MockReconLLM):
        async def reason(
            self,
            messages: list[LLMMessage],
            tools: list[dict[str, Any]] | None = None,
        ) -> AgentAction:
            return await super().reason(messages, tools)

    llm = CapturingLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm)

    await agent.run({"targets": ["example.com"]})
    await state.close()

    assert llm.tool_schemas_received, "LLM reason() was never called with tool schemas"
    first_call_schemas = llm.tool_schemas_received[0]
    schema_names = [s["name"] for s in first_call_schemas]

    assert "execute_capability" in schema_names
    # Raw tool names must NOT appear in schemas
    for bare_name in ("subfinder", "nmap", "whatweb", "httpx", "wafw00f"):
        assert bare_name not in schema_names, (
            f"Raw tool name '{bare_name}' was exposed to LLM — "
            "only 'execute_capability' should be in the schema list."
        )


# ---------------------------------------------------------------------------
# Tests: mid-run QUERY handling
# ---------------------------------------------------------------------------


async def test_mid_run_query_does_not_crash(tmp_path: Path) -> None:
    """An incoming QUERY injected into the inbox before run() does not crash."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    query = AgentMessage.query(
        from_agent=ORCHESTRATOR,
        to_agent="recon",
        engagement_id=eid,
        content={"query": "Also enumerate api.example.com specifically."},
    )
    agent.receive_message(query)

    result = await agent.run({"targets": ["example.com"]})
    await state.close()

    assert result["status"] == "complete"


async def test_mid_run_query_injected_into_llm_messages(tmp_path: Path) -> None:
    """A QUERY received mid-run is injected into the LLM conversation."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    query_text = "Please check port 8443 specifically."
    query = AgentMessage.query(
        from_agent=ORCHESTRATOR,
        to_agent="recon",
        engagement_id=eid,
        content={"query": query_text},
    )
    agent.receive_message(query)

    await agent.run({"targets": ["example.com"]})
    await state.close()

    injected = [
        m
        for m in agent.messages
        if m.role == "user" and query_text in (m.content or "")
    ]
    assert injected, (
        f"Query '{query_text}' was not found in agent.messages. "
        f"Messages: {[m.content for m in agent.messages if m.role == 'user']}"
    )


async def test_multiple_queries_all_injected(tmp_path: Path) -> None:
    """Multiple QUERY messages queued before run() are all injected."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    for i in range(3):
        query = AgentMessage.query(
            from_agent=ORCHESTRATOR,
            to_agent="recon",
            engagement_id=eid,
            content={"query": f"Query number {i}."},
        )
        agent.receive_message(query)

    result = await agent.run({"targets": ["example.com"]})
    await state.close()

    assert result["status"] == "complete"
    injected = [m for m in agent.messages if m.role == "user" and "Query number" in (m.content or "")]
    assert len(injected) == 3


# ---------------------------------------------------------------------------
# Test: RESULT message sent to Orchestrator bus via lifecycle manager
# ---------------------------------------------------------------------------


async def test_lifecycle_sends_result_to_orchestrator_bus(tmp_path: Path) -> None:
    """After ReconAgent finishes, the lifecycle manager sends RESULT to Orchestrator."""
    state = StateStore(tmp_path / "lifecycle.db")
    await state.connect()
    eid = await state.create_engagement("lifecycle-test", SCOPE.model_dump())

    bus = MessageBus(state=state)
    mock_resolver = _make_mock_resolver()

    # Patch ToolResolver so the agent's default ToolResolver() is our mock
    with patch("clinkz.agents.recon.ToolResolver", return_value=mock_resolver):
        mgr = AgentLifecycleManager(
            bus=bus,
            llm=MockReconLLM(),
            scope=SCOPE,
            state=state,
            engagement_id=eid,
        )

        task_msg = AgentMessage.task(
            from_agent=ORCHESTRATOR,
            to_agent="recon",
            engagement_id=eid,
            content={"targets": ["example.com"]},
        )

        await mgr.spin_up("recon", task_msg)

        # Block until a message arrives on the Orchestrator queue (RESULT expected)
        result_msg = await asyncio.wait_for(
            bus.receive(ORCHESTRATOR), timeout=15.0
        )

    assert result_msg.message_type == MessageType.RESULT, (
        f"Expected RESULT message, got {result_msg.message_type}"
    )
    assert result_msg.from_agent == "recon"
    assert result_msg.to_agent == ORCHESTRATOR
    assert "hosts" in result_msg.content
    assert "summary" in result_msg.content

    await state.close()
