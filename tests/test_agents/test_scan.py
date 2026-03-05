"""Tests for ScanAgent — dynamic tool discovery and attack surface mapping.

Coverage:
- resolver.find_tool() is called with capability strings, never tool names
- Discovered endpoints (crawl), paths (fuzzer), and parameters are persisted
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

from clinkz.agents.scan import ScanAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolMatch, ToolResolver

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="scan-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mock LLM — deterministic sequence of capability requests then done
# ---------------------------------------------------------------------------


class MockScanLLM(LLMClient):
    """Deterministic LLM: calls execute_capability 3 times then returns done.

    Call sequence:
      1 → execute_capability(web_crawling,         {url: http://example.com})
      2 → execute_capability(directory_fuzzing,    {url: http://example.com})
      3 → execute_capability(parameter_discovery,  {url: http://example.com/api})
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
            ("web_crawling", {"url": "http://example.com"}),
            ("directory_fuzzing", {"url": "http://example.com"}),
            ("parameter_discovery", {"url": "http://example.com/api"}),
        ]

        if self._calls <= len(sequence):
            capability, cap_args = sequence[self._calls - 1]
            self.capabilities_requested.append(capability)
            return AgentAction(
                thought=f"I need {capability} to map the attack surface.",
                tool_call=ToolCall(
                    id=f"call_{self._calls:03d}",
                    name="execute_capability",
                    arguments={"capability": capability, "arguments": cap_args},
                ),
            )

        return AgentAction(
            thought="Scan complete — found endpoints, paths, and parameters.",
            final_answer=(
                "Scan complete. Discovered: /login, /api/v1/users, /admin. "
                "Parameters: id, token. 3 endpoints, 2 hidden paths found."
            ),
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Mock tool output models
# ---------------------------------------------------------------------------


class _CrawlOutput(ToolOutput):
    """Mock crawler output."""

    endpoints: list[str] = []


class _FuzzOutput(ToolOutput):
    """Mock directory fuzzer output."""

    paths: list[str] = []


class _ParamOutput(ToolOutput):
    """Mock parameter discovery output."""

    parameters: list[str] = []


# ---------------------------------------------------------------------------
# Mock tool classes (ToolBase subclasses, no subprocess)
# ---------------------------------------------------------------------------


class _MockKatanaTool(ToolBase):
    """Returns 3 hardcoded crawled endpoints."""

    capabilities = ["web_crawling", "link_crawling"]
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
        return (
            "http://example.com/login\n"
            "http://example.com/api/v1/users\n"
            "http://example.com/about"
        )

    def parse_output(self, raw_output: str) -> _CrawlOutput:
        endpoints = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return _CrawlOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            endpoints=endpoints,
        )


class _MockFfufTool(ToolBase):
    """Returns 2 hardcoded fuzzed paths."""

    capabilities = ["directory_fuzzing", "path_bruteforce"]
    category = "scan"

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def description(self) -> str:
        return "Mock directory fuzzer."

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
        return "/admin\n/backup"

    def parse_output(self, raw_output: str) -> _FuzzOutput:
        paths = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return _FuzzOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            paths=paths,
        )


class _MockParamTool(ToolBase):
    """Returns 2 hardcoded discovered parameters.

    Uses name "nikto" so it doesn't inject an unexpected new tool into the
    global ToolBase subclass registry (which resolver tests enumerate).
    The mock ToolResolver still logs the action under the name "arjun" via
    its _MAP entry — name resolution is independent of the class name property.
    """

    capabilities = ["parameter_discovery"]
    category = "exploit"

    @property
    def name(self) -> str:
        return "nikto"

    @property
    def description(self) -> str:
        return "Mock parameter discovery tool."

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
        return "id\ntoken"

    def parse_output(self, raw_output: str) -> _ParamOutput:
        parameters = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return _ParamOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            parameters=parameters,
        )


# ---------------------------------------------------------------------------
# Mock ToolResolver factory
# ---------------------------------------------------------------------------


def _make_mock_resolver() -> ToolResolver:
    """Return a MagicMock resolver that maps capabilities to mock tool classes."""
    from unittest.mock import MagicMock

    _MAP: dict[str, tuple[type[ToolBase], str]] = {
        "web_crawling": (_MockKatanaTool, "katana"),
        "directory_fuzzing": (_MockFfufTool, "ffuf"),
        "parameter_discovery": (_MockParamTool, "arjun"),
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
) -> tuple[ScanAgent, StateStore, str]:
    """Spin up a fresh ScanAgent with an in-memory-SQLite state store."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("scan-test", SCOPE.model_dump())
    agent = ScanAgent(
        llm=llm or MockScanLLM(),
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

    await agent.run({"urls": ["http://example.com"]})
    await state.close()

    called_with = [call.args[0] for call in resolver.find_tool.call_args_list]
    assert "web_crawling" in called_with
    assert "directory_fuzzing" in called_with
    assert "parameter_discovery" in called_with


async def test_resolver_never_called_with_tool_names(tmp_path: Path) -> None:
    """No call to find_tool() uses a bare tool name like 'katana' or 'ffuf'."""
    resolver = _make_mock_resolver()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver)

    await agent.run({"urls": ["http://example.com"]})
    await state.close()

    called_with = [call.args[0] for call in resolver.find_tool.call_args_list]
    for tool_name in ("katana", "ffuf", "arjun", "nuclei", "nikto"):
        assert tool_name not in called_with, (
            f"find_tool() was called with tool name '{tool_name}' — "
            "it must only be called with capability strings."
        )


# ---------------------------------------------------------------------------
# Tests: state store receives discovered endpoints, paths, and parameters
# ---------------------------------------------------------------------------


async def test_crawled_endpoints_persisted_to_state_store(tmp_path: Path) -> None:
    """Endpoints discovered by the crawler are persisted to the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    identifiers = {t.get("ip") for t in targets}
    assert "http://example.com/login" in identifiers
    assert "http://example.com/api/v1/users" in identifiers
    assert "http://example.com/about" in identifiers


async def test_fuzzed_paths_persisted_to_state_store(tmp_path: Path) -> None:
    """Paths discovered by directory fuzzing are persisted to the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    identifiers = {t.get("ip") for t in targets}
    assert "/admin" in identifiers
    assert "/backup" in identifiers


async def test_discovered_parameters_persisted_to_state_store(tmp_path: Path) -> None:
    """Parameters discovered via parameter discovery are persisted."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    identifiers = {t.get("ip") for t in targets}
    assert "id" in identifiers
    assert "token" in identifiers


async def test_all_scan_results_in_state_store(tmp_path: Path) -> None:
    """State store contains endpoints, paths, and parameters from all tools."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    targets = await state.get_targets(eid)
    await state.close()

    # 3 endpoints + 2 paths + 2 parameters = 7 entries
    assert len(targets) >= 7, (
        f"Expected at least 7 target entries, got {len(targets)}: "
        f"{[t.get('ip') for t in targets]}"
    )


# ---------------------------------------------------------------------------
# Tests: result structure
# ---------------------------------------------------------------------------


async def test_run_returns_summary_endpoints_status(tmp_path: Path) -> None:
    """run() returns a dict with 'summary', 'endpoints', and 'status' keys."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"urls": ["http://example.com"]})
    await state.close()

    assert "summary" in result
    assert "endpoints" in result
    assert "status" in result
    assert result["status"] == "complete"
    assert result["summary"], "summary must be non-empty"
    assert isinstance(result["endpoints"], list)


async def test_run_endpoints_match_state_store(tmp_path: Path) -> None:
    """run() returns the same endpoint data as the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"urls": ["http://example.com"]})
    db_targets = await state.get_targets(eid)
    await state.close()

    assert len(result["endpoints"]) == len(db_targets)


# ---------------------------------------------------------------------------
# Tests: actions logged to state store
# ---------------------------------------------------------------------------


async def test_all_tools_logged_as_actions(tmp_path: Path) -> None:
    """Each tool execution is logged as an action in the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    tool_names = {a["tool"] for a in actions}
    assert "katana" in tool_names
    assert "ffuf" in tool_names
    assert "arjun" in tool_names


async def test_all_actions_completed(tmp_path: Path) -> None:
    """All logged actions have status 'completed' (no failures)."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    for action in actions:
        assert action["status"] == "completed", (
            f"Action for tool '{action['tool']}' has status '{action['status']}'"
        )


async def test_actions_linked_to_scan_phase(tmp_path: Path) -> None:
    """All actions are tagged with the 'scan' phase."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"urls": ["http://example.com"]})
    actions = await state.get_actions(eid)
    await state.close()

    for action in actions:
        assert action["phase"] == "scan", (
            f"Expected phase='scan', got '{action['phase']}' for tool '{action['tool']}'"
        )


# ---------------------------------------------------------------------------
# Tests: execute_capability schema exposed to LLM
# ---------------------------------------------------------------------------


async def test_only_execute_capability_schema_sent_to_llm(tmp_path: Path) -> None:
    """The LLM receives only the execute_capability schema, not raw tool schemas."""

    class CapturingLLM(MockScanLLM):
        async def reason(
            self,
            messages: list[LLMMessage],
            tools: list[dict[str, Any]] | None = None,
        ) -> AgentAction:
            return await super().reason(messages, tools)

    llm = CapturingLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm)

    await agent.run({"urls": ["http://example.com"]})
    await state.close()

    assert llm.tool_schemas_received, "LLM reason() was never called with tool schemas"
    first_call_schemas = llm.tool_schemas_received[0]
    schema_names = [s["name"] for s in first_call_schemas]

    assert "execute_capability" in schema_names
    for bare_name in ("katana", "ffuf", "arjun", "nuclei", "nikto"):
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
        to_agent="scan",
        engagement_id=eid,
        content={"query": "Also scan https://api.example.com specifically."},
    )
    agent.receive_message(query)

    result = await agent.run({"urls": ["http://example.com"]})
    await state.close()

    assert result["status"] == "complete"


async def test_mid_run_query_injected_into_llm_messages(tmp_path: Path) -> None:
    """A QUERY received mid-run is injected into the LLM conversation."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    query_text = "Please also fuzz port 8080."
    query = AgentMessage.query(
        from_agent=ORCHESTRATOR,
        to_agent="scan",
        engagement_id=eid,
        content={"query": query_text},
    )
    agent.receive_message(query)

    await agent.run({"urls": ["http://example.com"]})
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
            to_agent="scan",
            engagement_id=eid,
            content={"query": f"Scan query {i}."},
        )
        agent.receive_message(query)

    result = await agent.run({"urls": ["http://example.com"]})
    await state.close()

    assert result["status"] == "complete"
    injected = [
        m for m in agent.messages if m.role == "user" and "Scan query" in (m.content or "")
    ]
    assert len(injected) == 3


# ---------------------------------------------------------------------------
# Test: URL derivation from host data
# ---------------------------------------------------------------------------


async def test_urls_derived_from_host_services(tmp_path: Path) -> None:
    """When no URLs provided, run() derives them from host service data."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    hosts = [
        {
            "ip": "1.2.3.4",
            "hostnames": ["example.com"],
            "services": [
                {"port": 80, "name": "http"},
                {"port": 443, "name": "https"},
            ],
        }
    ]

    result = await agent.run({"hosts": hosts})
    await state.close()

    # Should complete successfully — URL derivation is internal
    assert result["status"] == "complete"


# ---------------------------------------------------------------------------
# Test: RESULT message sent to Orchestrator bus via lifecycle manager
# ---------------------------------------------------------------------------


async def test_lifecycle_sends_result_to_orchestrator_bus(tmp_path: Path) -> None:
    """After ScanAgent finishes, the lifecycle manager sends RESULT to Orchestrator."""
    state = StateStore(tmp_path / "lifecycle.db")
    await state.connect()
    eid = await state.create_engagement("lifecycle-scan-test", SCOPE.model_dump())

    bus = MessageBus(state=state)
    mock_resolver = _make_mock_resolver()

    with patch("clinkz.agents.scan.ToolResolver", return_value=mock_resolver):
        mgr = AgentLifecycleManager(
            bus=bus,
            llm=MockScanLLM(),
            scope=SCOPE,
            state=state,
            engagement_id=eid,
        )

        task_msg = AgentMessage.task(
            from_agent=ORCHESTRATOR,
            to_agent="scan",
            engagement_id=eid,
            content={"urls": ["http://example.com"]},
        )

        await mgr.spin_up("scan", task_msg)

        result_msg = await asyncio.wait_for(
            bus.receive(ORCHESTRATOR), timeout=15.0
        )

    assert result_msg.message_type == MessageType.RESULT, (
        f"Expected RESULT message, got {result_msg.message_type}"
    )
    assert result_msg.from_agent == "scan"
    assert result_msg.to_agent == ORCHESTRATOR
    assert "endpoints" in result_msg.content
    assert "summary" in result_msg.content

    await state.close()
