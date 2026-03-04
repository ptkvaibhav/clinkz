"""Integration test: BaseAgent ReAct loop wired to NmapTool.

Verifies the full loop end-to-end:
  Observe → Reason (mock LLM) → Act (mock nmap returns fixture XML) →
  Reflect → Reason (mock LLM returns done) → final_answer

No real network calls, no OpenAI API key, no real nmap binary required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clinkz.agents.base import BaseAgent
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.nmap import NmapTool

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

FIXTURE_XML = (
    Path(__file__).parent.parent / "fixtures" / "nmap_sample_output.xml"
).read_text(encoding="utf-8")

SCOPE = EngagementScope(
    name="localhost-test",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)


# ---------------------------------------------------------------------------
# Mock LLM — deterministic: call 1 → nmap tool_call; call 2+ → final_answer
# ---------------------------------------------------------------------------


class MockLLMClient(LLMClient):
    """Stub LLM: first reason() returns an nmap tool_call; second returns done."""

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
                thought="I will scan 127.0.0.1 with nmap to identify open ports.",
                tool_call=ToolCall(
                    id="call_test_001",
                    name="nmap",
                    arguments={"target": "127.0.0.1", "ports": "22,80,443,8080"},
                ),
            )
        return AgentAction(
            thought="Scan complete. Found OpenSSH, nginx, and Apache Tomcat.",
            final_answer="Scan complete. Found OpenSSH, nginx, and Apache Tomcat.",
        )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Mock NmapTool — returns fixture XML; no subprocess spawned
# ---------------------------------------------------------------------------


class MockNmapTool(NmapTool):
    """NmapTool that returns the saved fixture XML instead of running nmap."""

    async def execute(self, args: dict[str, Any]) -> str:
        return FIXTURE_XML


# ---------------------------------------------------------------------------
# Minimal concrete agent for testing
# ---------------------------------------------------------------------------


class MinimalReconAgent(BaseAgent):
    """Minimal BaseAgent subclass — drives _react_loop from run()."""

    @property
    def name(self) -> str:
        return "recon"

    @property
    def system_prompt(self) -> str:
        return (
            "You are a recon agent. Scan the target and report what services are running. "
            "When you have the results, respond with done."
        )

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        target = input_data.get("target", "127.0.0.1")
        observation = f"Scan the following target and report all open services: {target}"
        final_answer = await self._react_loop(observation)
        return {"final_answer": final_answer}


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _run_agent(db_path: Path) -> tuple[dict[str, Any], str, StateStore]:
    """Spin up a fresh engagement, run the agent, return (result, eid, state)."""
    state = StateStore(db_path)
    await state.connect()
    engagement_id = await state.create_engagement("localhost-test", SCOPE.model_dump())
    agent = MinimalReconAgent(
        llm=MockLLMClient(),
        tools=[MockNmapTool(scope=SCOPE)],
        scope=SCOPE,
        state=state,
        engagement_id=engagement_id,
    )
    result = await agent.run({"target": "127.0.0.1"})
    return result, engagement_id, state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_agent_returns_final_answer(tmp_path: Path) -> None:
    """Agent loop exits with a non-empty final answer."""
    result, _, state = await _run_agent(tmp_path / "test.db")
    await state.close()
    assert "final_answer" in result
    assert result["final_answer"]


async def test_nmap_action_logged_as_completed(tmp_path: Path) -> None:
    """The nmap tool call is recorded in the state store with status=completed."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    nmap_actions = [a for a in actions if a["tool"] == "nmap"]
    assert len(nmap_actions) == 1, f"Expected 1 nmap action, got {len(nmap_actions)}"
    assert nmap_actions[0]["status"] == "completed"
    assert nmap_actions[0]["phase"] == "recon"


async def test_nmap_output_stored_in_state(tmp_path: Path) -> None:
    """The parsed NmapOutput is serialised into the actions.output_json column."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    action = next(a for a in actions if a["tool"] == "nmap")
    output = json.loads(action["output_json"])

    assert output["success"] is True
    assert output["tool_name"] == "nmap"


async def test_host_discovered_from_fixture(tmp_path: Path) -> None:
    """Exactly one host (192.168.1.100) is parsed from the fixture XML."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    output = json.loads(next(a for a in actions if a["tool"] == "nmap")["output_json"])
    hosts = output["hosts"]

    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.1.100"
    assert "webserver.example.com" in hosts[0]["hostnames"]


async def test_four_open_ports_discovered(tmp_path: Path) -> None:
    """Closed port 3306 is excluded; exactly ports 22/80/443/8080 are reported."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    output = json.loads(next(a for a in actions if a["tool"] == "nmap")["output_json"])

    assert set(output["open_ports"]) == {22, 80, 443, 8080}
    assert len(output["hosts"][0]["services"]) == 4


async def test_service_names_and_versions(tmp_path: Path) -> None:
    """Each service has the expected product name and version string."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    services = {
        s["port"]: s
        for s in json.loads(
            next(a for a in actions if a["tool"] == "nmap")["output_json"]
        )["hosts"][0]["services"]
    }

    assert services[22]["product"] == "OpenSSH"
    assert services[22]["version"].startswith("8.9")
    assert services[80]["product"] == "nginx"
    assert services[80]["version"] == "1.24.0"
    assert services[443]["product"] == "nginx"
    assert services[8080]["product"] == "Apache Tomcat"
    assert services[8080]["version"] == "9.0.70"


async def test_os_detection_stored(tmp_path: Path) -> None:
    """OS detection result from the highest-accuracy osmatch is stored."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    host = json.loads(
        next(a for a in actions if a["tool"] == "nmap")["output_json"]
    )["hosts"][0]

    assert host["os"] == "Linux"
    assert "Linux 5" in host["os_version"]


async def test_nse_scripts_stored(tmp_path: Path) -> None:
    """NSE script outputs are captured and stored in each Service's scripts dict."""
    _, engagement_id, state = await _run_agent(tmp_path / "test.db")
    actions = await state.get_actions(engagement_id)
    await state.close()

    services = {
        s["port"]: s
        for s in json.loads(
            next(a for a in actions if a["tool"] == "nmap")["output_json"]
        )["hosts"][0]["services"]
    }

    assert "ssh-hostkey" in services[22]["scripts"]
    assert "ECDSA" in services[22]["scripts"]["ssh-hostkey"]
    assert "ssl-cert" in services[443]["scripts"]
    assert "webserver.example.com" in services[443]["scripts"]["ssl-cert"]
    assert "http-auth-finder" in services[8080]["scripts"]
    assert "Tomcat Manager" in services[8080]["scripts"]["http-auth-finder"]


async def test_llm_received_nmap_schema(tmp_path: Path) -> None:
    """LLM's first reason() call includes the nmap tool schema in OpenAI function format."""
    captured: list[list[dict[str, Any]]] = []

    class CapturingMockLLM(MockLLMClient):
        async def reason(
            self,
            messages: list[LLMMessage],
            tools: list[dict[str, Any]] | None = None,
        ) -> AgentAction:
            if tools is not None:
                captured.append(list(tools))
            return await super().reason(messages, tools)

    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("schema-test", SCOPE.model_dump())
        agent = MinimalReconAgent(
            llm=CapturingMockLLM(),
            tools=[MockNmapTool(scope=SCOPE)],
            scope=SCOPE,
            state=state,
            engagement_id=eid,
        )
        await agent.run({"target": "127.0.0.1"})

    assert captured, "LLM was never called with tool schemas"
    schema = captured[0][0]  # first call, first tool
    assert schema["name"] == "nmap"
    assert "target" in schema["parameters"]["required"]
    assert schema["parameters"]["type"] == "object"


async def test_out_of_scope_target_logs_failed_action(tmp_path: Path) -> None:
    """When the LLM requests an out-of-scope target, the action is stored as failed."""

    class OutOfScopeMockLLM(LLMClient):
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
                    thought="Trying out-of-scope target.",
                    tool_call=ToolCall(
                        id="call_oos_001",
                        name="nmap",
                        arguments={"target": "8.8.8.8"},  # out of scope!
                    ),
                )
            return AgentAction(
                thought="Got an error response.",
                final_answer="Could not scan — target is out of scope.",
            )

        async def research(self, query: str) -> str:
            return ""

        async def generate_text(self, prompt: str) -> str:
            return ""

    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("scope-test", SCOPE.model_dump())
        agent = MinimalReconAgent(
            llm=OutOfScopeMockLLM(),
            tools=[MockNmapTool(scope=SCOPE)],
            scope=SCOPE,
            state=state,
            engagement_id=eid,
        )
        result = await agent.run({"target": "127.0.0.1"})

        actions = await state.get_actions(eid)

    # Agent returned a final answer (error was fed back to LLM gracefully)
    assert result["final_answer"]

    # The failed action is in the state store
    failed = [a for a in actions if a["status"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["tool"] == "nmap"
