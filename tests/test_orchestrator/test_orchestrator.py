"""Unit tests for OrchestratorAgent.

Tests use:
- A mock LLM (_SequenceLLM) that returns predetermined action sequences
- A patched AgentLifecycleManager so no real agents are started
- A real in-memory StateStore (aiosqlite :memory:) so persistence is real

Key pattern
-----------
Each ``spin_up`` side-effect immediately:
1. Puts a RESULT (or QUERY) message on the bus for the orchestrator.
2. Removes the agent from ``running_agents``.

This ensures the orchestrator's next poll finds a pending message and calls the
LLM again — avoiding the hanging that would occur if no messages arrive and
agents appear to still be running.

Coverage:
- Orchestrator starts engagement, calls LLM, spins up Recon agent
- When Recon sends results, Orchestrator spins up Scan agent
- Exploit agent query triggers Orchestrator to re-spin Recon and route result back
- complete_engagement action exits the loop
- Messages (route_message) are persisted in the state store
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent, _trim_history
from clinkz.state import StateStore

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="Test Engagement",
    targets=[ScopeEntry(value="10.10.10.1", type=ScopeType.IP)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tc(name: str, **kwargs: Any) -> ToolCall:
    """Shorthand: create a ToolCall with the given name and kwargs as arguments."""
    return ToolCall(id=f"call-{name}-{id(kwargs)}", name=name, arguments=kwargs)


class _SequenceLLM(LLMClient):
    """LLM that returns a predetermined sequence of AgentActions.

    When the sequence is exhausted it returns ``complete_engagement`` to
    prevent the loop from hanging in tests.
    """

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
                tool_call=_tc("complete_engagement", summary="Sequence complete."),
            )

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _result_msg(from_agent: str, engagement_id: str, content: dict) -> AgentMessage:
    """Create a RESULT message from a phase agent to the Orchestrator."""
    return AgentMessage.result(
        from_agent=from_agent,
        to_agent=ORCHESTRATOR,
        engagement_id=engagement_id,
        content=content,
    )


async def _run_orchestrator(
    llm: LLMClient,
    scope: EngagementScope = SCOPE,
    on_spin_up: Callable | None = None,
) -> tuple[dict, MagicMock]:
    """Run OrchestratorAgent with a mocked lifecycle.

    Args:
        llm: Mock LLM to use.
        scope: Engagement scope.
        on_spin_up: Optional async callable(agent_type, task_msg, bus,
                    running_agents) called after each spin_up.  Use it to
                    inject bus messages and update running_agents.

    Returns:
        (result_dict, mock_lifecycle)
    """
    running_agents: list[str] = []
    bus_holder: list[MessageBus] = []

    mock_lifecycle = MagicMock()
    mock_lifecycle.get_status.return_value = {}
    mock_lifecycle.get_running_agents.side_effect = lambda: list(running_agents)
    mock_lifecycle.shut_down = AsyncMock()

    async def _spin_up(agent_type: str, task_msg: AgentMessage) -> MagicMock:
        running_agents.append(agent_type)
        if on_spin_up is not None and bus_holder:
            await on_spin_up(agent_type, task_msg, bus_holder[0], running_agents)
        return MagicMock()

    mock_lifecycle.spin_up = AsyncMock(side_effect=_spin_up)

    def _lifecycle_constructor(**kwargs: Any) -> MagicMock:
        # Capture the real bus created inside orchestrator.run()
        if "bus" in kwargs:
            bus_holder.append(kwargs["bus"])
        running_agents.clear()
        return mock_lifecycle

    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    with patch(
        "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
        side_effect=_lifecycle_constructor,
    ):
        result = await orchestrator.run(scope)

    return result, mock_lifecycle


# ---------------------------------------------------------------------------
# Test 1: Initial kickoff spins up Recon agent
# ---------------------------------------------------------------------------


async def test_initial_kickoff_spins_up_recon() -> None:
    """Orchestrator's first LLM call should spin up Recon with a task message."""

    async def on_spin_up(agent_type, task_msg, bus, running_agents):
        # Simulate agent completing instantly: inject result + remove from running
        await bus.send(
            _result_msg(agent_type, task_msg.engagement_id, {"done": True})
        )
        running_agents.remove(agent_type)

    llm = _SequenceLLM(
        [
            AgentAction(
                thought="I'll start with reconnaissance.",
                tool_call=_tc(
                    "spin_up_agent",
                    agent_type="recon",
                    task="Enumerate 10.10.10.1: open ports, services, tech stack.",
                ),
            ),
            # Recon result arrives → complete
            AgentAction(
                thought="Recon complete. Wrapping up.",
                tool_call=_tc("complete_engagement", summary="Recon done."),
            ),
        ]
    )

    result, mock_lifecycle = await _run_orchestrator(llm, on_spin_up=on_spin_up)

    # spin_up was called with "recon" as the first argument
    assert mock_lifecycle.spin_up.call_count >= 1
    call = mock_lifecycle.spin_up.call_args_list[0]
    agent_type_arg = call[0][0]  # first positional arg
    assert agent_type_arg == "recon"

    # The task message is the second positional arg
    task_msg: AgentMessage = call[0][1]
    assert isinstance(task_msg, AgentMessage)
    assert task_msg.message_type == MessageType.TASK
    assert task_msg.from_agent == ORCHESTRATOR
    assert task_msg.to_agent == "recon"
    assert "task" in task_msg.content

    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 2: Recon results trigger Scan agent spin-up
# ---------------------------------------------------------------------------


async def test_recon_result_triggers_scan_agent() -> None:
    """When Recon sends results, Orchestrator should spin up the Scan agent."""

    async def on_spin_up(agent_type, task_msg, bus, running_agents):
        # Every agent immediately "completes" and sends a result
        await bus.send(
            _result_msg(
                agent_type,
                task_msg.engagement_id,
                {"phase": agent_type, "result": "phase complete"},
            )
        )
        running_agents.remove(agent_type)

    llm = _SequenceLLM(
        [
            # Step 1: Spin up recon
            AgentAction(
                thought="Start with recon.",
                tool_call=_tc(
                    "spin_up_agent",
                    agent_type="recon",
                    task="Full recon of 10.10.10.1",
                ),
            ),
            # Step 2: Recon result received → spin up scan
            AgentAction(
                thought="Recon found services. Starting scan.",
                tool_call=_tc(
                    "spin_up_agent",
                    agent_type="scan",
                    task="Crawl http://10.10.10.1 — map endpoints.",
                ),
            ),
            # Step 3: Scan result received → complete
            AgentAction(
                thought="Scan complete. Engagement done.",
                tool_call=_tc(
                    "complete_engagement",
                    summary="Recon and scan phases complete.",
                ),
            ),
        ]
    )

    result, mock_lifecycle = await _run_orchestrator(llm, on_spin_up=on_spin_up)

    spun_types = [call[0][0] for call in mock_lifecycle.spin_up.call_args_list]
    assert "recon" in spun_types, f"Expected 'recon' in {spun_types}"
    assert "scan" in spun_types, f"Expected 'scan' in {spun_types}"
    # recon must come before scan
    assert spun_types.index("recon") < spun_types.index("scan")

    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 3: Exploit query triggers Recon re-spin and result routing
# ---------------------------------------------------------------------------


async def test_exploit_query_triggers_recon_and_routing() -> None:
    """When Exploit agent sends a query, Orchestrator re-spins Recon
    and routes the result back to Exploit."""
    recon_spins = 0

    async def on_spin_up(agent_type, task_msg, bus, running_agents):
        nonlocal recon_spins
        if agent_type == "exploit":
            # Exploit sends a QUERY to orchestrator asking for more recon
            await bus.send(
                AgentMessage.query(
                    from_agent="exploit",
                    to_agent=ORCHESTRATOR,
                    engagement_id=task_msg.engagement_id,
                    content={"query": "Need recon on api.target.com before I can continue."},
                )
            )
            running_agents.remove(agent_type)  # exploit "waiting"
        elif agent_type == "recon":
            recon_spins += 1
            # Second recon run returns new intel
            await bus.send(
                _result_msg(
                    "recon",
                    task_msg.engagement_id,
                    {"new_host": "api.target.com", "ports": [443]},
                )
            )
            running_agents.remove(agent_type)

    llm = _SequenceLLM(
        [
            # Step 1: Start exploit
            AgentAction(
                thought="Go straight to exploit.",
                tool_call=_tc(
                    "spin_up_agent",
                    agent_type="exploit",
                    task="Test 10.10.10.1",
                ),
            ),
            # Step 2: Exploit query received → re-spin recon
            AgentAction(
                thought="Exploit needs more recon. I'll spin up recon again.",
                tool_call=_tc(
                    "spin_up_agent",
                    agent_type="recon",
                    task="Enumerate api.target.com discovered by exploit agent.",
                ),
            ),
            # Step 3: Recon result received → route to exploit
            AgentAction(
                thought="Recon has new intel. Routing to exploit.",
                tool_call=_tc(
                    "route_message",
                    to_agent="exploit",
                    content={"recon_result": {"host": "api.target.com", "port": 443}},
                ),
            ),
            # Step 4: complete
            AgentAction(
                thought="Done routing. Completing engagement.",
                tool_call=_tc(
                    "complete_engagement",
                    summary="Exploit queried recon and received targeted intel.",
                ),
            ),
        ]
    )

    result, mock_lifecycle = await _run_orchestrator(llm, on_spin_up=on_spin_up)

    spun_types = [call[0][0] for call in mock_lifecycle.spin_up.call_args_list]
    assert "exploit" in spun_types, f"exploit not in {spun_types}"
    assert "recon" in spun_types, f"recon not in {spun_types}"
    assert recon_spins >= 1  # recon was activated at least once (re-spin)

    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 4: complete_engagement exits the loop immediately
# ---------------------------------------------------------------------------


async def test_complete_engagement_exits_loop() -> None:
    """complete_engagement action must cause _main_loop to exit cleanly."""
    llm = _SequenceLLM(
        [
            AgentAction(
                thought="Nothing to do — completing immediately.",
                tool_call=_tc(
                    "complete_engagement",
                    summary="Immediate completion for test.",
                ),
            ),
        ]
    )

    result, _ = await _run_orchestrator(llm)

    assert result["status"] == "completed"
    assert "Immediate completion for test." in result["summary"]


# ---------------------------------------------------------------------------
# Test 5: Messages are persisted in the state store
# ---------------------------------------------------------------------------


async def test_messages_persisted_in_state_store() -> None:
    """route_message must result in a persisted message via the state store.

    We mock StateStore so we can intercept save_message calls directly,
    verifying the bus writes every message to persistence.
    """
    # Build a real mock state that tracks save_message calls
    mock_state = MagicMock()
    mock_state.create_engagement = AsyncMock(return_value="test-eid-persist")
    mock_state.update_engagement_status = AsyncMock()
    mock_state.get_findings = AsyncMock(return_value=[])
    mock_state.save_message = AsyncMock()
    mock_state.__aenter__ = AsyncMock(return_value=mock_state)
    mock_state.__aexit__ = AsyncMock(return_value=False)

    mock_lifecycle = MagicMock()
    mock_lifecycle.get_status.return_value = {}
    mock_lifecycle.get_running_agents.return_value = []
    mock_lifecycle.spin_up = AsyncMock(return_value=MagicMock())
    mock_lifecycle.shut_down = AsyncMock()

    llm = _SequenceLLM(
        [
            # Send a route_message to recon — this should be persisted
            AgentAction(
                thought="Routing task to recon.",
                tool_call=_tc(
                    "route_message",
                    to_agent="recon",
                    content={"task": "enumerate targets for persistence test"},
                ),
            ),
            AgentAction(
                thought="Done.",
                tool_call=_tc("complete_engagement", summary="Persistence verified."),
            ),
        ]
    )

    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    with patch(
        "clinkz.orchestrator.orchestrator.StateStore",
        return_value=mock_state,
    ):
        with patch(
            "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
            return_value=mock_lifecycle,
        ):
            result = await orchestrator.run(SCOPE)

    # save_message must have been called at least once (the route_message)
    assert mock_state.save_message.call_count >= 1, (
        "Expected save_message to be called at least once (for the routed message). "
        f"Actual calls: {mock_state.save_message.call_count}"
    )

    # Verify the routed message was orchestrator → recon
    saved_msgs = [call.args[0] for call in mock_state.save_message.call_args_list]
    orch_to_recon = [
        m for m in saved_msgs
        if m.from_agent == ORCHESTRATOR and m.to_agent == "recon"
    ]
    assert len(orch_to_recon) >= 1, (
        f"Expected at least 1 orchestrator→recon message, got: "
        f"{[(m.from_agent, m.to_agent) for m in saved_msgs]}"
    )

    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test: _trim_history helper
# ---------------------------------------------------------------------------


def test_trim_history_keeps_most_recent() -> None:
    """_trim_history should retain the most recent messages up to max_turns."""
    history = [LLMMessage(role="user", content=f"msg {i}") for i in range(10)]
    trimmed = _trim_history(history, max_turns=3)
    assert len(trimmed) == 3
    assert trimmed[-1].content == "msg 9"
    assert trimmed[0].content == "msg 7"


def test_trim_history_no_op_when_short() -> None:
    """_trim_history should return the original list when within max_turns."""
    history = [LLMMessage(role="user", content=f"msg {i}") for i in range(5)]
    trimmed = _trim_history(history, max_turns=10)
    assert trimmed is history
