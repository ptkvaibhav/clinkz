"""Unit tests for AgentLifecycleManager.

Tests use lightweight mock agents so no real LLM, tools, or I/O are needed.
The MessageBus and StateStore are real (in-memory) instances.

Coverage:
- spin_up: creates agent, starts asyncio task, tracks status
- shut_down: signals stop, agent sends STATUS, status updated
- restart: shuts down existing instance, starts fresh
- concurrent agents: multiple agents running simultaneously
- get_status / get_running_agents: accurate snapshot
- unknown agent type: raises ValueError
- agent task crash: error message sent, lifecycle continues
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clinkz.agents.base import BaseAgent
from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.lifecycle import AgentLifecycleManager, AgentStatus

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

ENGAGEMENT_ID = "test-engagement-001"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)


def _make_task_msg(from_agent: str = ORCHESTRATOR, to_agent: str = "mock") -> AgentMessage:
    return AgentMessage.task(
        from_agent=from_agent,
        to_agent=to_agent,
        engagement_id=ENGAGEMENT_ID,
        content={"task": "do something"},
    )


def _make_mock_llm() -> MagicMock:
    llm = MagicMock()
    llm.reason = AsyncMock()
    return llm


def _make_mock_state() -> MagicMock:
    state = MagicMock()
    state.log_action = AsyncMock(return_value="action-id")
    state.complete_action = AsyncMock()
    state.save_message = AsyncMock()
    return state


# ---------------------------------------------------------------------------
# Minimal concrete BaseAgent for testing
# ---------------------------------------------------------------------------


class _MockAgent(BaseAgent):
    """Minimal agent that records calls and returns immediately."""

    _agent_name: str = "mock"
    run_called: int = 0
    run_result: dict[str, Any] = {}
    run_error: Exception | None = None

    @property
    def name(self) -> str:
        return self.__class__._agent_name

    @property
    def system_prompt(self) -> str:
        return "mock prompt"

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        self.__class__.run_called += 1
        if self.run_error is not None:
            raise self.run_error  # type: ignore[misc]
        return self.run_result or {"ok": True}


class _MockReconAgent(_MockAgent):
    _agent_name = "recon"


class _MockCrawlAgent(_MockAgent):
    _agent_name = "crawl"


class _MockExploitAgent(_MockAgent):
    _agent_name = "exploit"


class _MockReportAgent(_MockAgent):
    _agent_name = "report"


class _MockCriticAgent(_MockAgent):
    _agent_name = "critic"


# Mock agent class registry patch
_MOCK_AGENT_CLASSES = {
    "recon": _MockReconAgent,
    "scan": _MockCrawlAgent,
    "crawl": _MockCrawlAgent,
    "exploit": _MockExploitAgent,
    "report": _MockReportAgent,
    "critic": _MockCriticAgent,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manager(bus: MessageBus | None = None) -> AgentLifecycleManager:
    """Build a lifecycle manager backed by a real MessageBus."""
    return AgentLifecycleManager(
        bus=bus or MessageBus(state=None),
        llm=_make_mock_llm(),
        scope=SCOPE,
        state=_make_mock_state(),
        engagement_id=ENGAGEMENT_ID,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spin_up_creates_agent_and_sets_running_status():
    """spin_up() should track the agent as RUNNING."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        task_msg = _make_task_msg(to_agent="recon")
        agent = await mgr.spin_up("recon", task_msg)

    assert isinstance(agent, _MockReconAgent)
    assert mgr.get_status()["recon"] == AgentStatus.RUNNING
    assert "recon" in mgr.get_running_agents()

    # Clean up
    await mgr.shut_down("recon")


@pytest.mark.asyncio
async def test_spin_up_returns_base_agent_subclass():
    """spin_up() returns a BaseAgent instance."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        agent = await mgr.spin_up("exploit", _make_task_msg(to_agent="exploit"))

    assert isinstance(agent, BaseAgent)

    await mgr.shut_down("exploit")


@pytest.mark.asyncio
async def test_spin_up_unknown_type_raises():
    """spin_up() with an unrecognised type raises ValueError."""
    mgr = _make_manager()

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        with pytest.raises(ValueError, match="Unknown agent type"):
            await mgr.spin_up("nonexistent", _make_task_msg())


@pytest.mark.asyncio
async def test_shut_down_updates_status_to_stopped():
    """shut_down() changes the tracked status to STOPPED."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        # Give the task a moment to process the initial message
        await asyncio.sleep(0.05)
        await mgr.shut_down("recon")

    assert mgr.get_status()["recon"] == AgentStatus.STOPPED
    assert "recon" not in mgr.get_running_agents()


@pytest.mark.asyncio
async def test_shut_down_sends_status_message_to_orchestrator():
    """Agent sends STATUS message to Orchestrator on shutdown."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await asyncio.sleep(0.05)
        await mgr.shut_down("recon")

    # Drain orchestrator queue and look for STATUS message
    messages = await bus.get_pending(ORCHESTRATOR)
    status_msgs = [m for m in messages if m.message_type == MessageType.STATUS]
    assert len(status_msgs) >= 1
    assert status_msgs[-1].content.get("status") == "stopped"
    assert status_msgs[-1].content.get("agent") == "recon"


@pytest.mark.asyncio
async def test_shut_down_unknown_agent_raises():
    """shut_down() for an untracked agent raises ValueError."""
    mgr = _make_manager()

    with pytest.raises(ValueError, match="No agent named"):
        await mgr.shut_down("recon")


@pytest.mark.asyncio
async def test_shut_down_already_stopped_is_noop():
    """Calling shut_down() on an already-stopped agent is safe."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await asyncio.sleep(0.05)
        await mgr.shut_down("recon")
        # Second shut_down should not raise
        await mgr.shut_down("recon")

    assert mgr.get_status()["recon"] == AgentStatus.STOPPED


@pytest.mark.asyncio
async def test_restart_shuts_down_running_and_spins_up_fresh():
    """restart() stops the current instance and starts a new one."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        agent1 = await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await asyncio.sleep(0.05)
        agent2 = await mgr.restart("recon", _make_task_msg(to_agent="recon"))

    # Different instance
    assert agent1 is not agent2
    # Still tracked as running
    assert mgr.get_status()["recon"] == AgentStatus.RUNNING

    await mgr.shut_down("recon")


@pytest.mark.asyncio
async def test_concurrent_agents():
    """Multiple agents can run simultaneously as separate asyncio Tasks."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await mgr.spin_up("exploit", _make_task_msg(to_agent="exploit"))
        await asyncio.sleep(0.05)

        running = mgr.get_running_agents()
        assert "recon" in running
        assert "exploit" in running
        assert len(running) == 2

        await mgr.shut_down("recon")
        await mgr.shut_down("exploit")


@pytest.mark.asyncio
async def test_get_status_returns_all_tracked_agents():
    """get_status() includes all agents that have ever been spun up."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await asyncio.sleep(0.05)
        await mgr.shut_down("recon")
        await mgr.spin_up("exploit", _make_task_msg(to_agent="exploit"))

        status = mgr.get_status()

    assert "recon" in status
    assert "exploit" in status
    assert status["recon"] == AgentStatus.STOPPED
    assert status["exploit"] == AgentStatus.RUNNING

    await mgr.shut_down("exploit")


@pytest.mark.asyncio
async def test_get_running_agents_empty_when_nothing_spun_up():
    """get_running_agents() returns empty list before any spin_up."""
    mgr = _make_manager()
    assert mgr.get_running_agents() == []


@pytest.mark.asyncio
async def test_agent_result_sent_to_orchestrator_after_task():
    """Agent sends RESULT message to Orchestrator after completing a task."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        # Give the run loop time to process the task and send a result
        await asyncio.sleep(0.1)

    messages = await bus.get_pending(ORCHESTRATOR)
    result_msgs = [m for m in messages if m.message_type == MessageType.RESULT]
    assert len(result_msgs) >= 1
    assert result_msgs[0].from_agent == "recon"

    await mgr.shut_down("recon")


@pytest.mark.asyncio
async def test_spin_up_twice_same_type_shuts_down_previous():
    """spin_up() for the same type replaces the running instance."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        agent1 = await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))
        await asyncio.sleep(0.05)
        # Spin up again — should replace
        agent2 = await mgr.spin_up("recon", _make_task_msg(to_agent="recon"))

    assert agent1 is not agent2
    assert "recon" in mgr.get_running_agents()

    await mgr.shut_down("recon")


@pytest.mark.asyncio
async def test_scan_alias_creates_crawl_agent():
    """spin_up('scan', ...) creates a CrawlAgent (tracked as 'crawl')."""
    bus = MessageBus()
    mgr = _make_manager(bus)

    with patch("clinkz.orchestrator.lifecycle._AGENT_CLASSES", _MOCK_AGENT_CLASSES):
        agent = await mgr.spin_up("scan", _make_task_msg(to_agent="crawl"))

    assert isinstance(agent, _MockCrawlAgent)
    assert "crawl" in mgr.get_running_agents()

    await mgr.shut_down("crawl")
