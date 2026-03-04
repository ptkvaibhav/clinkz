"""Unit tests for MessageBus.

Tests cover:
- Agent → Orchestrator routing
- Orchestrator → Agent routing
- Direct agent-to-agent rejection
- get_pending (non-blocking drain)
- broadcast to all agents
- Message persistence in the state store
- Full two-hop routing flow (agent → orch → agent)
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import EXPLOIT, KNOWN_AGENTS, ORCHESTRATOR, RECON, SCAN
from clinkz.state import StateStore

EID = "eng-test-0001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _task(from_agent: str, to_agent: str, content: dict | None = None) -> AgentMessage:
    return AgentMessage.task(
        from_agent=from_agent,
        to_agent=to_agent,
        engagement_id=EID,
        content=content or {"task": "do something"},
    )


def _result(from_agent: str, to_agent: str, parent_id: str | None = None) -> AgentMessage:
    return AgentMessage.result(
        from_agent=from_agent,
        to_agent=to_agent,
        engagement_id=EID,
        content={"result": "done"},
        parent_message_id=parent_id,
    )


# ---------------------------------------------------------------------------
# Basic routing
# ---------------------------------------------------------------------------


async def test_agent_sends_to_orchestrator() -> None:
    bus = MessageBus()
    msg = _task(RECON, ORCHESTRATOR)
    await bus.send(msg)
    received = await asyncio.wait_for(bus.receive(ORCHESTRATOR), timeout=1)
    assert received.id == msg.id
    assert received.from_agent == RECON


async def test_orchestrator_sends_to_agent() -> None:
    bus = MessageBus()
    msg = _task(ORCHESTRATOR, RECON)
    await bus.send(msg)
    received = await asyncio.wait_for(bus.receive(RECON), timeout=1)
    assert received.id == msg.id
    assert received.to_agent == RECON


async def test_multiple_agents_send_to_orchestrator() -> None:
    bus = MessageBus()
    m1 = _task(RECON, ORCHESTRATOR, {"task": "recon done"})
    m2 = _task(SCAN, ORCHESTRATOR, {"task": "scan done"})
    await bus.send(m1)
    await bus.send(m2)

    r1 = await asyncio.wait_for(bus.receive(ORCHESTRATOR), timeout=1)
    r2 = await asyncio.wait_for(bus.receive(ORCHESTRATOR), timeout=1)
    received_ids = {r1.id, r2.id}
    assert m1.id in received_ids
    assert m2.id in received_ids


async def test_messages_delivered_to_correct_queue() -> None:
    """Orchestrator routes to recon; exploit queue stays empty."""
    bus = MessageBus()
    await bus.send(_task(ORCHESTRATOR, RECON))
    assert bus.queue_size(RECON) == 1
    assert bus.queue_size(EXPLOIT) == 0


# ---------------------------------------------------------------------------
# Two-hop routing (agent → orchestrator → agent)
# ---------------------------------------------------------------------------


async def test_full_two_hop_routing() -> None:
    """Recon sends result to Orchestrator; Orchestrator tasks Exploit."""
    bus = MessageBus()

    # Step 1: Recon reports to Orchestrator
    recon_result = _result(RECON, ORCHESTRATOR)
    await bus.send(recon_result)

    # Step 2: Orchestrator reads and decides to task Exploit
    orch_received = await asyncio.wait_for(bus.receive(ORCHESTRATOR), timeout=1)
    assert orch_received.from_agent == RECON

    exploit_task = AgentMessage.task(
        from_agent=ORCHESTRATOR,
        to_agent=EXPLOIT,
        engagement_id=EID,
        content={"task": "exploit discovered hosts"},
        parent_message_id=orch_received.id,
    )
    await bus.send(exploit_task)

    # Step 3: Exploit reads its task
    exploit_received = await asyncio.wait_for(bus.receive(EXPLOIT), timeout=1)
    assert exploit_received.from_agent == ORCHESTRATOR
    assert exploit_received.parent_message_id == orch_received.id


# ---------------------------------------------------------------------------
# Direct agent-to-agent rejection
# ---------------------------------------------------------------------------


async def test_direct_agent_to_agent_raises() -> None:
    bus = MessageBus()
    with pytest.raises(ValueError, match="must go through the Orchestrator"):
        await bus.send(_task(RECON, EXPLOIT))


async def test_direct_agent_to_scan_raises() -> None:
    bus = MessageBus()
    with pytest.raises(ValueError):
        await bus.send(_task(EXPLOIT, SCAN))


async def test_orchestrator_to_orchestrator_allowed() -> None:
    """Orchestrator may send to itself (e.g., deferred self-tasks)."""
    bus = MessageBus()
    msg = _task(ORCHESTRATOR, ORCHESTRATOR)
    await bus.send(msg)  # must not raise
    received = await asyncio.wait_for(bus.receive(ORCHESTRATOR), timeout=1)
    assert received.id == msg.id


# ---------------------------------------------------------------------------
# get_pending
# ---------------------------------------------------------------------------


async def test_get_pending_returns_queued_messages() -> None:
    bus = MessageBus()
    m1 = _task(ORCHESTRATOR, RECON, {"task": "first"})
    m2 = _task(ORCHESTRATOR, RECON, {"task": "second"})
    await bus.send(m1)
    await bus.send(m2)

    pending = await bus.get_pending(RECON)
    assert len(pending) == 2
    ids = {p.id for p in pending}
    assert m1.id in ids and m2.id in ids


async def test_get_pending_empty_queue() -> None:
    bus = MessageBus()
    pending = await bus.get_pending(RECON)
    assert pending == []


async def test_get_pending_drains_queue() -> None:
    bus = MessageBus()
    await bus.send(_task(ORCHESTRATOR, RECON))
    await bus.get_pending(RECON)
    assert bus.queue_size(RECON) == 0


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------


async def test_broadcast_reaches_all_known_agents() -> None:
    bus = MessageBus()
    msg = AgentMessage.status(
        from_agent=ORCHESTRATOR,
        to_agent=ORCHESTRATOR,  # broadcast ignores this field
        engagement_id=EID,
        content={"status": "engagement starting"},
    )
    await bus.broadcast(msg)

    for agent in KNOWN_AGENTS:
        assert bus.queue_size(agent) == 1, f"{agent} queue should have 1 message"


async def test_broadcast_with_exclude() -> None:
    bus = MessageBus()
    msg = AgentMessage.status(
        from_agent=ORCHESTRATOR, to_agent=ORCHESTRATOR,
        engagement_id=EID, content={"status": "ok"},
    )
    await bus.broadcast(msg, exclude={RECON, SCAN})

    assert bus.queue_size(RECON) == 0
    assert bus.queue_size(SCAN) == 0
    assert bus.queue_size(EXPLOIT) == 1


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


async def test_messages_persisted_to_state_store(tmp_path: Path) -> None:
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("test", {})
        bus = MessageBus(state=state)

        msg = AgentMessage.task(
            from_agent=ORCHESTRATOR, to_agent=RECON,
            engagement_id=eid, content={"task": "start recon"},
        )
        await bus.send(msg)

        rows = await state.get_messages(eid)
    assert len(rows) == 1
    assert rows[0]["from_agent"] == ORCHESTRATOR
    assert rows[0]["to_agent"] == RECON
    assert rows[0]["message_type"] == "task"
    assert rows[0]["id"] == msg.id


async def test_multiple_messages_all_persisted(tmp_path: Path) -> None:
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("test", {})
        bus = MessageBus(state=state)

        await bus.send(AgentMessage.task(ORCHESTRATOR, RECON, eid, {"task": "a"}))
        await bus.send(AgentMessage.result(RECON, ORCHESTRATOR, eid, {"result": "b"}))
        await bus.send(AgentMessage.task(ORCHESTRATOR, EXPLOIT, eid, {"task": "c"}))

        all_rows = await state.get_messages(eid)
        recon_rows = await state.get_messages(eid, agent_name=RECON)

    assert len(all_rows) == 3
    # recon appears in both "to_agent" (first) and "from_agent" (second)
    assert len(recon_rows) == 2


async def test_broadcast_persisted_once(tmp_path: Path) -> None:
    """broadcast() saves the message once regardless of how many agents receive it."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("test", {})
        bus = MessageBus(state=state)

        msg = AgentMessage.status(
            from_agent=ORCHESTRATOR, to_agent=ORCHESTRATOR,
            engagement_id=eid, content={"status": "go"},
        )
        await bus.broadcast(msg)
        rows = await state.get_messages(eid)

    assert len(rows) == 1
    assert rows[0]["id"] == msg.id


async def test_message_content_persisted_as_json(tmp_path: Path) -> None:
    import json

    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("test", {})
        bus = MessageBus(state=state)

        payload = {"hosts": ["192.168.1.1", "192.168.1.2"], "count": 2}
        msg = AgentMessage.result(
            from_agent=RECON, to_agent=ORCHESTRATOR,
            engagement_id=eid, content=payload,
        )
        await bus.send(msg)

        rows = await state.get_messages(eid)

    assert len(rows) == 1
    stored_content = json.loads(rows[0]["content_json"])
    assert stored_content == payload
