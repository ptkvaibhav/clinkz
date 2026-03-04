"""MessageBus — Orchestrator-mediated async message routing.

Architecture
------------
Every message sent by a phase agent (recon, scan, exploit, report, critic)
MUST be addressed to the Orchestrator.  The Orchestrator reads its queue,
reasons about the message, then forwards a new message to the appropriate
agent.  Direct agent-to-agent messaging is rejected.

Queue layout
------------
One ``asyncio.Queue`` per agent name.  The Orchestrator's queue receives
ALL messages from phase agents.  Phase-agent queues receive ONLY messages
that the Orchestrator explicitly routes to them.

Persistence
-----------
Every ``send()`` call persists the message to the StateStore (if provided)
so the full conversation history is available for auditing and replay.

Usage::

    bus = MessageBus(state=state_store)

    # Recon agent sends result to Orchestrator
    await bus.send(AgentMessage.result("recon", "orchestrator", eid, {...}))

    # Orchestrator reads its queue
    msg = await bus.receive("orchestrator")

    # Orchestrator routes task to Exploit agent
    await bus.send(AgentMessage.task("orchestrator", "exploit", eid, {...}))

    # Exploit agent reads its queue
    task = await bus.receive("exploit")
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from clinkz.comms.message import AgentMessage
from clinkz.comms.protocol import KNOWN_AGENTS, ORCHESTRATOR

if TYPE_CHECKING:
    from clinkz.state import StateStore

logger = logging.getLogger(__name__)


class MessageBus:
    """Async message router with Orchestrator-mediated delivery.

    Args:
        state: Optional StateStore for message persistence.  When provided,
               every ``send()`` call writes the message to the
               ``agent_messages`` table.
    """

    def __init__(self, state: StateStore | None = None) -> None:
        self._queues: dict[str, asyncio.Queue[AgentMessage]] = defaultdict(asyncio.Queue)
        self._state = state

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    async def send(self, message: AgentMessage) -> None:
        """Route a message to its recipient's queue.

        Routing rules:
        - Phase agents (non-orchestrator senders) MUST address the Orchestrator.
          Any other destination raises ``ValueError``.
        - The Orchestrator may send to any known agent.

        Args:
            message: The message to deliver.

        Raises:
            ValueError: If a phase agent tries to message another agent directly.
        """
        if message.from_agent != ORCHESTRATOR and message.to_agent != ORCHESTRATOR:
            raise ValueError(
                f"Agent '{message.from_agent}' cannot send directly to "
                f"'{message.to_agent}'. All messages must go through the "
                "Orchestrator. Set to_agent='orchestrator'."
            )

        logger.debug(
            "Bus: %s → %s [%s] id=%s",
            message.from_agent,
            message.to_agent,
            message.message_type,
            message.id,
        )

        if self._state is not None:
            await self._state.save_message(message)

        await self._queues[message.to_agent].put(message)

    async def receive(self, agent_name: str) -> AgentMessage:
        """Block until a message is available in this agent's queue.

        Args:
            agent_name: The agent reading from its inbox.

        Returns:
            The next AgentMessage in the queue.
        """
        return await self._queues[agent_name].get()

    async def get_pending(self, agent_name: str) -> list[AgentMessage]:
        """Return all messages currently queued for this agent (non-blocking).

        Drains the queue without blocking.  Returns an empty list when the
        queue is empty.

        Args:
            agent_name: The agent whose queue to inspect.

        Returns:
            List of pending AgentMessage objects (may be empty).
        """
        q = self._queues[agent_name]
        messages: list[AgentMessage] = []
        while True:
            try:
                messages.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return messages

    async def broadcast(
        self,
        message: AgentMessage,
        exclude: set[str] | None = None,
    ) -> None:
        """Deliver a message to every known agent's queue.

        Typically used by the Orchestrator for system-wide status updates.
        The same message object is enqueued for each target; ``to_agent``
        on the original message is preserved as-is.

        Args:
            message: The message to broadcast.
            exclude: Optional set of agent names to skip.
        """
        skip = exclude or set()
        targets = sorted(KNOWN_AGENTS - skip)

        for agent in targets:
            await self._queues[agent].put(message)
            logger.debug("Bus broadcast → %s [%s]", agent, message.id)

        if self._state is not None:
            await self._state.save_message(message)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def queue_size(self, agent_name: str) -> int:
        """Return the current number of messages waiting for an agent."""
        return self._queues[agent_name].qsize()
