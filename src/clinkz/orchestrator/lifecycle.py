"""Agent Lifecycle Manager — spins agents up and down on Orchestrator demand.

The Orchestrator calls this manager to create, start, and stop phase agents
as the engagement progresses.  Each agent runs as an independent asyncio.Task,
so multiple agents CAN execute concurrently.

Lifecycle
---------
1. Orchestrator calls ``spin_up("recon", task_msg)``
2. Manager creates a fresh ReconAgent, starts its run-loop as an asyncio.Task
3. Agent processes ``task_msg``, then waits for more messages from the bus
4. Orchestrator calls ``shut_down("recon")`` when done with that phase
5. Manager signals the stop event; agent finishes its current action,
   sends a STATUS message to the Orchestrator, then exits

Usage::

    mgr = AgentLifecycleManager(bus=bus, llm=llm, scope=scope, state=state,
                                 engagement_id=eid)

    recon = await mgr.spin_up("recon", task_message)
    # ... engagement runs ...
    await mgr.shut_down("recon")

    status = mgr.get_status()
    # {"recon": "stopped", "exploit": "running"}
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent
from clinkz.agents.crawl import CrawlAgent
from clinkz.agents.critic import CriticAgent
from clinkz.agents.exploit import ExploitAgent
from clinkz.agents.recon import ReconAgent
from clinkz.agents.report import ReportAgent
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR

if TYPE_CHECKING:
    from clinkz.comms.bus import MessageBus
    from clinkz.llm.base import LLMClient
    from clinkz.models.scope import EngagementScope
    from clinkz.state import StateStore
    from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Agent type → class mapping
# ---------------------------------------------------------------------------

#: Maps agent type strings accepted by spin_up/restart to the agent class.
#: "crawl" is an alias for "scan" (the file was named crawl.py but the
#: canonical protocol name is "scan").
_AGENT_CLASSES: dict[str, type[BaseAgent]] = {
    "recon": ReconAgent,
    "scan": CrawlAgent,    # protocol name
    "crawl": CrawlAgent,   # file/class name alias
    "exploit": ExploitAgent,
    "report": ReportAgent,
    "critic": CriticAgent,
}

# How long shut_down() waits for an agent task to finish before cancelling.
_SHUTDOWN_TIMEOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Status enum + internal record
# ---------------------------------------------------------------------------


class AgentStatus(StrEnum):
    """Runtime status of a managed agent."""

    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"


@dataclass
class _AgentRecord:
    """Internal bookkeeping for a managed agent instance."""

    agent: BaseAgent
    task: asyncio.Task[None]
    status: AgentStatus
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class AgentLifecycleManager:
    """Creates, starts, and stops phase agents on demand.

    All agents share the same LLM client, scope, state store, and engagement
    ID.  Each agent gets its own stop event and asyncio.Task.

    Args:
        bus: The shared MessageBus.
        llm: LLM client used by all agents.
        scope: Engagement scope for target validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        tools_per_agent: Optional mapping of agent type → tool list.
                         Agents not listed receive an empty tool list.
    """

    def __init__(
        self,
        bus: MessageBus,
        llm: LLMClient,
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        tools_per_agent: dict[str, list[ToolBase]] | None = None,
    ) -> None:
        self._bus = bus
        self._llm = llm
        self._scope = scope
        self._state = state
        self._engagement_id = engagement_id
        self._tools_per_agent: dict[str, list[ToolBase]] = tools_per_agent or {}
        # Keyed by agent.name (e.g. "recon", "crawl", "exploit")
        self._records: dict[str, _AgentRecord] = {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def spin_up(self, agent_type: str, task: AgentMessage) -> BaseAgent:
        """Create a new agent and start its run-loop as an asyncio.Task.

        If an agent with the same canonical name is already running, it is
        shut down first before the new instance is started.

        Args:
            agent_type: One of: "recon", "scan", "crawl", "exploit",
                        "report", "critic".
            task: Initial AgentMessage task to process immediately.

        Returns:
            The newly created BaseAgent instance.

        Raises:
            ValueError: If ``agent_type`` is not recognised.
        """
        if agent_type not in _AGENT_CLASSES:
            raise ValueError(
                f"Unknown agent type '{agent_type}'. "
                f"Valid types: {sorted(_AGENT_CLASSES)}"
            )

        agent_cls = _AGENT_CLASSES[agent_type]
        tools = self._tools_for(agent_type)
        agent = agent_cls(
            llm=self._llm,
            tools=tools,
            scope=self._scope,
            state=self._state,
            engagement_id=self._engagement_id,
        )

        # Shut down any pre-existing agent with the same canonical name
        if agent.name in self._records:
            await self.shut_down(agent.name)

        stop_event = asyncio.Event()
        loop_task: asyncio.Task[None] = asyncio.create_task(
            self._run_agent(agent, task, stop_event),
            name=f"clinkz-agent-{agent.name}",
        )

        self._records[agent.name] = _AgentRecord(
            agent=agent,
            task=loop_task,
            status=AgentStatus.RUNNING,
            stop_event=stop_event,
        )
        self._logger.info("Spun up agent '%s' for task %s", agent.name, task.id)
        return agent

    async def shut_down(self, agent_name: str) -> None:
        """Gracefully stop a running agent.

        Sets the agent's stop event so it finishes its current action before
        exiting.  The agent sends a STATUS message to the Orchestrator on
        exit.  Waits up to ``_SHUTDOWN_TIMEOUT_SECONDS`` before cancelling.

        Args:
            agent_name: Canonical agent name (e.g., "recon", "crawl").

        Raises:
            ValueError: If no agent with that name is tracked.
        """
        if agent_name not in self._records:
            raise ValueError(f"No agent named '{agent_name}' is being managed.")

        record = self._records[agent_name]
        if record.status == AgentStatus.STOPPED:
            self._logger.debug("Agent '%s' already stopped", agent_name)
            return

        self._logger.info("Shutting down agent '%s'", agent_name)
        record.stop_event.set()

        try:
            await asyncio.wait_for(record.task, timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            self._logger.warning(
                "Agent '%s' did not stop within %ds — cancelling task",
                agent_name,
                _SHUTDOWN_TIMEOUT_SECONDS,
            )
            record.task.cancel()
            try:
                await record.task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass

        record.status = AgentStatus.STOPPED
        self._logger.info("Agent '%s' stopped", agent_name)

    async def restart(self, agent_type: str, task: AgentMessage) -> BaseAgent:
        """Shut down the running agent (if any) and spin up a fresh instance.

        Useful when the Orchestrator needs to re-activate a phase agent with a
        new task (e.g., Recon Agent re-run for a newly discovered subdomain).

        Args:
            agent_type: Agent type string (same as spin_up).
            task: New AgentMessage task for the fresh instance.

        Returns:
            The newly created BaseAgent instance.
        """
        agent_cls = _AGENT_CLASSES.get(agent_type)
        if agent_cls is None:
            raise ValueError(f"Unknown agent type '{agent_type}'.")

        # Determine canonical name by creating a temp instance (no-cost)
        canonical = _peek_agent_name(agent_cls)
        if canonical in self._records and self._records[canonical].status == AgentStatus.RUNNING:
            await self.shut_down(canonical)

        return await self.spin_up(agent_type, task)

    def get_status(self) -> dict[str, str]:
        """Return a snapshot of all tracked agents and their statuses.

        Returns:
            Dict mapping agent name → status string ("running" / "stopped").
        """
        return {name: record.status.value for name, record in self._records.items()}

    def get_running_agents(self) -> list[str]:
        """Return the names of all currently running agents.

        Returns:
            Sorted list of agent name strings.
        """
        return sorted(
            name
            for name, record in self._records.items()
            if record.status == AgentStatus.RUNNING
        )

    # ------------------------------------------------------------------
    # Agent run-loop (asyncio.Task target)
    # ------------------------------------------------------------------

    async def _run_agent(
        self,
        agent: BaseAgent,
        initial_task: AgentMessage,
        stop_event: asyncio.Event,
    ) -> None:
        """Run one agent in a message-processing loop.

        Processes the initial task immediately, then polls the bus for more
        tasks until the stop event is set.  On exit, sends a STATUS message
        to the Orchestrator so it knows the agent has stopped.

        Args:
            agent: The agent instance to run.
            initial_task: First task to execute.
            stop_event: Set by shut_down() to signal graceful stop.
        """
        self._logger.debug("Agent '%s' run-loop started", agent.name)

        try:
            # Process the initial task
            await self._process_task(agent, initial_task)

            # Then continue processing incoming messages until told to stop
            while not stop_event.is_set():
                try:
                    msg = await asyncio.wait_for(
                        self._bus.receive(agent.name),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                if stop_event.is_set():
                    # Re-queue the message so it isn't lost
                    await self._bus.send(msg)
                    break

                await self._process_task(agent, msg)

        except asyncio.CancelledError:
            self._logger.debug("Agent '%s' run-loop cancelled", agent.name)
        except Exception as exc:
            self._logger.error(
                "Agent '%s' run-loop crashed: %s", agent.name, exc, exc_info=True
            )
            await self._safe_send(
                AgentMessage(
                    from_agent=agent.name,
                    to_agent=ORCHESTRATOR,
                    message_type=MessageType.ERROR,
                    content={"error": str(exc), "agent": agent.name},
                    engagement_id=self._engagement_id,
                )
            )
        finally:
            # Always notify Orchestrator that this agent has stopped
            await self._safe_send(
                AgentMessage(
                    from_agent=agent.name,
                    to_agent=ORCHESTRATOR,
                    message_type=MessageType.STATUS,
                    content={"status": "stopped", "agent": agent.name},
                    engagement_id=self._engagement_id,
                )
            )
            if agent.name in self._records:
                self._records[agent.name].status = AgentStatus.STOPPED
            self._logger.debug("Agent '%s' run-loop exited", agent.name)

    async def _process_task(self, agent: BaseAgent, msg: AgentMessage) -> None:
        """Run agent.run() for one task message and route the result.

        Errors are caught so a single task failure doesn't kill the loop.

        Args:
            agent: The agent to run.
            msg: Task message with content to pass to agent.run().
        """
        self._logger.info(
            "Agent '%s' processing task %s", agent.name, msg.id
        )
        try:
            result: dict[str, Any] = await agent.run(msg.content)
            await self._safe_send(
                AgentMessage.result(
                    from_agent=agent.name,
                    to_agent=ORCHESTRATOR,
                    engagement_id=msg.engagement_id,
                    content=result,
                    parent_message_id=msg.id,
                )
            )
        except NotImplementedError:
            self._logger.warning(
                "Agent '%s' run() not yet implemented — sending stub result", agent.name
            )
            await self._safe_send(
                AgentMessage.result(
                    from_agent=agent.name,
                    to_agent=ORCHESTRATOR,
                    engagement_id=msg.engagement_id,
                    content={"status": "not_implemented", "agent": agent.name},
                    parent_message_id=msg.id,
                )
            )
        except Exception as exc:
            self._logger.error(
                "Agent '%s' task %s failed: %s", agent.name, msg.id, exc, exc_info=True
            )
            await self._safe_send(
                AgentMessage.error(
                    from_agent=agent.name,
                    to_agent=ORCHESTRATOR,
                    engagement_id=msg.engagement_id,
                    content={"error": str(exc), "task_id": msg.id},
                    parent_message_id=msg.id,
                )
            )

    async def _safe_send(self, msg: AgentMessage) -> None:
        """Send a message on the bus, logging errors without crashing.

        Args:
            msg: Message to deliver.
        """
        try:
            await self._bus.send(msg)
        except Exception as exc:
            self._logger.error("Failed to send message on bus: %s", exc)

    def _tools_for(self, agent_type: str) -> list[ToolBase]:
        """Return the tool list for an agent type.

        Checks ``tools_per_agent`` first, then falls back to the agent's own
        canonical name in case the caller used the protocol alias.

        Args:
            agent_type: Agent type string.

        Returns:
            List of ToolBase instances (may be empty).
        """
        # Direct match
        if agent_type in self._tools_per_agent:
            return self._tools_per_agent[agent_type]
        # Try canonical name (e.g., "crawl" when "scan" was stored)
        cls = _AGENT_CLASSES.get(agent_type)
        if cls is not None:
            canonical = _peek_agent_name(cls)
            if canonical in self._tools_per_agent:
                return self._tools_per_agent[canonical]
        return []


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _peek_agent_name(cls: type[BaseAgent]) -> str:
    """Return the canonical name of an agent class without a full instantiation.

    Creates a minimal instance with None values — only safe because the
    BaseAgent.__init__ doesn't use its arguments to compute the name.

    Args:
        cls: BaseAgent subclass.

    Returns:
        The agent's canonical name string.
    """
    try:
        # BaseAgent stores args but name is a hard-coded property
        instance = cls.__new__(cls)
        return instance.name  # type: ignore[return-value]
    except Exception:
        # Fallback: instantiate properly (requires full args)
        return cls.__name__.lower().replace("agent", "")
