"""OrchestratorAgent — the LLM-driven central coordinator of a Clinkz engagement.

The Orchestrator owns the MessageBus, AgentLifecycleManager, ToolResolver, and
StateStore.  It runs an async reasoning loop that:

  1. Collects all pending messages from agents
  2. Builds a rich context (scope, state, capabilities, pending messages)
  3. Calls the LLM (most capable model) to decide the next action
  4. Executes that action (spin_up / shut_down / route / complete)
  5. Repeats until ``complete_engagement`` is called

Usage::

    scope = EngagementScope(name="ACME Q1", targets=[...])
    orchestrator = OrchestratorAgent()
    result = await orchestrator.run(scope)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.config import settings
from clinkz.credentials.store import CredentialStore
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.llm.factory import get_llm_client
from clinkz.models.scope import EngagementScope
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Orchestrator action tool schemas (passed to LLM as function-calling tools)
# ---------------------------------------------------------------------------

_ORCHESTRATOR_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "spin_up_agent",
            "description": (
                "Start a specialist phase agent and assign it a task. "
                "Use this to begin reconnaissance, scanning, exploitation, "
                "critic review, or report generation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_type": {
                        "type": "string",
                        "enum": ["recon", "scan", "exploit", "critic", "report"],
                        "description": "Type of specialist agent to create.",
                    },
                    "task": {
                        "type": "string",
                        "description": (
                            "Detailed task instruction for the agent. "
                            "Be specific: include targets, scope, and what output is expected."
                        ),
                    },
                },
                "required": ["agent_type", "task"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shut_down_agent",
            "description": "Stop a running agent when its work is complete.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "enum": ["recon", "scan", "exploit", "critic", "report"],
                        "description": "Canonical name of the agent to stop.",
                    },
                },
                "required": ["agent_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "route_message",
            "description": (
                "Forward information or a task from one agent to another. "
                "Use this when an agent needs data that another agent already produced, "
                "or when you want an agent to continue with new context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "to_agent": {
                        "type": "string",
                        "enum": ["recon", "scan", "exploit", "critic", "report"],
                        "description": "Destination agent for the routed message.",
                    },
                    "content": {
                        "type": "object",
                        "description": "Message payload to deliver to the agent.",
                    },
                },
                "required": ["to_agent", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "complete_engagement",
            "description": (
                "Declare the engagement finished. Call this ONLY after the Report Agent "
                "has delivered its final report. This exits the orchestrator loop."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Brief summary of the engagement outcome.",
                    },
                },
                "required": ["summary"],
            },
        },
    },
]

# Maximum conversation history to keep (system + this many turns) to avoid token overflow.
_MAX_HISTORY_TURNS = 20

# How long to wait between poll iterations when no messages are pending (seconds).
_POLL_INTERVAL = 1.0

# Max consecutive idle iterations before forcing completion (safety valve).
_MAX_IDLE_ITERATIONS = 300

# Block an agent after this many consecutive identical errors.
_MAX_SAME_ERROR = 2


# ---------------------------------------------------------------------------
# OrchestratorAgent
# ---------------------------------------------------------------------------


class OrchestratorAgent:
    """LLM-driven central coordinator for an autonomous pentest engagement.

    The Orchestrator owns all infrastructure components (bus, lifecycle manager,
    tool resolver, state store) and drives the engagement through an async
    reasoning loop.

    Args:
        llm: LLM client to use. If None, one is created from ORCHESTRATOR_LLM_PROVIDER
             env var (falls back to LLM_PROVIDER / settings.llm_provider).
        db_path: Path to the SQLite database. Defaults to settings.db_path.
        provider: Explicit LLM provider override (ignored when ``llm`` is provided).
    """

    def __init__(
        self,
        llm: LLMClient | None = None,
        db_path: Path | str | None = None,
        provider: str | None = None,
    ) -> None:
        if llm is not None:
            self._llm = llm
        else:
            orch_provider = (
                os.getenv("ORCHESTRATOR_LLM_PROVIDER")
                or provider
                or settings.llm_provider
            )
            self._llm = get_llm_client(orch_provider)

        self._db_path = Path(db_path) if db_path is not None else settings.db_path
        self._system_prompt: str = _load_system_prompt()

        # Set during run() — not available until the engagement starts
        self._state: StateStore | None = None
        self._bus: MessageBus | None = None
        self._lifecycle: AgentLifecycleManager | None = None
        self._resolver: ToolResolver | None = None
        self._cred_store: CredentialStore | None = None
        self._scope: EngagementScope | None = None
        self._engagement_id: str | None = None
        self._summary: dict[str, Any] = {}

        # Failure escalation: tracks consecutive errors per agent.
        # Key = agent_type, value = list of recent error strings.
        # When the same error appears 2+ times in a row, the agent is
        # blocked from retry and the Orchestrator moves on.
        self._agent_failures: dict[str, list[str]] = {}

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, scope: EngagementScope) -> dict[str, Any]:
        """Execute a full pentest engagement for the given scope.

        Creates a new engagement in the state store, spins up the infrastructure,
        and runs the LLM-driven coordination loop until completion.

        Args:
            scope: Engagement scope (targets, exclusions, rate limits).

        Returns:
            Summary dict with engagement outcome and key statistics.
        """
        self._logger.info(
            "OrchestratorAgent starting engagement — scope: %s",
            scope.name,
        )

        async with StateStore(self._db_path) as state:
            engagement_id = await state.create_engagement(
                scope.name, scope.model_dump()
            )
            bus = MessageBus(state=state)
            lifecycle = AgentLifecycleManager(
                bus=bus,
                llm=self._llm,
                scope=scope,
                state=state,
                engagement_id=engagement_id,
            )
            resolver = ToolResolver()
            cred_store = CredentialStore(state)
            await cred_store.initialize()

            self._state = state
            self._bus = bus
            self._lifecycle = lifecycle
            self._resolver = resolver
            self._cred_store = cred_store
            self._scope = scope
            self._engagement_id = engagement_id

            try:
                await self._main_loop()
            except Exception as exc:
                self._logger.error("Orchestrator loop crashed: %s", exc, exc_info=True)
                await state.update_engagement_status(engagement_id, "failed")
                self._summary["status"] = "failed"
                self._summary["error"] = str(exc)
                return self._summary

            await state.update_engagement_status(engagement_id, "completed")

        self._logger.info(
            "Engagement %s complete — %s",
            engagement_id,
            self._summary.get("summary", "no summary"),
        )
        return self._summary

    # ------------------------------------------------------------------
    # Main reasoning loop
    # ------------------------------------------------------------------

    async def _main_loop(self) -> None:
        """LLM-driven coordination loop.

        Collects pending messages, builds context, calls the LLM to decide
        an action, executes it, and repeats until ``complete_engagement``.
        """
        assert self._bus is not None
        assert self._lifecycle is not None

        # Conversation history for the orchestrator LLM
        history: list[LLMMessage] = []
        first_iteration = True
        idle_count = 0
        force_reason = False  # Set after LLM errors to retry reasoning

        while True:
            # Drain all pending messages addressed to the orchestrator
            pending = await self._bus.get_pending(ORCHESTRATOR)

            # Track agent failures/successes for escalation logic
            self._track_agent_outcomes(pending)

            running = self._lifecycle.get_running_agents()

            # Decide whether to call the LLM this iteration
            should_reason = first_iteration or bool(pending) or force_reason
            force_reason = False

            if not should_reason:
                if not running:
                    # No messages and no agents — nothing to wait for
                    self._logger.warning(
                        "No pending messages and no running agents. "
                        "Forcing engagement completion."
                    )
                    self._summary = {
                        "status": "completed",
                        "summary": "No agents running and no messages — engagement ended.",
                    }
                    break

                idle_count += 1
                if idle_count >= _MAX_IDLE_ITERATIONS:
                    self._logger.error(
                        "Orchestrator idle for %d iterations — forcing completion.",
                        _MAX_IDLE_ITERATIONS,
                    )
                    self._summary = {
                        "status": "timeout",
                        "summary": "Orchestrator timed out waiting for agent messages.",
                    }
                    break

                await asyncio.sleep(_POLL_INTERVAL)
                continue

            # We have work to do — call the LLM
            first_iteration = False
            idle_count = 0

            context_msg = await self._build_context(pending)
            history.append(LLMMessage(role="user", content=context_msg))

            # Trim history to avoid token overflow
            trimmed_history = _trim_history(history, _MAX_HISTORY_TURNS)
            messages = [
                LLMMessage(role="system", content=self._system_prompt),
                *trimmed_history,
            ]

            # LLM reasoning step
            try:
                action: AgentAction = await self._llm.reason(
                    messages, tools=_ORCHESTRATOR_TOOLS
                )
            except Exception as exc:
                self._logger.error("LLM reasoning failed: %s", exc, exc_info=True)
                # Remove the unanswered context message to avoid corrupting
                # the conversation history (e.g., orphaned user messages that
                # break function_call/response adjacency for Gemini).
                if history and history[-1].role == "user":
                    history.pop()
                force_reason = True  # retry on next iteration
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            # Record the assistant's response in history
            assistant_msg = LLMMessage(
                role="assistant",
                content=action.thought or "",
                tool_calls=[action.tool_call] if action.tool_call else None,
            )
            history.append(assistant_msg)

            if action.tool_call is None:
                if action.final_answer:
                    self._logger.info(
                        "LLM returned final_answer: %s", action.final_answer[:200]
                    )
                    self._summary = {
                        "status": "completed",
                        "summary": action.final_answer,
                    }
                    break
                # Bare thought — wait for more messages
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            # Execute the tool call
            result_text, is_complete = await self._execute_action(action.tool_call)
            self._logger.debug("Action result: %s", result_text)

            # Feed tool result back into history
            history.append(
                LLMMessage(
                    role="tool",
                    content=result_text,
                    tool_call_id=action.tool_call.id,
                )
            )

            if is_complete:
                break

    # ------------------------------------------------------------------
    # Failure escalation
    # ------------------------------------------------------------------

    def _track_agent_outcomes(self, pending: list[AgentMessage]) -> None:
        """Update the failure tracker based on incoming agent messages.

        ERROR messages append to the agent's failure list.
        RESULT messages with a successful outcome clear the failure list.

        Args:
            pending: Messages just drained from the orchestrator queue.
        """
        for msg in pending:
            agent = msg.from_agent
            if msg.message_type in (MessageType.ERROR, "error"):
                error_str = msg.content.get("error", str(msg.content))
                self._agent_failures.setdefault(agent, []).append(error_str)
                self._logger.debug(
                    "Failure tracker: %s error #%d: %s",
                    agent,
                    len(self._agent_failures[agent]),
                    error_str[:120],
                )
            elif msg.message_type in (MessageType.RESULT, "result"):
                status = msg.content.get("status", "")
                if status != "not_implemented":
                    # Successful result — reset failure counter
                    self._agent_failures.pop(agent, None)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    async def _build_context(self, pending: list[AgentMessage]) -> str:
        """Build a comprehensive context string for the orchestrator LLM.

        Summarizes the engagement state (running agents, finding counts,
        available capabilities) and formats pending messages.

        Args:
            pending: Messages waiting in the orchestrator's queue.

        Returns:
            A formatted context string to pass as a user message to the LLM.
        """
        assert self._lifecycle is not None
        assert self._scope is not None
        assert self._state is not None
        assert self._resolver is not None
        assert self._engagement_id is not None

        lines: list[str] = []

        # Engagement scope summary
        targets_str = ", ".join(
            f"{t.value} ({t.type.value})" for t in self._scope.targets
        )
        excluded_str = (
            ", ".join(f"{e.value}" for e in self._scope.excluded)
            if self._scope.excluded
            else "none"
        )
        lines.append("=== ENGAGEMENT STATE ===")
        lines.append(f"Engagement: {self._scope.name} (id={self._engagement_id})")
        lines.append(f"Targets: {targets_str or 'none'}")
        lines.append(f"Excluded: {excluded_str}")

        # Running agents
        running = self._lifecycle.get_running_agents()
        all_status = self._lifecycle.get_status()
        lines.append("")
        lines.append("=== AGENTS ===")
        if running:
            lines.append(f"Running: {', '.join(running)}")
        else:
            lines.append("Running: none")
        stopped = [n for n, s in all_status.items() if s == "stopped"]
        if stopped:
            lines.append(f"Completed: {', '.join(stopped)}")

        # Blocked agents (repeated failures)
        blocked = []
        for agent, errors in self._agent_failures.items():
            if (
                len(errors) >= _MAX_SAME_ERROR
                and len(set(errors[-_MAX_SAME_ERROR:])) == 1
            ):
                blocked.append(f"{agent} (error: {errors[-1][:100]})")
        if blocked:
            lines.append(f"BLOCKED (repeated failures): {'; '.join(blocked)}")

        # Findings with severity breakdown
        try:
            findings = await self._state.get_findings(self._engagement_id)
            validated = [f for f in findings if f.get("validated")]
            severity_counts: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            lines.append("")
            lines.append("=== FINDINGS ===")
            lines.append(
                f"{len(findings)} total, {len(validated)} validated by Critic"
            )
            if severity_counts:
                sev_parts = [f"{sev}: {cnt}" for sev, cnt in sorted(severity_counts.items())]
                lines.append(f"By severity: {', '.join(sev_parts)}")
            # Brief summary of confirmed findings
            confirmed = [f for f in findings if f.get("confirmed")]
            for cf in confirmed[:10]:
                title = cf.get("title", "Untitled")
                sev = cf.get("severity", "?")
                target = cf.get("target", "?")
                lines.append(f"  - [{sev.upper()}] {title} @ {target}")
            if len(confirmed) > 10:
                lines.append(f"  ... and {len(confirmed) - 10} more confirmed findings")
        except Exception as exc:
            self._logger.warning("Could not fetch findings: %s", exc)

        # Credential store status
        try:
            assert self._cred_store is not None
            all_creds = await self._cred_store.get(self._engagement_id)
            valid_creds = [c for c in all_creds if c.valid is True]
            untested = [c for c in all_creds if c.valid is None]
            invalid = [c for c in all_creds if c.valid is False]
            lines.append("")
            lines.append("=== CREDENTIAL STORE ===")
            lines.append(
                f"{len(all_creds)} total: {len(valid_creds)} valid, "
                f"{len(untested)} untested, {len(invalid)} invalid"
            )
            for vc in valid_creds:
                lines.append(
                    f"  - VALID: {vc.username}:{vc.password} "
                    f"({vc.technology or 'generic'}) @ {vc.url or 'no URL'}"
                )
        except Exception as exc:
            self._logger.warning("Could not fetch credentials: %s", exc)

        # Authenticated sessions (for cross-agent handoff)
        try:
            sessions = await self._state.get_sessions(self._engagement_id)
            if sessions:
                lines.append("")
                lines.append("=== AUTHENTICATED SESSIONS ===")
                for sess in sessions:
                    cookie_names = list(sess.get("cookies", {}).keys())
                    jar = sess.get("cookie_jar_path", "")
                    lines.append(
                        f"  - From '{sess['agent']}': cookies={cookie_names}, "
                        f"jar={jar}"
                    )
                lines.append(
                    "IMPORTANT: When spinning up Exploit or other agents, include "
                    "valid credentials and session cookies from above so the agent "
                    "does NOT waste iterations on login. Pass the cookie_jar_path "
                    "so tools can reuse the authenticated session."
                )
        except Exception as exc:
            self._logger.warning("Could not fetch sessions: %s", exc)

        # Available tool capabilities
        try:
            caps = self._resolver.get_all_capabilities()
            lines.append("")
            lines.append("=== AVAILABLE CAPABILITIES ===")
            for cap in caps[:30]:  # cap at 30 to avoid token bloat
                match = self._resolver.find_tool(cap)
                if match:
                    avail = "available" if match.available else "not installed"
                    lines.append(f"- {cap}: {match.name} ({match.source}, {avail})")
            if len(caps) > 30:
                lines.append(f"  ... and {len(caps) - 30} more")
        except Exception as exc:
            self._logger.warning("Could not fetch capabilities: %s", exc)

        # Pending messages
        if pending:
            lines.append("")
            lines.append(f"=== PENDING MESSAGES ({len(pending)}) ===")
            for i, msg in enumerate(pending, 1):
                content_preview = json.dumps(msg.content)[:500]
                lines.append(
                    f"{i}. [{msg.message_type.upper()}] from={msg.from_agent} "
                    f"id={msg.id[:8]}"
                )
                lines.append(f"   content: {content_preview}")
        else:
            lines.append("")
            lines.append("=== PENDING MESSAGES ===")
            lines.append("None")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Action executor
    # ------------------------------------------------------------------

    async def _execute_action(
        self, tool_call: ToolCall
    ) -> tuple[str, bool]:
        """Execute one orchestrator action tool call.

        Args:
            tool_call: The tool call returned by the LLM.

        Returns:
            Tuple of (result description, is_complete).
            is_complete is True only for ``complete_engagement``.
        """
        assert self._lifecycle is not None
        assert self._bus is not None
        assert self._engagement_id is not None

        name = tool_call.name
        args = tool_call.arguments

        if name == "spin_up_agent":
            agent_type: str = args["agent_type"]
            task_text: str = args["task"]

            # Escalation check: if this agent has failed with the same error
            # _MAX_SAME_ERROR times in a row, refuse the retry.
            recent = self._agent_failures.get(agent_type, [])
            if (
                len(recent) >= _MAX_SAME_ERROR
                and len(set(recent[-_MAX_SAME_ERROR:])) == 1
            ):
                blocked_err = recent[-1]
                self._logger.warning(
                    "ESCALATION: agent '%s' failed %d times with the same error "
                    "— blocking retry. Error: %s",
                    agent_type,
                    _MAX_SAME_ERROR,
                    blocked_err,
                )
                result = (
                    f"BLOCKED: {agent_type} agent has failed {_MAX_SAME_ERROR} "
                    f"consecutive times with the same error: {blocked_err[:200]}. "
                    f"Do NOT retry this agent with the same approach. "
                    f"Either try a completely different strategy, use a different "
                    f"agent, or skip this phase and move on."
                )
                return result, False

            task_msg = AgentMessage.task(
                from_agent=ORCHESTRATOR,
                to_agent=agent_type,
                engagement_id=self._engagement_id,
                content={"task": task_text},
            )
            try:
                await self._lifecycle.spin_up(agent_type, task_msg)
                result = f"Started {agent_type} agent. Task: {task_text[:120]}"
            except ValueError as exc:
                result = f"ERROR starting {agent_type}: {exc}"
            self._logger.info("Action spin_up_agent(%s): %s", agent_type, result)
            return result, False

        if name == "shut_down_agent":
            agent_name: str = args["agent_name"]
            try:
                await self._lifecycle.shut_down(agent_name)
                result = f"Stopped {agent_name} agent."
            except ValueError as exc:
                result = f"ERROR stopping {agent_name}: {exc}"
            self._logger.info("Action shut_down_agent(%s): %s", agent_name, result)
            return result, False

        if name == "route_message":
            to_agent: str = args["to_agent"]
            content: dict[str, Any] = args["content"]
            msg = AgentMessage.task(
                from_agent=ORCHESTRATOR,
                to_agent=to_agent,
                engagement_id=self._engagement_id,
                content=content,
            )
            try:
                await self._bus.send(msg)
                result = f"Routed message to {to_agent}. Content keys: {list(content.keys())}"
            except Exception as exc:
                result = f"ERROR routing to {to_agent}: {exc}"
            self._logger.info("Action route_message(→%s): %s", to_agent, result)
            return result, False

        if name == "complete_engagement":
            summary: str = args.get("summary", "Engagement complete.")
            self._summary = {"status": "completed", "summary": summary}
            self._logger.info("Action complete_engagement: %s", summary)
            return f"Engagement marked complete: {summary}", True

        # Unknown tool — log and continue
        self._logger.warning("Unknown orchestrator action: %s", name)
        return f"Unknown action '{name}' — ignored.", False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_system_prompt() -> str:
    """Load the orchestrator system prompt template from the prompts directory.

    Capability and scope placeholders are filled in at runtime by _build_context().
    We return the raw template here; substitution happens inside _build_context.

    Returns:
        System prompt string (with {capabilities} and {scope_summary} placeholders).
    """
    prompt_path = Path(__file__).parent / "prompts" / "orchestrator_system.md"
    try:
        return prompt_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Orchestrator system prompt not found at %s — using fallback.", prompt_path)
        return (
            "You are the Orchestrator of an autonomous penetration testing system. "
            "Coordinate specialist agents (recon, scan, exploit, critic, report) "
            "to complete the engagement. Use the provided tools to spin up agents, "
            "route messages, and complete the engagement when done."
        )


def _trim_history(
    history: list[LLMMessage], max_turns: int
) -> list[LLMMessage]:
    """Return the most recent ``max_turns`` messages from history.

    Keeps the conversation context bounded to avoid token overflow.
    Ensures the trimmed list does not start with a ``tool`` message
    (orphaned function_response) or an ``assistant`` message with
    tool_calls that lost its following tool response — both would
    cause a 400 error from LLM providers like Gemini that require
    strict function_call / function_response adjacency.

    Args:
        history: Full conversation history.
        max_turns: Maximum number of messages to retain.

    Returns:
        Trimmed history list (most recent messages).
    """
    if len(history) <= max_turns:
        return history

    trimmed = history[-max_turns:]

    # Drop leading tool messages (orphaned function_responses)
    while trimmed and trimmed[0].role == "tool":
        trimmed = trimmed[1:]

    # Drop leading assistant messages with tool_calls whose responses were cut
    while (
        trimmed
        and trimmed[0].role == "assistant"
        and trimmed[0].tool_calls
        and (len(trimmed) < 2 or trimmed[1].role != "tool")
    ):
        trimmed = trimmed[1:]
        # Also drop any following orphaned tool messages
        while trimmed and trimmed[0].role == "tool":
            trimmed = trimmed[1:]

    return trimmed
