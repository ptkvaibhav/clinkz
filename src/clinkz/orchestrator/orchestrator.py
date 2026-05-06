"""OrchestratorAgent — concurrent phase execution with shared state.

The Orchestrator drives three macro-phases:

  1. RECON (sequential)  — reconnaissance, default credential testing
  2. CONCURRENT          — Research + Scan + Exploit run in parallel via
                           asyncio.Tasks, coordinating through shared SQLite
                           state (endpoints, runbook, findings tables)
  3. REPORT (sequential) — generate the final pentest report

Within Phase 2 the agents share state:
  - Scan writes endpoints → Exploit reads new endpoints
  - Research writes runbook → Exploit reads runbook entries
  - Exploit writes findings → visible to all

A monitor loop polls every 10 seconds to decide when all concurrent work
is done (Scan finished + Exploit tested all endpoints + Research finished).

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
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.knowledge.query import KnowledgeBase
from clinkz.knowledge.seed_playbook import seed_tier1_tests
from clinkz.llm.base import LLMClient
from clinkz.llm.factory import get_llm_client
from clinkz.llm.fallback import ResilientLLMClient, validate_agent_chains
from clinkz.models.recon import (
    PortScanResult,
    ReconResult,
    ReconService,
    ServiceScanResult,
    TechStack,
    WebReconResult,
)
from clinkz.models.scope import EngagementScope
from clinkz.observability.trace import (
    TraceWriter,
    set_active_trace_writer,
)
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore
from clinkz.tools.docker_preflight import ensure_container_ready
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# How long to wait for an agent to produce a RESULT before timing out (seconds).
_PHASE_TIMEOUT = 600

# Maximum cross-phase re-spins per engagement (e.g., Exploit asks for more recon).
MAX_CROSS_PHASE_RESPINS = 3

# Poll interval when waiting for agent messages (seconds).
_POLL_INTERVAL = 1.0

# Generic service/protocol names that should NOT be fed to the Research Agent
# as "technologies". These are transport or protocol labels, not products —
# researching "http" yields no useful CVEs or writeups.
_GENERIC_SERVICE_NAMES: frozenset[str] = frozenset(
    {"", "tcp", "udp", "unknown", "http", "https", "ssh", "ftp", "smtp", "dns", "telnet"}
)


# ---------------------------------------------------------------------------
# OrchestratorAgent
# ---------------------------------------------------------------------------


class OrchestratorAgent:
    """Concurrent phase orchestrator for an autonomous pentest engagement.

    The run() method follows three macro-phases:
      1. RECON (sequential) — recon + default cred testing
      2. CONCURRENT — Research + Scan + Exploit in parallel
      3. REPORT (sequential) — findings summary

    Each agent gets its own LLM client via per-agent provider env vars
    (RECON_LLM_PROVIDER, SCAN_LLM_PROVIDER, etc.).

    Args:
        llm: LLM client for the orchestrator itself. If None, one is created
             from ORCHESTRATOR_LLM_PROVIDER env var.
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
                os.getenv("ORCHESTRATOR_LLM_PROVIDER") or provider or settings.llm_provider
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

        # Persistent knowledge base (created during run())
        self._persistent_kb: PersistentKnowledgeBase | None = None

        # Cross-phase re-spin counter (shared across all phases)
        self._cross_phase_respins: int = 0

        # Cache for _probe_url results to avoid repeated slow HTTP HEAD requests
        self._probe_cache: dict[str, int | None] = {}

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, scope: EngagementScope) -> dict[str, Any]:
        """Execute a full pentest engagement for the given scope.

        Three macro-phases:
          1. RECON (sequential) — recon + default credential testing
          2. CONCURRENT — Research + Scan + Exploit in parallel
          3. REPORT (sequential) — generate findings report

        Args:
            scope: Engagement scope (targets, exclusions, rate limits).

        Returns:
            Summary dict with engagement outcome and key statistics.
        """
        self._logger.info(
            "OrchestratorAgent starting engagement — scope: %s",
            scope.name,
        )

        # Container-first tool execution: verify the tools container is
        # reachable before we touch state or spin up any agent. Propagates
        # ClinkzDockerError to the caller (CLI) for clean exit.
        if settings.tool_exec_mode == "docker":
            await ensure_container_ready(settings.docker_container)

        # Fail fast if no agent has a usable LLM provider — otherwise every
        # LLM call later in the engagement walks an empty fallback chain.
        validate_agent_chains(["recon", "scan", "exploit", "research", "report"])

        async with StateStore(self._db_path) as state:
            engagement_id = await state.create_engagement(scope.name, scope.model_dump())
            # Open the engagement-scoped trace writer before any agents spin up
            # so tool/LLM/handoff events from the very first phase are captured.
            trace_writer = TraceWriter(engagement_id=engagement_id)
            set_active_trace_writer(trace_writer)
            self._logger.info("TraceWriter opened: %s", trace_writer.path)
            bus = MessageBus(state=state)
            knowledge_base = KnowledgeBase()
            self._logger.info("KnowledgeBase loaded: %s", knowledge_base.stats())

            # Initialize persistent knowledge base and seed Tier 1 tests
            persistent_kb = await PersistentKnowledgeBase.create(
                str(self._db_path).replace(".db", "_knowledge.db")
                if str(self._db_path) != ":memory:"
                else "clinkz_knowledge.db"
            )
            await seed_tier1_tests(persistent_kb)
            self._persistent_kb = persistent_kb
            self._logger.info("PersistentKB initialised and Tier 1 tests seeded")

            # Build per-agent LLM clients from env-var config
            agent_llms = self._build_agent_llms()

            lifecycle = AgentLifecycleManager(
                bus=bus,
                llm=self._llm,
                scope=scope,
                state=state,
                engagement_id=engagement_id,
                knowledge_base=knowledge_base,
                llm_per_agent=agent_llms,
                persistent_kb=persistent_kb,
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
            self._cross_phase_respins = 0

            targets_str = ", ".join(f"{t.value} ({t.type.value})" for t in scope.targets)
            summary: dict[str, Any] = {"status": "completed", "phases": {}}

            try:
                # =============================================================
                # PHASE 1: RECON (sequential — must complete first)
                # =============================================================
                recon_result = await self._run_phase(
                    "recon",
                    {
                        "task": f"Full reconnaissance on {targets_str}. "
                        f"Discover subdomains, open ports, services, "
                        f"technology stack, and any OSINT intel.",
                        "scope": scope.model_dump(),
                    },
                )
                summary["phases"]["recon"] = recon_result
                self._logger.info("PHASE 1 (RECON) complete")

                # If recon failed (error dict), construct a minimal ReconResult
                # from the scope targets so downstream agents can still work.
                # Preserve any top-level v1-style hints (tech, hosts, summary)
                # so downstream extraction still sees them.
                if recon_result.get("status") == "error" or "result" not in recon_result:
                    self._logger.warning(
                        "Recon returned error — constructing fallback ReconResult from scope"
                    )
                    fallback = self._build_fallback_recon(scope)
                    for hint_key in ("tech", "technologies", "tech_stack", "hosts", "summary"):
                        if hint_key in recon_result:
                            fallback[hint_key] = recon_result[hint_key]
                    recon_result = fallback

                # Try default credentials for discovered technologies
                await self._try_default_credentials(recon_result)

                # Gather credentials and sessions for handoff
                valid_creds = await cred_store.get_all_valid(engagement_id)
                sessions = await state.get_sessions(engagement_id)
                cred_data = [c.model_dump() for c in valid_creds]
                session_data = sessions

                # Extract technologies for the Research Agent
                technologies = self._extract_technologies(recon_result)

                # Query persistent KB for playbook entries matching tech stack
                await self._log_playbook_matches(persistent_kb, technologies)

                # Prepare session cookies for authenticated agents
                cookies: dict[str, str] = {}
                authenticated_as = ""
                if sessions:
                    login_url = await self._find_login_url(recon_result, "", scan_result=None)
                    if not login_url:
                        for t in scope.targets:
                            base = (
                                t.value
                                if t.value.startswith(("http://", "https://"))
                                else f"http://{t.value}"
                            )
                            login_url = f"{base.rstrip('/')}/login"
                            break
                    cookies, authenticated_as = await self._verify_and_refresh_session(
                        login_url or "", sessions, valid_creds
                    )

                # =============================================================
                # PHASE 2: CONCURRENT (Research + Scan + Exploit)
                # =============================================================
                self._logger.info(
                    "Starting concurrent phase: research=%d techs, scan+exploit",
                    len(technologies),
                )

                concurrent_results = await self._run_concurrent_phase(
                    targets_str=targets_str,
                    recon_result=recon_result,
                    technologies=technologies,
                    cred_data=cred_data,
                    session_data=session_data,
                    cookies=cookies,
                    authenticated_as=authenticated_as,
                )
                summary["phases"].update(concurrent_results)
                self._logger.info("PHASE 2 (CONCURRENT) complete")

                # Persist exploit findings to the findings table so the
                # Report Agent can query them.
                exploit_data = concurrent_results.get("exploit", {})
                exploit_result = exploit_data.get("result", {})
                persisted_findings = exploit_result.get("findings", [])
                if persisted_findings:
                    self._logger.info(
                        "Persisting %d exploit findings to state",
                        len(persisted_findings),
                    )
                    for finding in persisted_findings:
                        if isinstance(finding, dict):
                            await state.add_finding(engagement_id, finding)
                else:
                    self._logger.warning("No exploit findings to persist")

                # =============================================================
                # PHASE 3: REPORT (sequential)
                # =============================================================
                report_result = await self._run_phase(
                    "report",
                    {
                        "task": "Generate a penetration test report. "
                        "Include all findings with CVSS scores, evidence, "
                        "and remediation recommendations.",
                        "engagement_id": engagement_id,
                    },
                )
                summary["phases"]["report"] = report_result
                self._logger.info("PHASE 3 (REPORT) complete")

            except Exception as exc:
                self._logger.error("Orchestrator failed: %s", exc, exc_info=True)
                await state.update_engagement_status(engagement_id, "failed")
                summary["status"] = "failed"
                summary["error"] = str(exc)
                return summary
            finally:
                await persistent_kb.close()
                # Always close + unset the trace writer so module-level state
                # cannot leak between back-to-back engagements (relevant in
                # tests and long-running daemon processes).
                try:
                    trace_writer.close()
                finally:
                    set_active_trace_writer(None)

            await state.update_engagement_status(engagement_id, "completed")

        self._logger.info("Engagement %s complete", engagement_id)
        return summary

    # ------------------------------------------------------------------
    # Per-agent LLM factory
    # ------------------------------------------------------------------

    def _build_agent_llms(self) -> dict[str, LLMClient]:
        """Create a ResilientLLMClient per agent role.

        Each agent gets a wrapper tied to its profile (``fast`` or
        ``reasoning``) so a 429/503 from the primary provider silently
        falls back to the next one in the chain.

        Returns:
            Dict mapping agent type strings to LLMClient instances.
        """
        agent_roles = ("recon", "scan", "exploit", "research", "report")

        llms: dict[str, LLMClient] = {}
        for agent_type in agent_roles:
            try:
                llms[agent_type] = ResilientLLMClient(agent_role=agent_type)
                self._logger.debug("Agent '%s' LLM: ResilientLLMClient", agent_type)
            except Exception as exc:
                self._logger.warning(
                    "Failed to create ResilientLLMClient for '%s': %s — using default",
                    agent_type,
                    exc,
                )
        return llms

    # ------------------------------------------------------------------
    # Concurrent phase runner
    # ------------------------------------------------------------------

    async def _run_concurrent_phase(
        self,
        *,
        targets_str: str,
        recon_result: dict[str, Any],
        technologies: list[str],
        cred_data: list[dict[str, Any]],
        session_data: list[dict[str, Any]],
        cookies: dict[str, str],
        authenticated_as: str,
    ) -> dict[str, dict[str, Any]]:
        """Run Research + Scan in parallel, then Exploit sequentially.

        Flow:
        1. Start Research + Scan concurrently (asyncio.Tasks)
        2. Wait for Scan to complete (Exploit needs scan results)
        3. Wait for Research to complete (may finish before or after Scan)
        4. Pass v2 ScanResult and ResearchResult directly to Exploit
        5. Run Exploit with both inputs

        Args:
            targets_str: Human-readable target list.
            recon_result: Recon phase result dict.
            technologies: Technologies extracted from recon.
            cred_data: Serialized valid credentials.
            session_data: Session dicts from state store.
            cookies: Verified session cookies.
            authenticated_as: Username for authenticated session.

        Returns:
            Dict with keys "research", "scan", "exploit" → result dicts.
        """
        assert self._engagement_id is not None

        results: dict[str, dict[str, Any]] = {}

        # --- Start Research Agent as asyncio.Task ---
        research_task: asyncio.Task[dict[str, Any]] | None = None
        if technologies:
            research_task = asyncio.create_task(
                self._run_phase(
                    "research",
                    {
                        "task": f"Research CVEs, exploit PoCs, bug bounty writeups, "
                        f"and penetration testing techniques for: "
                        f"{', '.join(technologies)}. Write all findings to the "
                        f"engagement runbook.",
                        "technologies": technologies,
                    },
                ),
                name="clinkz-concurrent-research",
            )
        else:
            results["research"] = {"status": "skipped", "reason": "no technologies"}

        # --- Start Scan Agent as asyncio.Task ---
        scan_content: dict[str, Any] = {
            "task": f"Map the complete attack surface of {targets_str}. "
            f"Crawl all endpoints, fuzz parameters, identify "
            f"suspicious behaviors and anomalies.",
            "recon_result": recon_result,
            "recon_findings": recon_result,
            "credentials": cred_data,
            "sessions": session_data,
        }
        if cookies:
            scan_content["session_cookies"] = cookies
        scan_task = asyncio.create_task(
            self._run_phase("scan", scan_content),
            name="clinkz-concurrent-scan",
        )

        # --- Wait for Scan to complete (Exploit needs scan results) ---
        self._logger.info("Waiting for Scan to complete before starting Exploit")
        try:
            scan_result = await scan_task
            results["scan"] = scan_result
            self._logger.info("Scan complete — %s", scan_result.get("status", "unknown"))
        except Exception as exc:
            self._logger.error("Scan failed: %s", exc)
            results["scan"] = {"status": "error", "error": str(exc)}

        # --- Wait for Research (may already be done) ---
        research_data: dict[str, Any] = {}
        if research_task is not None:
            try:
                research_result = await research_task
                results["research"] = research_result
                research_data = research_result
                self._logger.info(
                    "Research complete — %s", research_result.get("status", "unknown")
                )
            except Exception as exc:
                self._logger.error("Research failed (proceeding without): %s", exc)
                results["research"] = {"status": "error", "error": str(exc)}

        # --- Run Exploit with v2 models directly ---
        exploit_content: dict[str, Any] = {
            "task": f"Exploit all identified vulnerabilities on {targets_str}. "
            f"Check the runbook for techniques. Test all discovered endpoints. "
            f"Validate findings and chain exploits for maximum impact.",
            "recon_result": recon_result,
            "credentials": cred_data,
            "sessions": session_data,
        }

        # Pass v2 ScanResult directly (the exploit agent parses it via _parse_scan_result)
        if results.get("scan", {}).get("status") != "error":
            scan_result_data = results["scan"].get("result")
            if scan_result_data:
                exploit_content["scan_result"] = scan_result_data

        # Pass v2 ResearchResult directly (the exploit agent parses it via _parse_research_result)
        if research_data.get("result"):
            exploit_content["research_result"] = research_data["result"]

        if cookies:
            exploit_content["session_cookies"] = cookies
            # /tmp path is inside the clinkz-tools Docker container — predictable
            # by design (subsequent curl calls reuse the jar); UUID prefix keeps
            # engagements isolated and the container is single-tenant.
            exploit_content["cookie_jar_path"] = f"/tmp/clinkz_{self._engagement_id}_cookies.txt"  # nosec B108
            exploit_content["authenticated_as"] = authenticated_as
            exploit_content["task"] = (
                f"You are already authenticated as '{authenticated_as}'. "
                f"Use the provided session cookies for ALL requests. "
                f"Do NOT attempt to login again.\n\n" + exploit_content["task"]
            )

        self._logger.info("Starting Exploit with v2 scan + research results")
        try:
            exploit_result = await self._run_phase("exploit", exploit_content)
            results["exploit"] = exploit_result
        except Exception as exc:
            self._logger.error("Exploit failed: %s", exc)
            results["exploit"] = {"status": "error", "error": str(exc)}

        # Fill in any missing results
        for name in ("research", "scan", "exploit"):
            if name not in results:
                results[name] = {"status": "not_started"}

        return results

    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------

    async def _run_phase(
        self,
        agent_type: str,
        task_content: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a single phase: spin up agent, wait for RESULT, handle QUERYs.

        Spins up the agent with the given task. Then waits for messages:
        - RESULT: phase complete, shut down agent, return result
        - QUERY: use LLM to formulate answer from state, route back to agent
        - ERROR: log and return error result
        - STATUS (stopped): agent stopped itself, return what we have

        If an agent sends a QUERY requesting cross-phase data (e.g., Exploit
        asks for more recon), the Orchestrator may re-spin a different agent
        for a targeted sub-task, capped at MAX_CROSS_PHASE_RESPINS.

        Args:
            agent_type: Agent to spin up ("recon", "scan", "exploit", etc.).
            task_content: Task payload dict for the agent.

        Returns:
            Result dict from the agent (or error info).

        Raises:
            TimeoutError: If the agent does not respond within _PHASE_TIMEOUT.
        """
        assert self._bus is not None
        assert self._lifecycle is not None
        assert self._engagement_id is not None

        self._logger.info("Starting phase: %s", agent_type)

        # Build and send the initial task
        task_msg = AgentMessage.task(
            from_agent=ORCHESTRATOR,
            to_agent=agent_type,
            engagement_id=self._engagement_id,
            content=task_content,
        )

        await self._lifecycle.spin_up(agent_type, task_msg)

        # Wait for phase completion
        deadline = asyncio.get_event_loop().time() + _PHASE_TIMEOUT
        result: dict[str, Any] = {}

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                self._logger.error("Phase '%s' timed out", agent_type)
                try:
                    await self._lifecycle.shut_down(agent_type)
                except Exception:
                    pass
                return {"status": "timeout", "agent": agent_type}

            # Drain pending messages for orchestrator
            pending = await self._bus.get_pending(ORCHESTRATOR)

            if not pending:
                # Check if agent is still running
                running = self._lifecycle.get_running_agents()
                if agent_type not in running:
                    self._logger.warning("Agent '%s' stopped without sending RESULT", agent_type)
                    return result or {"status": "agent_stopped", "agent": agent_type}
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            handled_own = False
            for msg in pending:
                # Messages from other agents must be re-queued so the
                # correct _run_phase coroutine can process them.
                # Only re-queue if the sender is still a running agent,
                # otherwise the message will loop forever unclaimed.
                if msg.from_agent != agent_type:
                    running = self._lifecycle.get_running_agents()
                    if msg.from_agent in running:
                        self._logger.debug(
                            "Re-queuing message from %s (intended for %s phase runner)",
                            msg.from_agent,
                            msg.from_agent,
                        )
                        await self._bus.requeue(ORCHESTRATOR, msg)
                    else:
                        self._logger.debug(
                            "Dropping stale message from %s (agent no longer running)",
                            msg.from_agent,
                        )
                    continue
                handled_own = True

                if msg.message_type in (MessageType.RESULT, "result"):
                    self._logger.info("Phase '%s' completed with result", agent_type)
                    result = msg.content
                    try:
                        await self._lifecycle.shut_down(agent_type)
                    except Exception:
                        pass
                    return result

                elif msg.message_type in (MessageType.ERROR, "error"):
                    self._logger.error(
                        "Phase '%s' error: %s",
                        agent_type,
                        msg.content.get("error", "unknown"),
                    )
                    result = {
                        "status": "error",
                        "agent": agent_type,
                        "error": msg.content.get("error", str(msg.content)),
                    }
                    try:
                        await self._lifecycle.shut_down(agent_type)
                    except Exception:
                        pass
                    return result

                elif msg.message_type in (MessageType.QUERY, "query"):
                    # Agent needs cross-phase data
                    await self._handle_query(agent_type, msg)

                elif msg.message_type in (MessageType.STATUS, "status"):
                    status = msg.content.get("status", "")
                    if status == "stopped":
                        self._logger.info("Agent '%s' reported stopped", msg.from_agent)
                        if msg.from_agent == agent_type:
                            return result or {
                                "status": "agent_stopped",
                                "agent": agent_type,
                            }

            # If we only re-queued other agents' messages (nothing for us),
            # sleep to avoid a busy-loop when multiple _run_phase tasks share
            # the same orchestrator queue.
            if not handled_own:
                await asyncio.sleep(_POLL_INTERVAL)

    # ------------------------------------------------------------------
    # Query handler (cross-phase data requests)
    # ------------------------------------------------------------------

    async def _handle_query(
        self,
        requesting_agent: str,
        query_msg: AgentMessage,
    ) -> None:
        """Handle a QUERY from an agent requesting cross-phase data.

        Uses LLM reasoning to decide the best response strategy:
        1. If the query explicitly requests another agent (``needs_agent`` key)
           AND re-spins are available, spin up that agent for a targeted sub-task.
        2. Otherwise, use the LLM to reason about who should answer and respond
           from the engagement state.

        The LLM reasons about routing like a human coordinator:
        "The Exploit Agent is asking about the technology behind /upload.php.
        This is a recon question. Let me check if I have this data in state,
        otherwise I'll re-spin the Recon Agent with a targeted task."

        Args:
            requesting_agent: The agent that sent the query.
            query_msg: The QUERY message.
        """
        assert self._state is not None
        assert self._bus is not None
        assert self._engagement_id is not None

        query_text = query_msg.content.get("query", json.dumps(query_msg.content))
        self._logger.info("Handling query from '%s': %s", requesting_agent, query_text[:200])

        # Check if the agent explicitly requests a cross-phase re-spin
        needs_respin = query_msg.content.get("needs_agent")

        # If no explicit target, use LLM to reason about whether a re-spin is needed
        if not needs_respin and self._cross_phase_respins < MAX_CROSS_PHASE_RESPINS:
            try:
                context = await self._gather_state_context()
                routing_prompt = (
                    f"An agent ({requesting_agent}) is asking:\n\n"
                    f'"{query_text}"\n\n'
                    f"Current engagement state:\n{context}\n\n"
                    f"Can you answer this question from the available state data? "
                    f"If yes, respond with: ANSWER_FROM_STATE\n"
                    f"If no and this requires a recon task, respond with: RESPIN_RECON\n"
                    f"If no and this requires a scan task, respond with: RESPIN_SCAN\n"
                    f"If no and this requires an exploit task, respond with: RESPIN_EXPLOIT\n"
                    f"Respond with ONLY the action keyword."
                )
                routing_decision = (await self._llm.generate_text(routing_prompt)).strip()
                self._logger.info(
                    "Orchestrator routing decision for query from '%s': %s",
                    requesting_agent,
                    routing_decision,
                )
                if "RESPIN_RECON" in routing_decision:
                    needs_respin = "recon"
                elif "RESPIN_SCAN" in routing_decision:
                    needs_respin = "scan"
                elif "RESPIN_EXPLOIT" in routing_decision:
                    needs_respin = "exploit"
            except Exception as exc:
                self._logger.warning("LLM routing decision failed: %s — answering from state", exc)

        # Execute cross-phase re-spin if decided
        if needs_respin and self._cross_phase_respins < MAX_CROSS_PHASE_RESPINS:
            self._cross_phase_respins += 1
            self._logger.info(
                "Cross-phase re-spin %d/%d: spinning '%s' for targeted sub-task",
                self._cross_phase_respins,
                MAX_CROSS_PHASE_RESPINS,
                needs_respin,
            )
            sub_result = await self._run_phase(
                needs_respin,
                {
                    "task": query_text,
                    "scope": self._scope.model_dump() if self._scope else {},
                },
            )
            # Route sub-task result back to the requesting agent
            response_msg = AgentMessage.response(
                from_agent=ORCHESTRATOR,
                to_agent=requesting_agent,
                engagement_id=self._engagement_id,
                content={"response": sub_result, "sub_task_agent": needs_respin},
                parent_message_id=query_msg.id,
            )
            await self._bus.send(response_msg)
            return

        # Answer from state using LLM
        try:
            context = await self._gather_state_context()
            prompt = (
                f"An agent ({requesting_agent}) is asking:\n\n"
                f"{query_text}\n\n"
                f"Here is the current engagement state:\n{context}\n\n"
                f"Provide a concise, factual response based on the available data. "
                f"If you don't have the information, say so clearly."
            )
            response_text = await self._llm.generate_text(prompt)
        except Exception as exc:
            self._logger.warning("LLM query response failed: %s", exc)
            response_text = f"Could not generate response: {exc}"

        response_msg = AgentMessage.response(
            from_agent=ORCHESTRATOR,
            to_agent=requesting_agent,
            engagement_id=self._engagement_id,
            content={"response": response_text},
            parent_message_id=query_msg.id,
        )
        await self._bus.send(response_msg)

    # ------------------------------------------------------------------
    # Default credential testing
    # ------------------------------------------------------------------

    async def _try_default_credentials(
        self,
        recon_result: dict[str, Any],
    ) -> None:
        """Try default credentials for technologies identified during recon.

        Seeds the credential store with defaults for each identified technology,
        then uses the HTTP client tool to attempt login on discovered endpoints.
        Valid credentials and sessions are stored for handoff to later phases.

        Args:
            recon_result: Result dict from the recon phase.
        """
        assert self._cred_store is not None
        assert self._state is not None
        assert self._engagement_id is not None

        # Extract identified technologies from recon results
        technologies = self._extract_technologies(recon_result)
        if not technologies:
            self._logger.info("No technologies identified — skipping default cred check")
            return

        self._logger.info("Trying default credentials for: %s", ", ".join(technologies))

        # Cache login URL lookups per target to avoid repeated 5s-timeout probes
        login_url_cache: dict[str, str | None] = {}
        # Track tested (url, user, pass) combos to skip duplicates across technologies
        tested_combos: set[tuple[str, str, str]] = set()

        for tech in technologies:
            # Seed defaults into the credential store
            cred_ids = await self._cred_store.seed_defaults(self._engagement_id, tech)
            if not cred_ids:
                continue

            # Get the seeded credentials
            creds = await self._cred_store.get(self._engagement_id, technology=tech)
            untested = [c for c in creds if c.valid is None]

            # Find login URL once per technology (cached per target base)
            cache_key = tech
            if cache_key not in login_url_cache:
                login_url_cache[cache_key] = await self._find_login_url(recon_result, tech)
            login_url = login_url_cache[cache_key]
            if not login_url:
                continue

            for cred in untested:
                combo = (login_url, cred.username, cred.password)
                if combo in tested_combos:
                    self._logger.debug(
                        "Skipping duplicate cred test: %s:%s @ %s",
                        cred.username,
                        "***",
                        login_url,
                    )
                    continue
                tested_combos.add(combo)

                # Try the credential via HTTP client
                success = await self._attempt_login(
                    login_url, cred.username, cred.password, cred.id
                )
                if success:
                    self._logger.info(
                        "DEFAULT CRED VALID: %s:%s on %s (%s)",
                        cred.username,
                        "***",
                        login_url,
                        tech,
                    )
                else:
                    await self._cred_store.mark_invalid(cred.id)

    def _extract_technologies(self, recon_result: dict[str, Any]) -> list[str]:
        """Extract technology names from recon results.

        Searches multiple levels of the result dict:
        0. v2 ReconResult format: ``result.tech_stack.technologies`` (list of dicts).
        1. Top-level ``tech`` / ``technologies`` / ``tech_stack`` keys (v1 format).
        2. Nested host/service dicts (``hosts[].services[].product``).
        3. Free-text ``summary`` field — regex-matches common technology names.

        Args:
            recon_result: Recon phase result dict.

        Returns:
            Deduplicated list of technology name strings.
        """
        import re

        techs: set[str] = set()

        # v2 ReconResult format: result.tech_stack.technologies is list of dicts
        nested_result = recon_result.get("result")
        if isinstance(nested_result, dict):
            ts = nested_result.get("tech_stack")
            if isinstance(ts, dict):
                for tech_item in ts.get("technologies", []):
                    if isinstance(tech_item, dict):
                        name = tech_item.get("name", "").strip()
                        version = tech_item.get("version") or ""
                        if name:
                            tech_str = f"{name} {version}".strip().lower()
                            techs.add(tech_str)
            # Extract from web_info.technologies_found (body fingerprinting)
            web_info = nested_result.get("web_info")
            if isinstance(web_info, dict):
                for wt in web_info.get("technologies_found", []):
                    if isinstance(wt, str) and wt.strip():
                        techs.add(wt.strip().lower())
            # Also extract from nested services
            svc_data = nested_result.get("services")
            if isinstance(svc_data, dict):
                for svc in svc_data.get("services", []):
                    if isinstance(svc, dict):
                        svc_name = svc.get("service_name", "").strip()
                        version = (svc.get("version") or "").strip()
                        if svc_name and svc_name.lower() not in _GENERIC_SERVICE_NAMES:
                            techs.add(svc_name.lower())
                        if version and svc_name:
                            techs.add(f"{svc_name} {version}".strip().lower())

        # Direct tech lists (v1 format)
        for key in ("tech", "technologies", "tech_stack"):
            val = recon_result.get(key)
            if isinstance(val, list):
                techs.update(str(t).lower().strip() for t in val if str(t).strip())
            elif isinstance(val, str) and val.strip():
                techs.add(val.lower().strip())

        # Nested in host/service results — look for product/version in services
        for key in ("hosts", "services", "results"):
            items = recon_result.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                # Direct tech keys on the item
                for sub_key in ("tech", "technologies", "technology", "tech_stack"):
                    sub_val = item.get(sub_key)
                    if isinstance(sub_val, list):
                        techs.update(str(t).lower().strip() for t in sub_val if str(t).strip())
                    elif isinstance(sub_val, str) and sub_val.strip():
                        techs.add(sub_val.lower().strip())
                # Services with product/version (nmap-style output)
                for svc in item.get("services") or []:
                    if not isinstance(svc, dict):
                        continue
                    product = svc.get("product", "").strip()
                    version = svc.get("version", "").strip()
                    if product:
                        tech = f"{product} {version}".strip().lower()
                        techs.add(tech)
                    name = svc.get("name", "").strip()
                    if name and name.lower() not in _GENERIC_SERVICE_NAMES:
                        techs.add(name.lower())

        # Parse the summary text for common technology names
        summary = recon_result.get("summary", "")
        if isinstance(summary, str) and summary:
            # Match well-known technologies (case-insensitive)
            known_patterns = [
                r"apache(?:\s+httpd)?(?:\s+[\d.]+)?",
                r"nginx(?:\s+[\d.]+)?",
                r"php(?:\s+[\d.]+)?",
                r"mysql(?:\s+[\d.]+)?",
                r"mariadb(?:\s+[\d.]+)?",
                r"postgresql(?:\s+[\d.]+)?",
                r"dvwa",
                r"tomcat(?:\s+[\d.]+)?",
                r"iis(?:\s+[\d.]+)?",
                r"wordpress(?:\s+[\d.]+)?",
                r"node\.?js(?:\s+[\d.]+)?",
                r"express(?:\s+[\d.]+)?",
                r"django(?:\s+[\d.]+)?",
                r"flask(?:\s+[\d.]+)?",
                r"openssh(?:\s+[\d.]+)?",
                r"openssl(?:\s+[\d.]+)?",
                r"jquery(?:\s+[\d.]+)?",
                r"bootstrap(?:\s+[\d.]+)?",
                r"react(?:\s+[\d.]+)?",
                r"vue\.?js(?:\s+[\d.]+)?",
                r"jenkins(?:\s+[\d.]+)?",
                r"grafana(?:\s+[\d.]+)?",
                r"redis(?:\s+[\d.]+)?",
                r"mongodb(?:\s+[\d.]+)?",
                r"elasticsearch(?:\s+[\d.]+)?",
                r"vsftpd(?:\s+[\d.]+)?",
                r"proftpd(?:\s+[\d.]+)?",
            ]
            for pattern in known_patterns:
                for match in re.finditer(pattern, summary, re.IGNORECASE):
                    techs.add(match.group(0).strip().lower())

        # Remove empty strings
        techs.discard("")

        return sorted(techs)

    async def _log_playbook_matches(
        self,
        persistent_kb: PersistentKnowledgeBase,
        technologies: list[str],
    ) -> None:
        """Query persistent KB for playbook entries matching discovered tech stack.

        Logs Tier 1 universal entries and Tier 2 technology-specific entries
        that match the discovered technologies. This helps downstream agents
        prioritize their testing.

        Args:
            persistent_kb: The persistent knowledge base instance.
            technologies: List of technology name strings from recon.
        """
        try:
            # Tier 1 universal tests (always applicable)
            tier1 = await persistent_kb.get_tier1_tests()
            self._logger.info("Playbook: %d Tier 1 universal tests available", len(tier1))

            # Tier 2 tech-matched tests for each discovered technology
            matched_count = 0
            for tech in technologies:
                tier2 = await persistent_kb.get_tier2_tests(tech)
                if tier2:
                    matched_count += len(tier2)
                    self._logger.info(
                        "Playbook: %d Tier 2 entries matched for '%s': %s",
                        len(tier2),
                        tech,
                        [e["technique_name"] for e in tier2[:5]],
                    )

            # Also query by full technology string for broader matches
            for tech in technologies:
                entries = await persistent_kb.get_playbook_for_technology(tech)
                for entry in entries:
                    if entry.get("tier") not in (1, 2):
                        matched_count += 1

            self._logger.info(
                "Playbook summary: %d Tier 1 + %d tech-matched entries for %d technologies",
                len(tier1),
                matched_count,
                len(technologies),
            )
        except Exception as exc:
            self._logger.warning("Playbook matching failed: %s", exc)

    async def _find_login_url(
        self,
        recon_result: dict[str, Any],
        technology: str,
        scan_result: dict[str, Any] | None = None,
    ) -> str | None:
        """Find a login URL using a multi-strategy fallback chain.

        Strategies (tried in order, first hit wins):
        1. Explicit ``login_urls`` dict keyed by technology.
        2. Structured URL fields in recon/scan results containing login paths.
        3. Free-text search of recon ``summary`` for URLs with login keywords.
        4. Discovered targets/endpoints in the state store with login in path.
        5. Probe common login paths on each scope target with HEAD requests.
        6. Fall back to the root URL as the login page.

        Args:
            recon_result: Recon phase result dict.
            technology: Technology name to look for (may be empty).
            scan_result: Optional scan phase result dict for additional URL sources.

        Returns:
            Login URL string, or None if not found.
        """
        import re as _re

        login_path_hints = ("/login", "/admin", "/wp-login", "/manager", "/signin", "/auth")

        # --- Strategy 1: explicit login_urls dict ---
        login_urls = recon_result.get("login_urls", {})
        if isinstance(login_urls, dict):
            if technology and technology in login_urls:
                return login_urls[technology]
            # Return any URL from the dict
            for _tech, url in login_urls.items():
                if url:
                    return url

        # --- Strategy 2: structured URL fields in recon + scan results ---
        sources = [recon_result]
        if scan_result:
            sources.append(scan_result)
        for source in sources:
            for key in ("hosts", "results", "endpoints", "urls"):
                items = source.get(key)
                if isinstance(items, list):
                    for item in items:
                        url = ""
                        if isinstance(item, dict):
                            url = item.get("url", "")
                        elif isinstance(item, str):
                            url = item
                        if url and any(p in url.lower() for p in login_path_hints):
                            return url

        # --- Strategy 3: regex search of free-text summary for URLs ---
        for source in sources:
            summary = source.get("summary", "")
            if isinstance(summary, str) and summary:
                # Find URLs in free text
                url_matches = _re.findall(r'https?://[^\s<>"\']+', summary)
                for candidate in url_matches:
                    if any(p in candidate.lower() for p in login_path_hints):
                        return candidate

        # --- Strategy 4: search state store targets/endpoints ---
        if self._state and self._engagement_id:
            try:
                targets = await self._state.get_targets(self._engagement_id)
                for t in targets:
                    ip = t.get("ip", "")
                    for hostname in t.get("hostnames", []):
                        if any(p in str(hostname).lower() for p in login_path_hints):
                            return str(hostname)
                    if any(p in str(ip).lower() for p in login_path_hints):
                        return str(ip)
            except Exception:
                pass

        # --- Strategy 5: construct and probe common login paths ---
        base_url = recon_result.get("base_url") or recon_result.get("url")
        probe_bases: list[str] = []
        if base_url:
            probe_bases.append(base_url.rstrip("/"))
        if self._scope:
            for t in self._scope.targets:
                if t.value.startswith(("http://", "https://")):
                    candidate = t.value
                else:
                    candidate = f"http://{t.value}"
                if candidate.rstrip("/") not in [b.rstrip("/") for b in probe_bases]:
                    probe_bases.append(candidate)

        probe_paths = ["/login.php", "/login", "/signin", "/admin", "/auth", "/wp-login.php"]
        for base in probe_bases:
            for path in probe_paths:
                probe_url = f"{base.rstrip('/')}{path}"
                status = await self._probe_url(probe_url)
                if status and status < 400:
                    self._logger.info("Probed login URL found: %s (status %d)", probe_url, status)
                    return probe_url

        # --- Strategy 6: fall back to root URL ---
        if probe_bases:
            root_url = probe_bases[0]
            self._logger.info("Falling back to root URL as login page: %s", root_url)
            return root_url

        return None

    async def _attempt_login(
        self,
        url: str,
        username: str,
        password: str,
        credential_id: str,
    ) -> bool:
        """Attempt a login with the given credentials via WebAuthenticator.

        Uses deterministic CSRF-aware login flow (GET→extract→POST) instead
        of manual HTTP requests.  On success, marks the credential as valid
        and stores the session.

        Args:
            url: Login URL.
            username: Username to try.
            password: Password to try.
            credential_id: ID of the credential being tested.

        Returns:
            True if login was successful.
        """
        assert self._cred_store is not None
        assert self._engagement_id is not None

        try:
            from clinkz.tools.auth import WebAuthenticator

            authenticator = WebAuthenticator(
                scope=self._scope,
                engagement_id=self._engagement_id,
            )

            result = await authenticator.authenticate(url, username, password)

            if result.success:
                await self._cred_store.mark_valid(
                    credential_id,
                    session_cookies=result.session_cookies,
                    # Container-internal path; see _cookie_jar_path() in tools/http_client.py
                    cookie_jar_path=f"/tmp/clinkz_{self._engagement_id}_cookies.txt",  # nosec B108
                    engagement_id=self._engagement_id,
                    agent="orchestrator",
                )
                return True

        except Exception as exc:
            self._logger.debug(
                "Login attempt failed for %s:%s @ %s: %s",
                username,
                "***",
                url,
                exc,
            )

        return False

    async def _verify_and_refresh_session(
        self,
        login_url: str,
        sessions: list[dict[str, Any]],
        valid_creds: list[Any],
    ) -> tuple[dict[str, str], str]:
        """Verify a session is still valid; re-authenticate if not.

        Called before handing off to the Exploit Agent to ensure the
        session cookies will actually work.

        Args:
            login_url: Login URL for re-authentication.
            sessions: Session dicts from state store.
            valid_creds: Valid Credential objects.

        Returns:
            Tuple of (cookies_dict, authenticated_as_username).
        """
        assert self._engagement_id is not None

        if not sessions:
            return {}, ""

        latest = sessions[-1]
        cookies = latest.get("cookies", {})
        if not cookies:
            return {}, ""

        # Find who we authenticated as
        cred_id = latest.get("metadata", {}).get("credential_id", "")
        authenticated_as = "unknown"
        matched_cred = None
        for c in valid_creds:
            if c.id == cred_id:
                authenticated_as = c.username
                matched_cred = c
                break

        # Verify the session
        from clinkz.tools.auth import WebAuthenticator

        authenticator = WebAuthenticator(
            scope=self._scope,
            engagement_id=self._engagement_id,
        )

        # Use the login URL base to check a protected page
        from urllib.parse import urlparse

        parsed = urlparse(login_url)
        check_url = f"{parsed.scheme}://{parsed.netloc}/"

        session_valid = await authenticator.verify_session(check_url, cookies)

        if session_valid:
            self._logger.info("Session still valid for '%s'", authenticated_as)
            return cookies, authenticated_as

        # Session expired — re-authenticate if we have credentials
        self._logger.warning("Session expired — attempting re-authentication")

        if matched_cred:
            result = await authenticator.authenticate(
                login_url, matched_cred.username, matched_cred.password
            )
            if result.success:
                self._logger.info("Re-authentication successful for '%s'", matched_cred.username)
                # Update the stored session
                if self._cred_store:
                    await self._cred_store.mark_valid(
                        matched_cred.id,
                        session_cookies=result.session_cookies,
                        # Container-internal path; see _cookie_jar_path() in tools/http_client.py
                        cookie_jar_path=f"/tmp/clinkz_{self._engagement_id}_cookies.txt",  # nosec B108
                        engagement_id=self._engagement_id,
                        agent="orchestrator",
                    )
                return result.session_cookies, matched_cred.username

        self._logger.warning("Re-authentication failed — proceeding without session")
        return {}, ""

    # ------------------------------------------------------------------
    # Fallback recon from scope targets
    # ------------------------------------------------------------------

    def _build_fallback_recon(self, scope: EngagementScope) -> dict[str, Any]:
        """Construct a minimal recon result from scope targets when recon fails.

        Parses URL targets to infer ports, services, and basic tech stack
        so downstream agents have something to work with.
        """
        from urllib.parse import urlparse

        target_val = scope.targets[0].value if scope.targets else "unknown"
        parsed = urlparse(target_val) if "://" in target_val else None

        port = 80
        scheme = "http"
        if parsed and parsed.hostname:
            scheme = parsed.scheme or "http"
            port = parsed.port or (443 if scheme == "https" else 80)

        svc_name = "https" if scheme == "https" else "http"
        fallback = ReconResult(
            target=target_val,
            ports=PortScanResult(open_ports=[port], tool_used="fallback_inference"),
            services=ServiceScanResult(
                services=[ReconService(port=port, protocol="tcp", service_name=svc_name)],
                tool_used="fallback_inference",
            ),
            tech_stack=TechStack(technologies=[]),
            web_info=WebReconResult(),
            llm_summary="Fallback recon — LLM unavailable, inferred from scope target URL.",
        )
        return {"result": fallback.model_dump(mode="json"), "status": "fallback"}

    # ------------------------------------------------------------------
    # URL probing helper
    # ------------------------------------------------------------------

    async def _probe_url(self, url: str) -> int | None:
        """Send a HEAD request to *url* and return the HTTP status code.

        Returns ``None`` on any failure (timeout, connection refused, etc.).
        Uses a 10-second timeout (some targets like DVWA take ~5s for HEAD).
        Results are cached to avoid repeated slow probes of the same URL.

        This method is separated so that tests can trivially mock it.
        """
        if url in self._probe_cache:
            return self._probe_cache[url]

        try:
            from clinkz.tools.http_client import HTTPClientTool

            http = HTTPClientTool(
                scope=self._scope,
                timeout=10,
                engagement_id=self._engagement_id or "",
            )
            validated = http.validate_input({"url": url, "method": "HEAD"})
            raw = await asyncio.wait_for(http.execute(validated), timeout=10)
            parsed = http.parse_output(raw)
            result = parsed.status_code if parsed.status_code else None
        except Exception:
            result = None

        self._probe_cache[url] = result
        return result

    # ------------------------------------------------------------------
    # State context gathering (for LLM query responses)
    # ------------------------------------------------------------------

    async def _gather_state_context(self) -> str:
        """Build a summary of current engagement state for LLM context.

        Returns:
            Formatted string with targets, findings, credentials, and sessions.
        """
        assert self._state is not None
        assert self._engagement_id is not None

        lines: list[str] = []

        try:
            targets = await self._state.get_targets(self._engagement_id)
            lines.append(f"Targets: {len(targets)} discovered")
            for t in targets[:10]:
                lines.append(f"  - {json.dumps(t)[:200]}")
        except Exception:
            pass

        try:
            findings = await self._state.get_findings(self._engagement_id)
            lines.append(f"Findings: {len(findings)} total")
            for f in findings[:10]:
                title = f.get("title", "Untitled")
                sev = f.get("severity", "?")
                lines.append(f"  - [{sev}] {title}")
        except Exception:
            pass

        try:
            if self._cred_store:
                creds = await self._cred_store.get_all_valid(self._engagement_id)
                lines.append(f"Valid credentials: {len(creds)}")
                for c in creds:
                    lines.append(f"  - {c.username}:*** ({c.technology}) @ {c.url}")
        except Exception:
            pass

        try:
            sessions = await self._state.get_sessions(self._engagement_id)
            lines.append(f"Sessions: {len(sessions)}")
        except Exception:
            pass

        return "\n".join(lines) if lines else "No state data available."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_system_prompt() -> str:
    """Load the orchestrator system prompt template from the prompts directory.

    Returns:
        System prompt string.
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
