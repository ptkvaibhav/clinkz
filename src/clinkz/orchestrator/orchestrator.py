"""OrchestratorAgent — deterministic phase state machine with LLM reasoning within phases.

The Orchestrator drives a fixed phase sequence:
  1. RECON   — reconnaissance and information gathering
  2. CREDS   — try default credentials for identified technologies
  3. SCAN    — crawl, fuzz, and map the attack surface
  4. EXPLOIT — attempt exploitation of discovered vulnerabilities
  5. CRITIC  — validate findings before reporting
  6. REPORT  — generate the final pentest report

Phase order is HARDCODED — no LLM decides when to move between phases.
LLM is used ONLY for:
  - Formulating detailed task descriptions for agents
  - Answering agent QUERY messages with cross-phase context
  - Synthesizing results across phases

Cross-phase re-spins (e.g., Exploit asks for more recon) are handled as
exceptions within _run_phase(), capped at MAX_CROSS_PHASE_RESPINS per
engagement to prevent infinite loops.

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
from clinkz.knowledge.query import KnowledgeBase
from clinkz.llm.base import LLMClient
from clinkz.llm.factory import get_llm_client
from clinkz.models.scope import EngagementScope
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# How long to wait for an agent to produce a RESULT before timing out (seconds).
_PHASE_TIMEOUT = 600

# Maximum cross-phase re-spins per engagement (e.g., Exploit asks for more recon).
MAX_CROSS_PHASE_RESPINS = 3

# Poll interval when waiting for agent messages (seconds).
_POLL_INTERVAL = 1.0


# ---------------------------------------------------------------------------
# OrchestratorAgent
# ---------------------------------------------------------------------------


class OrchestratorAgent:
    """Deterministic phase orchestrator for an autonomous pentest engagement.

    The run() method follows a hardcoded sequence of phases. LLM reasoning
    is used within each phase (task formulation, query answering) but never
    for deciding phase order.

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

        # Cross-phase re-spin counter (shared across all phases)
        self._cross_phase_respins: int = 0

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, scope: EngagementScope) -> dict[str, Any]:
        """Execute a full pentest engagement for the given scope.

        Follows a deterministic phase sequence:
        RECON → default creds → SCAN → EXPLOIT → CRITIC → REPORT.

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
            engagement_id = await state.create_engagement(scope.name, scope.model_dump())
            bus = MessageBus(state=state)
            knowledge_base = KnowledgeBase()
            self._logger.info("KnowledgeBase loaded: %s", knowledge_base.stats())
            lifecycle = AgentLifecycleManager(
                bus=bus,
                llm=self._llm,
                scope=scope,
                state=state,
                engagement_id=engagement_id,
                knowledge_base=knowledge_base,
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

            summary: dict[str, Any] = {"status": "completed", "phases": {}}

            try:
                # PHASE 1: RECON (mandatory)
                targets_str = ", ".join(f"{t.value} ({t.type.value})" for t in scope.targets)
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

                # Between RECON and SCAN: try default credentials
                await self._try_default_credentials(recon_result)

                # Gather credentials and sessions for handoff
                valid_creds = await cred_store.get_all_valid(engagement_id)
                sessions = await state.get_sessions(engagement_id)
                cred_data = [c.model_dump() for c in valid_creds]
                session_data = sessions

                # PHASE 2: SCAN (mandatory)
                scan_result = await self._run_phase(
                    "scan",
                    {
                        "task": f"Map the complete attack surface of {targets_str}. "
                        f"Crawl all endpoints, fuzz parameters, identify "
                        f"suspicious behaviors and anomalies.",
                        "recon_findings": recon_result,
                        "credentials": cred_data,
                        "sessions": session_data,
                    },
                )
                summary["phases"]["scan"] = scan_result
                self._logger.info("PHASE 2 (SCAN) complete")

                # Refresh creds/sessions after scan (scan may have found new ones)
                valid_creds = await cred_store.get_all_valid(engagement_id)
                sessions = await state.get_sessions(engagement_id)
                cred_data = [c.model_dump() for c in valid_creds]
                session_data = sessions

                # Build exploit task with session handoff
                exploit_task: dict[str, Any] = {
                    "task": f"Exploit all identified vulnerabilities on {targets_str}. "
                    f"Research CVEs and PoCs for identified technologies. "
                    f"Validate findings and chain exploits for maximum impact.",
                    "recon_findings": recon_result,
                    "scan_findings": scan_result,
                    "credentials": cred_data,
                    "sessions": session_data,
                }

                # Verify and inject session cookies so Exploit Agent skips login
                if sessions:
                    # Find login URL for re-auth if needed
                    login_url = await self._find_login_url(
                        recon_result, "", scan_result=scan_result
                    )
                    if not login_url:
                        # Construct from first target
                        for t in scope.targets:
                            login_url = f"http://{t.value}/login"
                            break

                    cookies, authenticated_as = await self._verify_and_refresh_session(
                        login_url or "", sessions, valid_creds
                    )

                    if cookies:
                        exploit_task["session_cookies"] = cookies
                        exploit_task["cookie_jar_path"] = f"/tmp/clinkz_{engagement_id}_cookies.txt"
                        exploit_task["authenticated_as"] = authenticated_as
                        exploit_task["task"] = (
                            f"You are already authenticated as '{authenticated_as}'. "
                            f"Use the provided session cookies for ALL requests. "
                            f"Do NOT attempt to login again. Go straight to exploitation.\n\n"
                            f"Exploit all identified vulnerabilities on {targets_str}. "
                            f"Research CVEs and PoCs for identified technologies. "
                            f"Validate findings and chain exploits for maximum impact."
                        )
                        self._logger.info(
                            "VERIFIED session handoff to exploit "
                            "agent: authenticated_as=%s, cookies=%s",
                            authenticated_as,
                            list(cookies.keys()),
                        )

                # PHASE 3: EXPLOIT (mandatory)
                exploit_result = await self._run_phase("exploit", exploit_task)
                summary["phases"]["exploit"] = exploit_result
                self._logger.info("PHASE 3 (EXPLOIT) complete")

                # PHASE 4: CRITIC (mandatory)
                findings = await state.get_findings(engagement_id)
                critic_result = await self._run_phase(
                    "critic",
                    {
                        "task": "Validate all findings. Check CVSS accuracy, "
                        "eliminate false positives, verify evidence and "
                        "reproduction steps are complete.",
                        "findings": findings,
                    },
                )
                summary["phases"]["critic"] = critic_result
                self._logger.info("PHASE 4 (CRITIC) complete")

                # PHASE 5: REPORT (mandatory)
                report_result = await self._run_phase(
                    "report",
                    {
                        "task": "Generate a professional penetration test report. "
                        "Include executive summary, methodology, all validated "
                        "findings with evidence, and remediation recommendations.",
                        "engagement_id": engagement_id,
                    },
                )
                summary["phases"]["report"] = report_result
                self._logger.info("PHASE 5 (REPORT) complete")

            except Exception as exc:
                self._logger.error("Orchestrator failed: %s", exc, exc_info=True)
                await state.update_engagement_status(engagement_id, "failed")
                summary["status"] = "failed"
                summary["error"] = str(exc)
                return summary

            await state.update_engagement_status(engagement_id, "completed")

        self._logger.info("Engagement %s complete", engagement_id)
        return summary

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

            for msg in pending:
                if msg.from_agent != agent_type and msg.message_type != MessageType.STATUS:
                    # Message from a different agent (e.g., a sub-task result)
                    # Route it to the requesting agent if applicable
                    self._logger.debug(
                        "Received message from %s during %s phase",
                        msg.from_agent,
                        agent_type,
                    )

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

        for tech in technologies:
            # Seed defaults into the credential store
            cred_ids = await self._cred_store.seed_defaults(self._engagement_id, tech)
            if not cred_ids:
                continue

            # Get the seeded credentials
            creds = await self._cred_store.get(self._engagement_id, technology=tech)
            untested = [c for c in creds if c.valid is None]

            for cred in untested:
                # Find a login URL for this technology
                login_url = await self._find_login_url(recon_result, tech)
                if not login_url:
                    continue

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
        1. Top-level ``tech`` / ``technologies`` / ``tech_stack`` keys.
        2. Nested host/service dicts (``hosts[].services[].product``).
        3. Free-text ``summary`` field — regex-matches common technology names.

        Args:
            recon_result: Recon phase result dict.

        Returns:
            Deduplicated list of technology name strings.
        """
        import re

        techs: set[str] = set()

        # Direct tech lists
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
                    if name and name not in ("tcp", "udp", "unknown"):
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
                    cookie_jar_path=f"/tmp/clinkz_{self._engagement_id}_cookies.txt",
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
                        cookie_jar_path=f"/tmp/clinkz_{self._engagement_id}_cookies.txt",
                        engagement_id=self._engagement_id,
                        agent="orchestrator",
                    )
                return result.session_cookies, matched_cred.username

        self._logger.warning("Re-authentication failed — proceeding without session")
        return {}, ""

    # ------------------------------------------------------------------
    # URL probing helper
    # ------------------------------------------------------------------

    async def _probe_url(self, url: str) -> int | None:
        """Send a HEAD request to *url* and return the HTTP status code.

        Returns ``None`` on any failure (timeout, connection refused, etc.).
        Uses a short 5-second timeout to avoid blocking the pipeline.

        This method is separated so that tests can trivially mock it.
        """
        try:
            from clinkz.tools.http_client import HTTPClientTool

            http = HTTPClientTool(
                scope=self._scope,
                timeout=5,
                engagement_id=self._engagement_id or "",
            )
            validated = http.validate_input({"url": url, "method": "HEAD"})
            raw = await asyncio.wait_for(http.execute(validated), timeout=5)
            parsed = http.parse_output(raw)
            return parsed.status_code if parsed.status_code else None
        except Exception:
            return None

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
