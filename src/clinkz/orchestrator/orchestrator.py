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
import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.config import settings
from clinkz.credentials.store import CredentialStore
from clinkz.discovery import (
    DiscoveryEngine,
    SourceModel,
    TopologyContext,
    abstract_reaches_identity,
    derive_bundles_edges,
    derive_successor_edges,
    predicate_point_version,
)
from clinkz.engagement.artifact_scan import SCAN_REPORT_FILENAME, run_disclosure_gate
from clinkz.engagement.auth_state import (
    PROTECTED_PATH_CANDIDATES,
    AuthAssertion,
    AuthMechanism,
    SessionSentinel,
    assert_authenticated,
    detect_auth_mechanism,
)
from clinkz.engagement.gate import open_engagement
from clinkz.engagement.secrets import clear_secrets, register_secret
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.knowledge.query import KnowledgeBase
from clinkz.knowledge.seed_playbook import seed_tier1_tests
from clinkz.llm.base import LLMClient
from clinkz.llm.factory import get_llm_client
from clinkz.llm.fallback import (
    ResilientLLMClient,
    preflight_provider_available,
    validate_agent_chains,
)
from clinkz.models.engagement import AuthorizationRecord, CredentialSet, RoleCredential
from clinkz.models.finding import ExploitTask
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
from clinkz.oob import CallbackShape, OOBCollaborator
from clinkz.orchestrator.lifecycle import AgentLifecycleManager
from clinkz.orchestrator.target_resolver import resolve_target_for_docker_mode
from clinkz.safety.governor import EngagementGovernor, set_active_governor
from clinkz.state import StateStore
from clinkz.tools.docker_preflight import ensure_container_ready
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# How long to wait for an agent to produce a RESULT before timing out (seconds).
_PHASE_TIMEOUT = 600

# Exploit phase cooperative-stop margins (seconds), used ONLY when an explicit
# wall-clock budget is configured (``settings.exploit_phase_budget > 0``). By
# default there is NO phase budget: the full exploit task queue runs to
# completion and no category is starved by a phase-level clock — operation-level
# timeouts (per HTTP request, per tool subprocess, per LLM call) are the safety
# valve against a genuine hang. When a budget IS set, the Exploit Agent stops
# dispatching NEW tasks _EXPLOIT_STOP_MARGIN seconds before it elapses, lets the
# in-flight task finish, persists its findings, and returns cleanly; the
# orchestrator only force-kills if that return does not arrive within
# _EXPLOIT_HARD_GRACE seconds past the budget.
_EXPLOIT_STOP_MARGIN = 30
_EXPLOIT_HARD_GRACE = 30

# Research phase backstop. The Research Agent self-returns within
# settings.research_time_budget; if a single in-flight grounded call overruns,
# the orchestrator force-stops the phase this many seconds past the budget so
# Research can never hold the engagement open indefinitely.
_RESEARCH_PHASE_GRACE = 150

# Scan phase backstop, behind the Scan Agent's own settings.scan_time_budget.
# The generic phase timeout is a force-kill that DISCARDS the agent's return
# value, so on a scan it does not produce a smaller attack surface — it produces
# none, and the Exploit planner then invents endpoints instead of probing
# discovered ones. The agent self-caps first; this is only the wall behind it.
_SCAN_PHASE_GRACE = 180

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


class _ToolHttpProbe:
    """:class:`~clinkz.engagement.auth_state.HttpProbe` over the engagement's HTTP client.

    Routing auth detection and the authenticated-state assertion through
    :class:`~clinkz.tools.http_client.HTTPClientTool` rather than a bare client
    is what keeps them honest: they inherit the same scope enforcement, the same
    docker/host routing, and the same safety governor as every other request the
    engagement makes.

    Every probe here sets ``no_session=True`` except when session material is
    passed explicitly. That is the load-bearing detail of the whole assertion —
    the shared cookie jar would otherwise make the "anonymous" control carry the
    engagement's own session, and the comparison would prove nothing while
    looking like it proved everything.
    """

    #: Per-probe timeout. Auth detection walks a candidate list, so the default
    #: 300s tool timeout would let one unreachable host stall the engagement for
    #: an hour before recon's own findings were ever used.
    PROBE_TIMEOUT = 10

    def __init__(self, scope: Any, engagement_id: str) -> None:
        self._scope = scope
        self._engagement_id = engagement_id

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> Any:
        return await self._send(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "cookies": cookies or {},
                "follow_redirects": follow_redirects,
                "no_session": not (cookies or headers),
            }
        )

    async def post_json(self, url: str, payload: dict[str, str]) -> Any:
        return await self._send(
            {
                "method": "POST",
                "url": url,
                "headers": {"Content-Type": "application/json", "Accept": "application/json"},
                "body": json.dumps(payload),
                "follow_redirects": False,
                "no_session": True,
            }
        )

    async def _send(self, args: dict[str, Any]) -> Any:
        from clinkz.engagement.auth_state import ProbeResponse
        from clinkz.tools.http_client import HTTPClientTool

        tool = HTTPClientTool(
            scope=self._scope,
            engagement_id=self._engagement_id,
            stage="auth",
            timeout=self.PROBE_TIMEOUT,
        )
        try:
            validated = tool.validate_input(args)
            parsed = tool.parse_output(await tool.execute(validated))
        except Exception as exc:  # noqa: BLE001 — a probe failure is data, not a crash
            return ProbeResponse(error=str(exc))
        return ProbeResponse(
            status=parsed.status_code,
            headers=parsed.response_headers,
            body=parsed.response_body,
            error=parsed.error,
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
        credentials: CredentialSet | None = None,
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

        # P6 out-of-band collaborator (provisioned per engagement when opted in;
        # None on the default black-box floor). Held for teardown in run()'s finally.
        self._oob_collaborator: OOBCollaborator | None = None

        # Persistent knowledge base (created during run())
        self._persistent_kb: PersistentKnowledgeBase | None = None

        # Cross-phase re-spin counter (shared across all phases)
        self._cross_phase_respins: int = 0

        # Cache for _probe_url results to avoid repeated slow HTTP HEAD requests
        self._probe_cache: dict[str, int | None] = {}

        # ---- Productization P1 --------------------------------------------
        # Operator-supplied credentials, one entry per role. Held here and NEVER
        # attached to the scope: the scope is model_dump()-ed into the state
        # store at engagement creation, and a credential set must not be.
        self._credentials: CredentialSet = credentials or CredentialSet()
        self._authorization: AuthorizationRecord | None = None
        self._governor: EngagementGovernor | None = None
        # Watches every response for signs the session has been lost, so half an
        # engagement cannot run silently unauthenticated.
        self._session_sentinel = SessionSentinel()
        # role → {cookies, headers, username, assertion}
        self._role_sessions: dict[str, dict[str, Any]] = {}
        self._auth_assertion: AuthAssertion | None = None
        self._auth_mechanism: AuthMechanism = AuthMechanism.NONE
        self._reauth_credential: RoleCredential | None = None
        self._reauth_login_url: str = ""
        # The login request shape the authenticator PROVED against this target
        # (url + method + content type + body field names), handed to Scan so
        # the credential-attack classes have a real injection point on it.
        # ``None`` until a role authenticates; never populated by a guess.
        self._proven_login: dict[str, Any] | None = None
        # Scan, Research and Exploit poll the same sentinel concurrently, so the
        # verify-and-refresh sequence is serialised. Two simultaneous re-logins
        # would race to write _role_sessions and push the loser's token.
        self._session_reauth_lock = asyncio.Lock()

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

        Raises:
            AuthorizationRequiredError: The scope carries no authorization record.
            EngagementWindowClosedError: Now is outside the authorized window.
        """
        # THE GATE. Before docker, before state, before a single packet: an
        # engagement without a named authorizing party is not an engagement.
        # This is the refusal that makes the authorization record a required
        # input rather than a flag with a default — there is no path to a tool
        # call that does not pass through here.
        self._authorization = open_engagement(scope)

        # Register operator-supplied secrets so every artifact writer redacts
        # them. The primary guarantee is that no writer is ever handed a
        # password; this is the second layer, for the route nobody thought of.
        for secret in self._credentials.secrets():
            register_secret(secret)

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
            engagement_id = await state.create_engagement(scope.name, scope.model_dump(mode="json"))
            # Open the engagement-scoped trace writer before any agents spin up
            # so tool/LLM/handoff events from the very first phase are captured.
            trace_writer = TraceWriter(engagement_id=engagement_id)
            set_active_trace_writer(trace_writer)
            self._logger.info("TraceWriter opened: %s", trace_writer.path)

            # Install the production safety rails for this engagement. Every
            # outbound request now passes through the governor: paced, capped,
            # classified, logged if it mutates, and stopped the moment the kill
            # switch appears or the target starts blocking. Uninstalled in the
            # finally below so it can never leak into a later engagement or a
            # test — the rails govern an engagement, not the process.
            governor = EngagementGovernor(
                engagement_id,
                scope.safety,
                window=scope.window,
            )
            governor.add_response_observer(self._session_sentinel.observe)
            set_active_governor(governor)
            self._governor = governor
            self._logger.info(
                "Safety rails active — %.1f req/s, %d concurrent, halt-on-blocking=%s, "
                "kill switch: %s",
                scope.safety.max_requests_per_second,
                scope.safety.max_concurrent_requests,
                scope.safety.halt_on_blocking,
                governor.halt_path,
            )

            # In docker tool-exec mode, agents and tools execute inside the
            # clinkz-tools container — so a target like http://localhost:8080
            # would resolve to the tools container itself, not the sibling
            # DVWA/Juice Shop container. Rewrite localhost targets to the
            # publishing container's network alias here so every downstream
            # agent sees a reachable address.
            scope = await resolve_target_for_docker_mode(
                scope, self_container=settings.docker_container
            )
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

            # Credit pre-flight: detect a depleted/unavailable Gemini key ONCE
            # up front instead of letting every agent's first call storm 429s
            # before falling back. When Gemini is down and Anthropic can carry
            # the engagement, exclude Gemini from every agent's chain so the
            # whole run completes transparently on Anthropic — including the
            # recon tech-stack extraction the deterministic auth flow depends on
            # (auth itself makes no LLM calls; it silently degraded last run
            # only because depleted-Gemini recon starved it of technologies).
            exclude_providers: set[str] = set()
            gemini_keyed = bool(
                settings.gemini_api_key
                or settings.google_api_key
                or os.getenv("GEMINI_API_KEY")
                or os.getenv("GOOGLE_API_KEY")
            )
            anthropic_keyed = bool(settings.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY"))
            gemini_ok = (
                await preflight_provider_available("gemini")
                if (gemini_keyed and anthropic_keyed)
                else True
            )
            if not gemini_ok:
                exclude_providers.add("gemini")
                self._logger.warning(
                    "Gemini unavailable (credit pre-flight failed) — running "
                    "engagement on Anthropic fallback for all agents"
                )

            # Build per-agent LLM clients from env-var config
            agent_llms = self._build_agent_llms(exclude_providers=exclude_providers)

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

            # P6 out-of-band collaborator (disabled by default). Provisioned +
            # health-checked here alongside the other preflights; a healthy one is
            # wired onto the Exploit agent so its SSRF blind branch can confirm
            # out-of-band. A down / disabled collaborator leaves the black-box floor
            # intact (blind hypotheses defer). Torn down in the engagement finally.
            self._oob_collaborator = await self._provision_collaborator()
            lifecycle._oob_collaborator = self._oob_collaborator

            # P7 client-side execution oracle (disabled by default). Resolved BY
            # CAPABILITY and wired onto the Exploit agent, so DOM-XSS, a
            # client-rendered reflected/stored XSS, and a served CSP can be
            # confirmed on a WITNESSED execution. Absent ⇒ those classes record
            # unproven leads exactly as before — the black-box floor is unchanged.
            lifecycle._client_execution_oracle = self._provision_client_oracle(resolver, scope)

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
                        "scope": scope.model_dump(mode="json"),
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

                # Authenticate every supplied role and PROVE the session is
                # authenticated before scanning. Silent anonymous scanning of an
                # authenticated application is the failure that produces an
                # empty report and a false all-clear, so when the operator
                # supplied credentials and the assertion fails, this raises and
                # the engagement stops loudly.
                (
                    cookies,
                    authenticated_as,
                    auth_headers,
                ) = await self._establish_authenticated_state(recon_result, sessions, valid_creds)
                summary["authentication"] = self._authentication_summary()

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
                    auth_headers=auth_headers,
                )
                summary["phases"].update(concurrent_results)
                self._logger.info("PHASE 2 (CONCURRENT) complete")

                # Reconcile exploit findings into the findings table. The
                # Exploit Agent now persists each finding incrementally as it is
                # verified, so this loop is an idempotent safety net: it only
                # adds findings not already in the store (e.g. should the
                # incremental write ever be skipped). Dedup by finding id avoids
                # a UNIQUE-constraint crash on the re-insert and means a
                # force-killed phase (which returns no result here) still keeps
                # the findings it persisted mid-flight.
                exploit_data = concurrent_results.get("exploit", {})
                exploit_result = exploit_data.get("result", {})
                returned_findings = exploit_result.get("findings", [])
                existing = await state.get_findings(engagement_id)
                existing_ids = {f.get("id") for f in existing if isinstance(f, dict)}
                added = 0
                for finding in returned_findings:
                    if isinstance(finding, dict) and finding.get("id") not in existing_ids:
                        await state.add_finding(engagement_id, finding)
                        existing_ids.add(finding.get("id"))
                        added += 1
                self._logger.info(
                    "Findings reconciled: %d persisted incrementally, %d added by safety net",
                    len(existing),
                    added,
                )

                # =============================================================
                # PHASE 3: REPORT (sequential)
                # =============================================================
                # The report runs even when the engagement was halted — a halt is
                # a clean stop, and an operator whose kill switch fired needs the
                # report MORE than one whose run completed, not less. Hence
                # honor_halt=False: the report phase sends no requests, so there
                # is nothing for the rails to stop.
                report_result = await self._run_phase(
                    "report",
                    {
                        "task": "Generate a penetration test report. "
                        "Include all findings with CVSS scores, evidence, "
                        "and remediation recommendations.",
                        "engagement_id": engagement_id,
                        "engagement_name": scope.name,
                        "authorization": self._authorization.model_dump(mode="json")
                        if self._authorization
                        else None,
                        "scope_in": [f"{t.value} ({t.type.value})" for t in scope.targets],
                        "scope_out": [
                            f"{e.value} ({e.type.value})" + (f" — {e.notes}" if e.notes else "")
                            for e in scope.excluded
                        ],
                        "rules_of_engagement": list(scope.rules_of_engagement),
                        "engagement_window": scope.window.model_dump(mode="json")
                        if scope.window
                        else None,
                        "safety": governor.stats(),
                        "authentication": self._authentication_summary(),
                    },
                    honor_halt=False,
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
                summary["safety"] = governor.stats()
                summary["action_log"] = str(governor.action_log.path)
                if governor.halted:
                    summary["status"] = "halted"
                    summary["halt_reason"] = governor.halt_reason
                    summary["halt_detail"] = governor.halt_detail
                # Uninstall the rails and forget every registered secret. Both
                # are module-level state, so leaving either behind would leak
                # into the next engagement in the same process (and between
                # tests).
                set_active_governor(None)
                self._governor = None
                clear_secrets()

                await persistent_kb.close()
                # Tear down the P6 collaborator (bounded, per-engagement, redacted
                # log cleared) — always, even on failure.
                if self._oob_collaborator is not None:
                    with contextlib.suppress(Exception):
                        await self._oob_collaborator.stop()
                    self._oob_collaborator = None
                    lifecycle._oob_collaborator = None
                # Always close + unset the trace writer so module-level state
                # cannot leak between back-to-back engagements (relevant in
                # tests and long-running daemon processes).
                try:
                    trace_writer.close()
                finally:
                    set_active_trace_writer(None)

                # The disclosure gate runs LAST, once every writer has flushed,
                # and reads the bundle back off disk with its own eyes. It
                # deliberately shares no state with the redaction that produced
                # those files: a guarantee checked by the logic that makes it is
                # not checked at all, which is exactly how five live session
                # tokens sat in a trace under a check reporting zero leaks.
                summary["artifact_scan"] = self._run_disclosure_gate(engagement_id)

            await state.update_engagement_status(engagement_id, "completed")

        self._logger.info("Engagement %s complete", engagement_id)
        return summary

    # ------------------------------------------------------------------
    # Per-agent LLM factory
    # ------------------------------------------------------------------

    def _build_agent_llms(self, exclude_providers: set[str] | None = None) -> dict[str, LLMClient]:
        """Create a ResilientLLMClient per agent role.

        Each agent gets a wrapper tied to its profile (``fast`` or
        ``reasoning``) so a 429/503 from the primary provider silently
        falls back to the next one in the chain.

        Args:
            exclude_providers: Providers to drop from every agent's chain for
                this engagement (e.g. ``{"gemini"}`` when the credit pre-flight
                found the Gemini key depleted). Each agent then leads with its
                next available provider — Anthropic for the ``fast`` roles.

        Returns:
            Dict mapping agent type strings to LLMClient instances.
        """
        agent_roles = ("recon", "scan", "exploit", "research", "report")

        llms: dict[str, LLMClient] = {}
        for agent_type in agent_roles:
            try:
                llms[agent_type] = ResilientLLMClient(
                    agent_role=agent_type, exclude_providers=exclude_providers
                )
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
        auth_headers: dict[str, str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Run Research + Scan in parallel; start Exploit as soon as Scan is done.

        Flow:
        1. Start Research + Scan concurrently (asyncio.Tasks)
        2. Wait for Scan to complete (Exploit's only hard dependency)
        3. Do NOT block on Research — if it already finished, fold its runbook
           into Exploit's inputs; otherwise start Exploit without it
        4. Run Exploit with the v2 ScanResult (and ResearchResult if ready)
        5. Collect Research's result afterwards for the report

        Args:
            targets_str: Human-readable target list.
            recon_result: Recon phase result dict.
            technologies: Technologies extracted from recon.
            cred_data: Serialized valid credentials.
            session_data: Session dicts from state store.
            cookies: Verified session cookies.
            authenticated_as: Username for authenticated session.
            auth_headers: Auth headers for JWT/bearer sessions (e.g.
                ``{"Authorization": "Bearer <token>"}``). Empty for cookie auth.

        Returns:
            Dict with keys "research", "scan", "exploit" → result dicts.
        """
        assert self._engagement_id is not None

        auth_headers = auth_headers or {}
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
                    phase_timeout=settings.research_time_budget + _RESEARCH_PHASE_GRACE,
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
        if auth_headers:
            scan_content["session_headers"] = auth_headers
        if self._proven_login is not None:
            scan_content["proven_login"] = dict(self._proven_login)
        # The scan phase gets its OWN budget plus a grace window, exactly like
        # research. The generic 600 s phase timeout is a force-kill that
        # DISCARDS the agent's return value: on a real SPA the crawl +
        # enrichment + coverage-expansion pass ran past it, and the Exploit
        # planner was handed zero endpoints after the scan had discovered 138.
        # The agent now self-caps at settings.scan_time_budget and returns a
        # partial map; this timeout is only the backstop behind that.
        scan_task = asyncio.create_task(
            self._run_phase(
                "scan",
                scan_content,
                phase_timeout=settings.scan_time_budget + _SCAN_PHASE_GRACE,
            ),
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

        # --- Strict decouple: Exploit depends on Scan, NOT Research. ---
        # Research runs concurrently (it shares the Scan window and self-caps at
        # settings.research_time_budget). If it has already finished, fold its
        # runbook into Exploit's inputs; otherwise start Exploit immediately and
        # collect Research's result afterwards for the report. A slow/grounded
        # Research phase can therefore never delay Exploit's start.
        research_data: dict[str, Any] = {}
        if research_task is not None and research_task.done():
            try:
                research_result = research_task.result()
                results["research"] = research_result
                research_data = research_result
                self._logger.info(
                    "Research already complete — handing runbook to Exploit (%s)",
                    research_result.get("status", "unknown"),
                )
            except Exception as exc:
                self._logger.error("Research failed (proceeding without): %s", exc)
                results["research"] = {"status": "error", "error": str(exc)}
        elif research_task is not None:
            self._logger.info(
                "Research still running — starting Exploit now (strict decouple); "
                "runbook handoff skipped this engagement"
            )

        # --- Run Exploit with v2 models directly ---
        exploit_content: dict[str, Any] = {
            "task": f"Exploit all identified vulnerabilities on {targets_str}. "
            f"Check the runbook for techniques. Test all discovered endpoints. "
            f"Validate findings and chain exploits for maximum impact.",
            "recon_result": recon_result,
            "credentials": cred_data,
            "sessions": session_data,
        }
        # The client's permitted-technique list gates dispatch: a class outside
        # it is never attempted, and the report names it under "Techniques not
        # authorized" rather than leaving the client to assume coverage.
        if self._authorization is not None and not self._authorization.permits_all:
            exploit_content["permitted_techniques"] = list(self._authorization.permitted_techniques)

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
        if auth_headers:
            exploit_content["session_headers"] = auth_headers
        if cookies or auth_headers:
            exploit_content["authenticated_as"] = authenticated_as
            credential_kind = "session cookies" if cookies else "Authorization bearer token"
            exploit_content["task"] = (
                f"You are already authenticated as '{authenticated_as}'. "
                f"Use the provided {credential_kind} for ALL requests. "
                f"Do NOT attempt to login again.\n\n" + exploit_content["task"]
            )

        # Discovery engine — the gray-box THIRD plan source (§2.7 / §4.5). When the
        # engagement supplies a source tree, ingest it now and hand the lowered
        # Tier-A hypotheses to Exploit BEFORE it plans, so a channel a black-box
        # crawl missed (the unlinked GeoServer TestWfsPost servlet; Solr's shared
        # stream.url request parser) is still tested. Inert when no source_dir is
        # configured — the default pipeline is unchanged.
        discovery_tasks = await self._build_discovery_tasks(technologies, targets_str)
        if discovery_tasks:
            exploit_content["discovery_tasks"] = [
                t.model_dump(mode="json") for t in discovery_tasks
            ]

        # Exploit phase budget. Default (settings.exploit_phase_budget == 0) is
        # UNBOUNDED: no cooperative deadline is passed (the agent runs the full
        # task queue to completion) and _run_phase gets no hard cap — a genuine
        # hang is caught by operation-level timeouts, not a phase clock. When a
        # budget IS configured, we pass an absolute time.monotonic() deadline
        # plus a stop margin (the agent reads it on the same event loop) and give
        # _run_phase a hard cap of budget + grace so the cooperative return wins
        # the race against the force-kill.
        budget = float(settings.exploit_phase_budget)
        if budget > 0:
            exploit_content["deadline_ts"] = time.monotonic() + budget
            exploit_content["stop_margin_seconds"] = _EXPLOIT_STOP_MARGIN
            exploit_phase_timeout: float = budget + _EXPLOIT_HARD_GRACE
            self._logger.info(
                "Starting Exploit with v2 scan + research results "
                "(budget=%.0fs, stop_margin=%ds, hard_cap=%.0fs)",
                budget,
                _EXPLOIT_STOP_MARGIN,
                exploit_phase_timeout,
            )
        else:
            exploit_phase_timeout = float("inf")
            self._logger.info(
                "Starting Exploit with v2 scan + research results "
                "(no phase budget — full task queue runs to completion; "
                "operation-level timeouts are the safety valve)"
            )
        try:
            exploit_result = await self._run_phase(
                "exploit",
                exploit_content,
                phase_timeout=exploit_phase_timeout,
            )
            results["exploit"] = exploit_result
        except Exception as exc:
            self._logger.error("Exploit failed: %s", exc)
            results["exploit"] = {"status": "error", "error": str(exc)}

        # --- Collect Research for the report (bounded by its wall-clock budget). ---
        # Exploit did not wait on it; gather its result now if it wasn't already
        # collected before Exploit started.
        if research_task is not None and "research" not in results:
            try:
                research_result = await research_task
                results["research"] = research_result
                self._logger.info(
                    "Research collected post-Exploit — %s",
                    research_result.get("status", "unknown"),
                )
            except Exception as exc:
                self._logger.error("Research failed (post-exploit collect): %s", exc)
                results["research"] = {"status": "error", "error": str(exc)}

        # Fill in any missing results
        for name in ("research", "scan", "exploit"):
            if name not in results:
                results[name] = {"status": "not_started"}

        return results

    # ------------------------------------------------------------------
    # Discovery engine (gray-box) — the third exploit-plan source
    # ------------------------------------------------------------------

    async def _build_discovery_tasks(
        self, technologies: list[str], targets_str: str
    ) -> list[ExploitTask]:
        """Run the discovery engine over the engagement source tree, if any.

        Gray-box only: with no ``scope.source_dir`` this returns ``[]`` and the
        pipeline is exactly black-box. Otherwise it ingests the source, derives
        Δ-capability × reachability hypotheses, and lowers them to Tier-A
        ``ExploitTask``s the Exploit agent unions into its plan (§2.7). The
        recon-derived *technologies* are the fingerprint; the base URL that
        source-derived routes join onto is ``scope.discovery_base_url`` (a shared
        request parser with no source route, like Solr, supplies the reflecting
        handler here), falling back to the primary target URL. Failures degrade to
        black-box — discovery never breaks the engagement.

        Layer-2 (design §4): the persistent capability store is dumped and handed to
        ``discover`` as the load-as-prior input — a confirmed-before capability RANKS
        earlier and, on partial source, SEEDS a hypothesis the recognizer could not
        derive. After discovery, the manifest-derived ``bundles`` and version-lineage
        ``successor`` transfer edges are written back (the dormant table's first
        production writers), so the NEXT engagement's recall can transfer. Recall
        NEVER emits — emission stays the unchanged live proof (§5).
        """
        scope = self._scope
        if scope is None or not scope.source_dir:
            return []
        if not Path(scope.source_dir).exists():
            self._logger.warning("Discovery: source_dir does not exist: %s", scope.source_dir)
            return []
        base_url = scope.discovery_base_url or self._primary_target_url()
        if not base_url:
            self._logger.warning("Discovery: no base URL for %s — skipping", targets_str)
            return []
        capability_facts, technology_relations = await self._load_capability_store()
        topology_context = self._build_topology_context(base_url, technologies)
        try:
            result = DiscoveryEngine().discover(
                scope.source_dir,
                technologies,
                base_url,
                capability_facts=capability_facts,
                technology_relations=technology_relations,
                topology_context=topology_context,
            )
        except Exception as exc:  # noqa: BLE001 — discovery must never break the run
            self._logger.error("Discovery engine failed (proceeding black-box): %s", exc)
            return []
        await self._write_transfer_edges(result.source_model, technologies)
        tasks = result.exploit_tasks()
        recall_seeded = sum(1 for h in result.hypotheses if h.prior_source == "capability_recall")
        self._logger.info(
            "Discovery: %d hypothesis task(s) from source "
            "(%d entrypoints, %d Δ, %d edges, %d recalls, %d recall-seeded/-boosted) base=%s",
            len(tasks),
            len(result.source_model.entrypoints),
            len(result.deltas),
            len(result.edges),
            len(result.recalls),
            recall_seeded,
            base_url,
        )
        return tasks

    async def _load_capability_store(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Dump ``capability_facts`` + ``technology_relations`` for the recall prior.

        Read-only. With no persistent KB (or on any read error) returns empty dumps,
        so discovery degrades to a cold start — never breaks the engagement.
        """
        kb = self._persistent_kb
        if kb is None:
            return [], []
        try:
            facts = await kb.get_capability_facts()
            relations = await kb.get_technology_relations()
        except Exception as exc:  # noqa: BLE001 — a KB read must never break the run
            self._logger.warning("Discovery: capability-store read failed (cold start): %s", exc)
            return [], []
        return facts, relations

    async def _write_transfer_edges(
        self, source_model: SourceModel, technologies: list[str]
    ) -> None:
        """Write the deterministic Layer-2 transfer edges (design §2.4).

        ``bundles`` — the manifest-derived edge from each specific app in the
        fingerprint to the carrying dependency (``apache-solr@8.11.0 →
        log4j-core@2.14.1``); ``successor`` — version-lineage edges across the
        versions the store already has facts for. Both are pure-derived then persisted
        via the generic relation writer. Best-effort: a write failure is logged, never
        raised (transfer is an optimisation, not a correctness dependency).
        """
        kb = self._persistent_kb
        if kb is None or not source_model.manifest_technology_key:
            return
        try:
            bundles = derive_bundles_edges(
                source_model.manifest_technology_key,
                source_model.manifest_observed_version,
                technologies,
            )
            for edge in bundles:
                await kb.add_technology_relation(
                    edge.tech_a, edge.tech_b, edge.relation_type, edge.similarity
                )
            # Version lineage over the versions the store now holds for this dep.
            dep_facts = await kb.get_capability_facts(source_model.manifest_technology_key)
            versions = [predicate_point_version(f.get("version_predicate", "")) for f in dep_facts]
            if source_model.manifest_observed_version:
                versions.append(source_model.manifest_observed_version)
            successors = derive_successor_edges(
                source_model.manifest_technology_key, [v for v in versions if v]
            )
            for edge in successors:
                await kb.add_technology_relation(
                    edge.tech_a, edge.tech_b, edge.relation_type, edge.similarity
                )
            if bundles or successors:
                self._logger.info(
                    "Discovery: wrote %d bundles + %d successor transfer edge(s) for %s",
                    len(bundles),
                    len(successors),
                    source_model.manifest_technology_key,
                )
        except Exception as exc:  # noqa: BLE001 — transfer edges are best-effort
            self._logger.warning("Discovery: transfer-edge write failed: %s", exc)

    # ------------------------------------------------------------------
    # P6 out-of-band collaborator provisioning (docs/p6-oob-design.md §P6.1.3)
    # ------------------------------------------------------------------

    def _provision_client_oracle(
        self, resolver: ToolResolver, scope: EngagementScope
    ) -> object | None:
        """Resolve the P7 client-side execution oracle, or ``None`` (P7 disabled).

        Same degradation discipline as the P6 collaborator: an oracle that is
        disabled by configuration, absent from the tool chain, or not actually
        installed is logged and skipped, and the engagement completes with the
        affected classes recording unproven leads exactly as before.

        The oracle is found BY CAPABILITY (``client_side_execution``) and never by
        name, so a different browser backend registered for that capability is
        picked up without a change here.
        """
        from clinkz.config import settings

        if settings.client_oracle_mode == "disabled":
            return None
        match = resolver.find_tool("client_side_execution")
        if match is None or not match.available or match.tool_class is None:
            self._logger.warning(
                "P7 client-side execution oracle requested (CLIENT_ORACLE_MODE=%s) but no "
                "available tool provides 'client_side_execution' — DOM-XSS / CSP candidates "
                "will be reported as unproven leads. Install with: "
                "pip install -e '.[browser]' && playwright install chromium",
                settings.client_oracle_mode,
            )
            return None
        try:
            oracle = match.tool_class(
                scope=scope, engagement_id=self._engagement_id, stage="exploit"
            )
        except Exception as exc:  # noqa: BLE001 — an unusable oracle is an absent one
            self._logger.warning("P7 oracle could not be constructed (%s) — skipping", exc)
            return None
        self._logger.info("P7 client-side execution oracle ready: %s", match.name)
        return oracle

    async def _provision_collaborator(self) -> OOBCollaborator | None:
        """Provision + health-check the P6 collaborator, or ``None`` (P6 disabled).

        Mirrors the container-preflight degradation discipline: a collaborator that
        cannot bind its listeners, or fails its self-round-trip health-check, is
        logged and skipped — the engagement completes on the in-band half exactly as
        before (blind hypotheses defer). Only a **healthy** collaborator (both DNS
        and HTTP legs round-tripped) is returned, so the exploit agent may turn a P6
        non-confirmation into a research-lead only when the loop is proven (§P6.7.1).
        Never raises.
        """
        mode = settings.oob_collaborator_mode
        if mode == "disabled":
            return None
        if mode == "external":
            # A self-hosted interactsh-style client is reserved (§P6.1.2); the public
            # shared server is refused, not defaulted (§P6.1.5 guardrail 5). Not built.
            self._logger.warning(
                "OOB collaborator mode 'external' is not implemented — P6 disabled "
                "(the public shared server is refused by design)"
            )
            return None
        try:
            collab = OOBCollaborator(
                zone=settings.oob_zone,
                callback_shape=CallbackShape(settings.oob_callback_shape),
                http_port=settings.oob_http_port,
                dns_port=settings.oob_dns_port,
                advertised_ip=settings.oob_advertised_ip,
            )
            await collab.start()
        except Exception as exc:  # noqa: BLE001 — P6 must never break the engagement
            self._logger.warning("OOB collaborator failed to start — P6 disabled: %s", exc)
            return None
        if not await collab.health_check():
            self._logger.warning(
                "OOB collaborator health-check failed — P6 disabled (collaborator "
                "unavailable; blind hypotheses will NOT be marked clean)"
            )
            with contextlib.suppress(Exception):
                await collab.stop()
            return None
        self._logger.info(
            "OOB collaborator provisioned and healthy: zone=%s shape=%s",
            collab.zone,
            collab.callback_shape.value,
        )
        return collab

    def _build_topology_context(
        self, base_url: str, technologies: list[str]
    ) -> TopologyContext | None:
        """Build the cross-service :class:`TopologyContext` from scope (design §2b/§6).

        Service A is the discovery ``base_url``; the candidate B set is every OTHER
        in-scope target (distinct bare hostname from A). This is the recon-adjacency
        prior — in scope ⇒ reachable from A's segment (the scope declares the wire
        open, incl. internal-only metadata/admin surfaces). The SOURCE upgrade (§2a,
        A statically references B) is computed inside the discovery engine by matching
        A's static egress hosts against these candidates. Returns ``None`` (no
        cross-service composition) when there is no distinct second in-scope service —
        a single-service engagement, unchanged behaviour.

        Slice B2 (§6.4): ``origin_identity`` is A's abstracted SPECIFIC role/tech-class
        from the recon fingerprint (:func:`_abstract_origin_identity`) — matched against
        a learned ``reaches`` edge's A-end and carried into a confirmed reach's edge
        write-back. ``service_identities`` (B-URL → B's role/tech-class) is left EMPTY
        here: the black-box multi-target orchestrator does not deeply fingerprint a
        secondary in-scope service, so B is typically un-abstractable and a confirmed
        reach stays engagement-local (the honest §9 default). A gray-box driver that
        DOES know B's role supplies ``service_identities`` directly.
        """
        from urllib.parse import urlparse

        scope = self._scope
        if scope is None or not scope.targets:
            return None
        origin_bare = urlparse(base_url if "://" in base_url else f"//{base_url}").hostname or ""
        origin_bare = origin_bare.lower()
        services: list[str] = []
        seen: set[str] = set()
        for entry in scope.targets:
            value = entry.value
            url = value if "://" in value else f"http://{value}"
            bare = (urlparse(url).hostname or "").lower()
            if not bare or bare == origin_bare or bare in seen:
                continue
            seen.add(bare)
            services.append(url)
        if not services:
            return None
        return TopologyContext(
            origin_host=origin_bare,
            internal_services=services,
            origin_identity=self._abstract_origin_identity(technologies),
        )

    @staticmethod
    def _abstract_origin_identity(technologies: list[str]) -> str:
        """A's most-specific abstractable role/tech-class from the fingerprint (§6.4).

        Runs each fingerprint entry through the write-boundary abstraction fence
        (:func:`~clinkz.discovery.abstract_reaches_identity`) — which drops hosts, bare
        versions, and over-broad bare languages — and keeps the MOST specific survivor
        (the longest normalized key, a proxy for specificity: ``owasp-juice-shop`` over
        ``express``). ``""`` when nothing abstracts (⇒ no learned transfer keys on A).
        """
        best = ""
        for tech in technologies:
            key = abstract_reaches_identity(tech)
            if key and len(key) > len(best):
                best = key
        return best

    def _primary_target_url(self) -> str:
        """A base URL for discovery from the first in-scope target (best effort)."""
        scope = self._scope
        if scope is None or not scope.targets:
            return ""
        value = scope.targets[0].value
        return value if "://" in value else f"http://{value}"

    # ------------------------------------------------------------------
    # Phase runner
    # ------------------------------------------------------------------

    @staticmethod
    def _phase_stop_result(
        status: str,
        agent_type: str,
        result: dict[str, Any],
        **extra: Any,
    ) -> dict[str, Any]:
        """The result dict for a phase the orchestrator stopped early.

        Whatever the agent already delivered is carried through. A stop is a
        reason to stop asking for more, never a reason to discard work the phase
        already handed over — and on the scan phase the difference is total: its
        return value IS the attack surface, so dropping it leaves the Exploit
        planner with no endpoints and every methodology probing an invented URL.

        Args:
            status: Why the phase stopped (``"timeout"`` / ``"halted"``).
            agent_type: The phase's agent name.
            result: Whatever the agent had already delivered (may be empty).
            **extra: Status-specific detail (halt reason, etc).

        Returns:
            The phase result dict, including ``result`` when there was one.
        """
        return {
            "status": status,
            "agent": agent_type,
            **extra,
            **({"result": result} if result else {}),
        }

    async def _run_phase(
        self,
        agent_type: str,
        task_content: dict[str, Any],
        phase_timeout: float | None = None,
        honor_halt: bool = True,
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
            phase_timeout: Hard cap (seconds) before the orchestrator force-kills
                the agent. Defaults to ``_PHASE_TIMEOUT``. The exploit phase
                passes a larger value than its cooperative budget so the agent
                has a grace window to stop cleanly before being cancelled.
            honor_halt: Whether a halted governor ends this phase. ``True`` for
                every testing phase; ``False`` for the report, which sends no
                requests and must still run after a halt.

        Returns:
            Result dict from the agent (or error info).

        Raises:
            TimeoutError: If the agent does not respond within the timeout.
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
        timeout = phase_timeout if phase_timeout is not None else _PHASE_TIMEOUT
        deadline = asyncio.get_event_loop().time() + timeout
        result: dict[str, Any] = {}

        while True:
            # Kill switch / window / blocking. The governor already refuses every
            # request once halted, so no further traffic is possible; this loop
            # is what turns "sending nothing" into "stopped", by shutting the
            # agent down and letting the run proceed to the report.
            if honor_halt and self._governor is not None and self._governor.halted:
                self._logger.error(
                    "Phase '%s' stopping — engagement halted (%s): %s",
                    agent_type,
                    self._governor.halt_reason,
                    self._governor.halt_detail,
                )
                try:
                    await self._lifecycle.shut_down(agent_type)
                except Exception:
                    pass
                return self._phase_stop_result(
                    "halted",
                    agent_type,
                    result,
                    halt_reason=self._governor.halt_reason,
                    halt_detail=self._governor.halt_detail,
                )

            # Session maintenance. The sentinel sees every response the
            # engagement receives, so a session lost mid-phase is noticed here
            # rather than by the methodology that lost it.
            if self._session_sentinel.reauth_needed:
                await self._reauthenticate_running_agents()

            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                self._logger.error("Phase '%s' timed out", agent_type)
                try:
                    await self._lifecycle.shut_down(agent_type)
                except Exception:
                    pass
                return self._phase_stop_result("timeout", agent_type, result)

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
            for idx, msg in enumerate(pending):
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
                    # We drained the whole orchestrator queue but are about to
                    # return; requeue messages we never examined so a concurrent
                    # phase runner (e.g. a still-running Research) doesn't lose
                    # its result.
                    await self._requeue_unexamined(pending, idx + 1)
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
                    await self._requeue_unexamined(pending, idx + 1)
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
                            await self._requeue_unexamined(pending, idx + 1)
                            return result or {
                                "status": "agent_stopped",
                                "agent": agent_type,
                            }

            # If we only re-queued other agents' messages (nothing for us),
            # sleep to avoid a busy-loop when multiple _run_phase tasks share
            # the same orchestrator queue.
            if not handled_own:
                await asyncio.sleep(_POLL_INTERVAL)

    async def _requeue_unexamined(
        self,
        pending: list[AgentMessage],
        start: int,
    ) -> None:
        """Requeue drained-but-unexamined messages before a terminal return.

        ``get_pending`` drains the entire orchestrator queue, but a phase runner
        returns the instant it sees its own terminal message — leaving any later
        messages in the same batch drained yet unprocessed. With Scan/Research/
        Exploit polling the same queue concurrently, those would be lost (e.g. a
        still-running Research's RESULT). Putting them back lets the owning
        runner pick them up on its next poll.

        Args:
            pending: The batch returned by ``get_pending``.
            start: Index of the first message not yet examined by the loop.
        """
        assert self._bus is not None
        for later in pending[start:]:
            await self._bus.requeue(ORCHESTRATOR, later)

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
                    "scope": self._scope.model_dump(mode="json") if self._scope else {},
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
                    bearer_token=result.bearer_token,
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
    ) -> tuple[dict[str, str], str, dict[str, str]]:
        """Verify a session is still valid; re-authenticate if not.

        Called before handing off to the Scan/Exploit Agents to ensure the
        session will actually work. Handles both auth shapes:

        - **Cookie/form** sessions are verified with a protected-page GET and
          re-authenticated on expiry.
        - **JWT/bearer** sessions (cookies empty, ``bearer_token`` in metadata)
          are trusted for the engagement window — the token rides the
          ``Authorization`` header, so the cookie-based protected-page check
          does not apply.

        Args:
            login_url: Login URL for re-authentication.
            sessions: Session dicts from state store.
            valid_creds: Valid Credential objects.

        Returns:
            Tuple of (cookies_dict, authenticated_as_username, auth_headers).
            ``auth_headers`` carries ``{"Authorization": "Bearer <token>"}``
            for JWT sessions, else an empty dict.
        """
        assert self._engagement_id is not None

        if not sessions:
            return {}, "", {}

        latest = sessions[-1]
        cookies = latest.get("cookies", {})
        metadata = latest.get("metadata", {})
        bearer = metadata.get("bearer_token", "") if isinstance(metadata, dict) else ""
        if not cookies and not bearer:
            return {}, "", {}

        # Find who we authenticated as
        cred_id = metadata.get("credential_id", "") if isinstance(metadata, dict) else ""
        authenticated_as = "unknown"
        matched_cred = None
        for c in valid_creds:
            if c.id == cred_id:
                authenticated_as = c.username
                matched_cred = c
                break

        # JWT/bearer session — no cookie-based protected-page check applies.
        # Trust the token for the engagement window (re-auth on expiry is a
        # cookie-flow concern; JWTs outlive a single engagement).
        if bearer:
            self._logger.info("Bearer session active for '%s'", authenticated_as)
            return cookies, authenticated_as, {"Authorization": f"Bearer {bearer}"}

        # Verify the cookie session
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
            return cookies, authenticated_as, {}

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
                        bearer_token=result.bearer_token,
                    )
                auth_headers = (
                    {"Authorization": f"Bearer {result.bearer_token}"}
                    if result.bearer_token
                    else {}
                )
                return result.session_cookies, matched_cred.username, auth_headers

        self._logger.warning("Re-authentication failed — proceeding without session")
        return {}, "", {}

    # ------------------------------------------------------------------
    # Authenticated scanning (productization P1 · part B)
    # ------------------------------------------------------------------

    async def _establish_authenticated_state(
        self,
        recon_result: dict[str, Any],
        sessions: list[dict[str, Any]],
        valid_creds: list[Any],
    ) -> tuple[dict[str, str], str, dict[str, str]]:
        """Authenticate every supplied role, then PROVE the primary session.

        Three outcomes, and the difference between them is the whole point:

        * **Credentials supplied and the assertion succeeds** — the engagement
          proceeds authenticated, and the proof is recorded in the report.
        * **Credentials supplied and the assertion fails** — the engagement
          ABORTS. Scanning an authenticated application anonymously produces an
          empty report that reads like a clean bill of health, which is worse
          than no report at all.
        * **No credentials supplied** — the engagement proceeds anonymously
          (a legitimate black-box run), falling back to whatever session the
          default-credential phase happened to establish. The report says so
          explicitly.

        Args:
            recon_result: Recon phase result, used to locate the login surface.
            sessions: Sessions already in the state store (default-cred phase).
            valid_creds: Valid credentials from the default-cred phase.

        Returns:
            ``(cookies, authenticated_as, auth_headers)`` for the primary role.

        Raises:
            AuthStateError: Credentials were supplied but authenticated state
                could not be proven.
        """
        from clinkz.engagement.auth_state import AuthStateError

        base_url = self._primary_target_url()

        if not self._credentials.authenticating and not sessions:
            # Nothing to authenticate with. Probing for a login surface we have
            # no credentials for would cost the target a dozen requests and tell
            # us nothing we can act on, so this path stays exactly as it was
            # before the productization pass — but says plainly what an empty
            # report from it would and would not mean.
            self._logger.warning(
                "No credentials available — this engagement will run ANONYMOUSLY. "
                "If %s requires a login, an empty report means the application "
                "was never seen, not that it is secure.",
                base_url,
            )
            return {}, "", {}

        probe = _ToolHttpProbe(self._scope, self._engagement_id or "")
        discovered_login = await self._find_login_url(recon_result, "", scan_result=None)
        detection = await detect_auth_mechanism(
            probe,
            base_url,
            extra_login_urls=[u for u in (discovered_login,) if u],
        )
        self._auth_mechanism = detection.mechanism
        self._logger.info(
            "Auth mechanism detected: %s (login_url=%s) — %s",
            detection.mechanism.value,
            detection.login_url or "(none)",
            "; ".join(detection.evidence) or "no evidence",
        )

        if not self._credentials.authenticating:
            # Default-credential sessions only. Pre-existing behaviour, kept.
            self._logger.warning(
                "No operator credentials supplied — proceeding on the default "
                "credentials the recon phase validated."
            )
            login_url = discovered_login or detection.login_url or f"{base_url}/login"
            return await self._verify_and_refresh_session(login_url, sessions, valid_creds)

        # Authenticate each role. Every role gets its own session so the
        # access-control classes have two principals to compare.
        for cred in self._credentials.authenticating:
            await self._authenticate_role(cred, detection.login_url or discovered_login or base_url)

        primary = self._credentials.primary()
        primary_session = self._role_sessions.get(primary.role if primary else "", {})
        if not primary_session.get("established"):
            raise AuthStateError(self._auth_failure_message(base_url, detection))

        assertion: AuthAssertion = primary_session["assertion"]
        self._auth_assertion = assertion
        # There is now a session to lose. Everything before this point was
        # unauthenticated by definition — the login POSTs, the mechanism probes,
        # the form-auth attempts that fail before the JSON path succeeds — and a
        # live run had the sentinel fire on exactly those, seconds before the
        # session it was watching for existed.
        self._session_sentinel.arm()
        self._logger.info(
            "AUTHENTICATED STATE PROVEN as '%s' — %s at %s (auth=%d anon=%d)",
            primary_session["username"],
            assertion.discriminator,
            assertion.url,
            assertion.authenticated_status,
            assertion.anonymous_status,
        )
        if len(self._role_sessions) >= 2:
            self._logger.info(
                "Multi-role engagement: %s — access-control classes can compare principals",
                ", ".join(sorted(self._role_sessions)),
            )

        return (
            primary_session["cookies"],
            primary_session["username"],
            primary_session["headers"],
        )

    async def _authenticate_role(self, cred: RoleCredential, default_login_url: str) -> None:
        """Log in as one role and assert the resulting session, recording both."""
        from clinkz.tools.auth import WebAuthenticator

        login_url = cred.login_url or default_login_url
        authenticator = WebAuthenticator(scope=self._scope, engagement_id=self._engagement_id)
        result = await authenticator.authenticate(login_url, cred.username, cred.secret())

        if not result.success:
            self._logger.error(
                "Login FAILED for role '%s' at %s (status %d): %s",
                cred.role,
                login_url,
                result.status_code,
                result.error or "no error reported",
            )
            self._role_sessions[cred.role] = {
                "established": False,
                "username": cred.username,
                "cookies": {},
                "headers": {},
                "assertion": AuthAssertion(
                    established=False,
                    why_unproven=f"Login did not succeed at {login_url}",
                ),
            }
            return

        # The authenticator discovered this target's login route and the body
        # shape that actually returned a token. That is an OBSERVED schema for
        # the endpoint every credential-attack class targets, and no other
        # discovery source can reach it: a login body is not in a collection
        # representation, and a frontend hands its form object straight through
        # without ever naming the fields. Recorded once, on the first role that
        # proves a session.
        if result.auth_body_fields and self._proven_login is None:
            self._proven_login = {
                "url": result.login_url or login_url,
                "method": "POST",
                "content_type": result.auth_content_type or "application/json",
                "fields": list(result.auth_body_fields),
            }
            self._logger.info(
                "Login request shape observed at %s: %s",
                self._proven_login["url"],
                ", ".join(self._proven_login["fields"]),
            )

        headers = {"Authorization": f"Bearer {result.bearer_token}"} if result.bearer_token else {}
        assertion = await self._assert_role_session(
            cred, result.session_cookies, headers, login_url
        )
        self._role_sessions[cred.role] = {
            "established": assertion.established,
            "username": cred.username,
            "cookies": result.session_cookies,
            "headers": headers,
            "assertion": assertion,
        }
        if assertion.established and cred.role == (
            self._credentials.primary().role if self._credentials.primary() else ""
        ):
            # Remember what to re-authenticate with when the session is lost.
            self._reauth_credential = cred
            self._reauth_login_url = login_url

    async def _assert_role_session(
        self,
        cred: RoleCredential,
        cookies: dict[str, str],
        headers: dict[str, str],
        login_url: str,
    ) -> AuthAssertion:
        """Prove *cred*'s session is authenticated against an anonymous control.

        Candidate order is deliberate: the operator's own ``assert_url`` first
        (they know their application), then conventional protected paths, then
        the site root and the login URL last — the root is the least likely to
        discriminate on a modern SPA, whose shell renders identically either way.
        """
        probe = _ToolHttpProbe(self._scope, self._engagement_id or "")
        base_url = self._primary_target_url().rstrip("/")
        candidates = [
            *([cred.assert_url] if cred.assert_url else []),
            *(f"{base_url}{path}" for path in PROTECTED_PATH_CANDIDATES),
            f"{base_url}/",
            f"{base_url}/index.php",
            login_url,
        ]
        assertion = await assert_authenticated(
            probe,
            candidates,
            cookies=cookies,
            headers=headers,
            username=cred.username,
        )
        if not assertion.established:
            self._logger.error(
                "Could NOT prove authenticated state for role '%s': %s",
                cred.role,
                assertion.why_unproven,
            )
        return assertion

    def _auth_failure_message(self, base_url: str, detection: Any) -> str:
        """The loud abort message for an unprovable session."""
        lines = [
            "ABORTING: credentials were supplied but authenticated state could not be proven.",
            "",
            "Scanning an authenticated application anonymously produces an empty report "
            "that reads like a clean bill of health. That is a worse outcome than no "
            "report, so the engagement stops here rather than continuing blind.",
            "",
            f"Target        : {base_url}",
            f"Auth mechanism: {getattr(detection, 'mechanism', '?')}",
            f"Login URL     : {getattr(detection, 'login_url', '') or '(not found)'}",
            "",
            "Per role:",
        ]
        for role, session in self._role_sessions.items():
            assertion: AuthAssertion = session["assertion"]
            lines.append(f"  [{role}] {assertion.why_unproven or 'not established'}")
            for attempt in assertion.attempted[:6]:
                lines.append(f"      tried {attempt}")
        lines += [
            "",
            "Fix one of:",
            "  - the credentials are wrong, or the account is locked",
            '  - the login URL is wrong (set "login_url" on the role in the credential file)',
            "  - the application has no URL that behaves differently when "
            "authenticated among the ones tried; supply a known "
            "authenticated-only URL",
        ]
        return "\n".join(lines)

    async def _reauthenticate_running_agents(self) -> None:
        """Verify the session the sentinel flagged, and refresh it if it is dead.

        The sentinel raised a flag from a heuristic; acting on it is the
        Orchestrator's job because it owns the engagement session. Two things
        happen here that the sentinel deliberately cannot do for itself.

        **The oracle decides, not the heuristic.** Before re-authenticating we
        re-run :func:`assert_authenticated` — the same with-session /
        without-session comparison that proved the session at startup. A run of
        401s from an authorization boundary the scan legitimately walked into
        looks identical to a dead session from the outside; only the assertion
        can tell them apart. A verified-alive session is a false alarm, recorded
        as one, and costs two requests instead of a needless re-login that
        rotates a working token mid-phase.

        **Only a success counts as a re-authentication.** The counter used to be
        incremented on the way IN, before anything had been attempted, so a run
        with no credential to re-authenticate with still reported having
        re-authenticated. The report is where that number is read; a recovery
        nobody made must not appear in it.

        Pushing the refreshed cookies into the live agent instances is a
        deliberate coupling: an agent reads its session once, at task start, so
        without this the remainder of the phase would keep using the dead one —
        exactly the "half the engagement ran unauthenticated" failure this
        machinery exists to prevent.

        Three phases poll the same sentinel concurrently, so the whole sequence
        is serialised: two simultaneous re-logins would race to write
        ``_role_sessions`` and the loser's token would be pushed to the agents.
        """
        async with self._session_reauth_lock:
            if not self._session_sentinel.reauth_needed:
                # A concurrent phase already handled this flag.
                return
            await self._verify_and_refresh_session()

    async def _verify_and_refresh_session(self) -> None:
        """The body of :meth:`_reauthenticate_running_agents`, under the lock."""
        cred = self._reauth_credential

        if await self._session_still_proven(cred):
            self._logger.info(
                "Session-loss signals did not survive verification — the session is "
                "still authenticated; continuing without re-authenticating"
            )
            self._session_sentinel.clear(reauthenticated=False)
            return

        if cred is None or not self._reauth_login_url:
            self._logger.warning(
                "Session loss detected but no credential is available to "
                "re-authenticate with — continuing with the session we have"
            )
            self._session_sentinel.clear(reauthenticated=False)
            return

        self._logger.warning("Session lost — re-authenticating as '%s'", cred.username)
        from clinkz.tools.auth import WebAuthenticator

        authenticator = WebAuthenticator(scope=self._scope, engagement_id=self._engagement_id)
        result = await authenticator.authenticate(
            self._reauth_login_url, cred.username, cred.secret()
        )
        if not result.success:
            self._logger.error(
                "Re-authentication FAILED for '%s' — the remainder of this phase "
                "may run unauthenticated; this is recorded in the report",
                cred.username,
            )
            self._session_sentinel.clear(reauthenticated=False)
            return

        headers = {"Authorization": f"Bearer {result.bearer_token}"} if result.bearer_token else {}
        self._role_sessions.setdefault(cred.role, {}).update(
            {"cookies": result.session_cookies, "headers": headers, "username": cred.username}
        )
        if self._cred_store and self._engagement_id:
            valid = await self._cred_store.get_all_valid(self._engagement_id)
            for stored in valid:
                if stored.username == cred.username:
                    await self._cred_store.mark_valid(
                        stored.id,
                        session_cookies=result.session_cookies,
                        engagement_id=self._engagement_id,
                        agent="orchestrator",
                        bearer_token=result.bearer_token,
                    )
                    break

        pushed = self._push_session_to_agents(result.session_cookies, headers)
        self._session_sentinel.clear(reauthenticated=True)
        self._logger.info(
            "Re-authenticated as '%s' — session pushed to %d running agent(s)",
            cred.username,
            pushed,
        )

    async def _session_still_proven(self, cred: RoleCredential | None) -> bool:
        """Whether the flagged session still passes the authenticated assertion.

        Re-runs the startup proof against the URL it originally succeeded at, so
        the verification is the same oracle rather than a second heuristic. A
        probe failure returns ``False``: "we could not verify" must fall through
        to re-authentication, never be read as "it is fine".

        Args:
            cred: The credential whose session is in question.

        Returns:
            ``True`` only when the assertion re-established the boundary.
        """
        if cred is None or not self._engagement_id:
            return False
        session = self._role_sessions.get(cred.role) or {}
        cookies = session.get("cookies") or {}
        headers = session.get("headers") or {}
        if not cookies and not headers:
            return False

        previous: AuthAssertion | None = session.get("assertion")
        candidates = [
            *([previous.url] if previous and previous.url else []),
            *([cred.assert_url] if cred.assert_url else []),
        ]
        if not candidates:
            return False

        probe = _ToolHttpProbe(self._scope, self._engagement_id)
        try:
            assertion = await assert_authenticated(
                probe,
                candidates,
                cookies=cookies,
                headers=headers,
                username=cred.username,
            )
        except Exception as exc:  # noqa: BLE001 — verification failure is not proof of health
            self._logger.warning("Session verification probe failed: %s", exc)
            return False
        return assertion.established

    def _push_session_to_agents(self, cookies: dict[str, str], headers: dict[str, str]) -> int:
        """Write a refreshed session onto every running agent that holds one."""
        if self._lifecycle is None:
            return 0
        pushed = 0
        for name in self._lifecycle.get_running_agents():
            agent = self._lifecycle.get_agent(name)
            if agent is None:
                continue
            if hasattr(agent, "_session_cookies") and cookies:
                agent._session_cookies = dict(cookies)
                pushed += 1
            if hasattr(agent, "_session_headers") and headers:
                agent._session_headers = dict(headers)
        return pushed

    def _run_disclosure_gate(self, engagement_id: str) -> dict[str, Any]:
        """Scan the finished bundle for credential material and report it.

        Runs after every writer has flushed, so what it sees is what an operator
        would hand over. A failure does not retract the report — the findings
        are still the client's — but it is stated at ERROR and recorded in the
        run summary, because "this bundle must not leave the building" is
        information the operator needs before they attach it to an email.

        Never raises: a scan that crashed must not be the reason a completed
        engagement reports failure, so the error is recorded instead.
        """
        root = Path("outputs") / engagement_id
        try:
            report = run_disclosure_gate(root, engagement_id=engagement_id)
        except Exception as exc:  # noqa: BLE001 — a gate must not sink the run
            self._logger.error("Artifact disclosure gate could not run: %s", exc, exc_info=True)
            return {"status": "error", "error": str(exc), "root": str(root)}

        if not report.clean:
            self._logger.error(
                "DO NOT SHARE outputs/%s — the artifact disclosure gate found "
                "%d credential shape(s). See %s.",
                engagement_id,
                len(report.findings),
                root / SCAN_REPORT_FILENAME,
            )
        return {
            "status": "clean" if report.clean else "credential_material_found",
            "root": str(root),
            "report_file": str(root / SCAN_REPORT_FILENAME),
            "files_scanned": report.files_scanned,
            "bytes_scanned": report.bytes_scanned,
            "credential_findings": len(report.findings),
            "advisory_suspicions": len(report.suspicions),
            "summary": report.summary_line(),
        }

    def _authentication_summary(self) -> dict[str, Any]:
        """Authentication state as the report and the run summary render it."""
        assertion = self._auth_assertion
        return {
            "mechanism": self._auth_mechanism.value,
            "roles": sorted(self._role_sessions),
            "multi_role": len([r for r, s in self._role_sessions.items() if s.get("established")])
            >= 2,
            "authenticated": bool(assertion and assertion.established),
            "assertion": assertion.model_dump(mode="json") if assertion else None,
            # Session maintenance, stated so the numbers cannot contradict each
            # other silently. `session_losses_detected` counts ONLY responses to
            # requests that actually carried the session; the engagement's own
            # anonymous controls are counted separately, because a run that
            # reports fifteen losses and zero re-authentications is telling the
            # operator nothing unless it also says what those fifteen were.
            "session_losses_detected": self._session_sentinel.losses_detected,
            "control_responses_ignored": self._session_sentinel.control_responses_ignored,
            "pre_session_signals": self._session_sentinel.pre_session_signals,
            "session_checks_performed": self._session_sentinel.checks_requested,
            "session_false_alarms": self._session_sentinel.false_alarms,
            "reauthentications": self._session_sentinel.reauths_triggered,
        }

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
