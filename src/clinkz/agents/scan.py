"""Deterministic Scan Agent (v2) — service-specific methods with LLM supervision.

Unlike the v1 ScanAgent (which ran a free-form ReAct loop), this agent
follows a fixed sequence of tool steps with LLM checkpoints:

    1. LLM plans scan strategy          (PLANNING checkpoint)
    2. Execute service-specific scans    (TOOL — deterministic per service)
    3. LLM reviews each tool output      (REASONING checkpoint)
    4. LLM checks coverage sufficiency   (REASONING checkpoint)
    5. Expand coverage if insufficient   (TOOL — conditional)
    6. Build structured result           (CODE — deterministic)

Every tool call goes through the ToolResolver (never direct imports).
Every LLM call goes through self.llm (from BaseAgent).
"""

from __future__ import annotations

import json
import logging
import re as _re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from clinkz.agents._dom_sources import body_reads_dom_source
from clinkz.agents._origin import same_origin
from clinkz.agents._route_discovery import (
    FetchResult,
    default_discoverers,
    run_route_discovery,
)
from clinkz.agents._url_safety import find_session_setter_urls, is_state_changing_url
from clinkz.agents._url_shape import (
    STATIC_ASSET_EXTENSIONS,
    crawl_visit_priority,
    path_extension,
)
from clinkz.agents.base import BaseAgent
from clinkz.llm.base import LLMClient
from clinkz.models.recon import (
    ReconResult,
)
from clinkz.models.scan import (
    CoverageAssessment,
    DBScanResult,
    Endpoint,
    FTPScanResult,
    HTTPScanResult,
    ParamLocation,
    ScanResult,
    ServiceScanResult,
    SMBScanResult,
    SSHScanResult,
)
from clinkz.models.scope import EngagementScope
from clinkz.observability.ledger import (
    ComponentKind,
    record_contribution,
    record_dead_seam,
)
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase
from clinkz.tools.resolver import ToolResolver

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "scan_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")

# Measured costs of the scan's long steps, against a live SPA. These are what
# the budget guards compare against: a guard has to know what the work it is
# about to start COSTS, because "the clock has not run out yet" says nothing
# about whether the step will finish before it does.
#
# One full HTTP pass = crawl + 80-URL rate-limited enrichment + route discovery
# + directory fuzz + schema learning ≈ 6 min, of which the fuzz alone is ≈ 5 min
# and logs nothing at all while it runs.
_COST_EXPANSION_PASS = 420  # a whole re-scan for one coverage gap
_COST_FUZZ = 330  # directory fuzzing
_COST_CRAWL = 90  # crawl + enrichment


class ScanAgent(BaseAgent):
    """Attack surface mapper — tool-driven with LLM supervision and fallback chains.

    Args:
        llm: LLM client for reasoning checkpoints.
        tools: Passed to BaseAgent (not used directly — resolver handles dispatch).
        scope: Engagement scope for target validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        resolver: Optional pre-built ToolResolver.
        knowledge_base: Optional knowledge base for security testing reference.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        resolver: ToolResolver | None = None,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            knowledge_base=knowledge_base,
            **kwargs,
        )
        self._resolver: ToolResolver = resolver if resolver is not None else ToolResolver()
        self._session_cookies: dict[str, str] = {}
        # Auth headers for JWT/bearer sessions (e.g. Juice Shop), sent on
        # authenticated HTTP crawl/enrichment requests alongside cookies.
        self._session_headers: dict[str, str] = {}
        # Wall-clock deadline for this phase; ``None`` until run() starts, which
        # is what keeps every direct-invocation caller (smoke suites, drivers,
        # scan_additional) unbudgeted and byte-identical.
        self._deadline: float | None = None

    # ------------------------------------------------------------------
    # Phase budget
    # ------------------------------------------------------------------

    def _budget_exhausted(self) -> bool:
        """Whether the scan phase's own wall-clock budget has run out.

        The scan agent bounds itself for the same reason the research agent
        does: the orchestrator's phase timeout force-kills the agent and
        **discards its return value**, so an over-running scan delivers not a
        smaller map but no map at all — and the Exploit planner then has no
        endpoints to plan against.

        Prefer :meth:`_budget_allows` at any guard in front of work that takes
        real time. This predicate only says the budget is *already* gone, which
        is too late for a step that is about to spend five minutes.
        """
        return self._deadline is not None and time.monotonic() >= self._deadline

    def _budget_remaining(self) -> float:
        """Seconds left in the phase budget (``inf`` when unbudgeted)."""
        if self._deadline is None:
            return float("inf")
        return max(0.0, self._deadline - time.monotonic())

    def _budget_allows(self, seconds_needed: float, what: str) -> bool:
        """Whether enough budget remains to FINISH *seconds_needed* of work.

        This is the question a cooperative budget has to ask, and asking the
        other one — "has the budget run out?" — is what made the first two
        attempts at this fail identically. Directory fuzzing takes about five
        minutes and logs nothing while it runs; started with 104 seconds left it
        finished 17 seconds after the orchestrator had already given up and
        thrown the whole attack surface away. The guard has to know what the
        work costs, not just what the clock says.

        Args:
            seconds_needed: Measured cost of the step about to run.
            what: Step name, for the log line when it is skipped.

        Returns:
            ``True`` when the step may run (always, when unbudgeted).
        """
        remaining = self._budget_remaining()
        if remaining >= seconds_needed:
            return True
        self._logger.warning(
            "Scan budget: skipping %s — %.0fs left, it needs about %.0fs. "
            "Returning the surface mapped so far.",
            what,
            remaining,
            seconds_needed,
        )
        return False

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "scan"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Execute the 6-step deterministic scan pipeline.

        Args:
            input_data: Must contain ``recon_result`` (ReconResult dict or object).

        Returns:
            Dict with ``result`` (ScanResult dict), ``summary``, and ``status``.
        """
        # Parse recon_result from input — accepts:
        # 1. ReconResult object directly
        # 2. Dict with ReconResult fields
        # 3. Dict with "result" key containing ReconResult dict (from recon agent output)
        raw_recon = input_data.get("recon_result")
        if raw_recon is None:
            raise ValueError("ScanAgent requires 'recon_result' in input_data")

        if isinstance(raw_recon, ReconResult):
            recon_result = raw_recon
        elif isinstance(raw_recon, dict):
            # If it's the full recon output dict (with "result" key), unwrap it
            if "result" in raw_recon and isinstance(raw_recon["result"], dict):
                recon_result = ReconResult.model_validate(raw_recon["result"])
            else:
                recon_result = ReconResult.model_validate(raw_recon)
        else:
            raise TypeError(f"Unexpected recon_result type: {type(raw_recon)}")

        target = recon_result.target
        # Capture session cookies from orchestrator for authenticated crawling
        self._session_cookies = input_data.get("session_cookies", {})
        if self._session_cookies:
            self._logger.info(
                "ScanAgent received session cookies: %s",
                list(self._session_cookies.keys()),
            )
        # Capture JWT/bearer auth headers for authenticated crawling (Juice Shop).
        self._session_headers = input_data.get("session_headers", {})
        if self._session_headers:
            self._logger.info(
                "ScanAgent received auth headers: %s",
                list(self._session_headers.keys()),
            )
        # The login request shape the authenticator proved against this target.
        # Unioned into the endpoint set below so the credential-attack classes
        # get a real body injection point on the login route.
        self._proven_login: dict[str, Any] = input_data.get("proven_login") or {}
        from clinkz.config import settings

        self._deadline = time.monotonic() + settings.scan_time_budget
        self._logger.info(
            "ScanAgent v2 starting — target: %s (budget %.0fs)",
            target,
            settings.scan_time_budget,
        )

        # Step 1: LLM plans scan strategy (PLANNING checkpoint)
        self._logger.info("Step 1: LLM plans scan strategy")
        plan = await self._llm_plan_scan_strategy(recon_result)
        self._logger.info("Step 1 complete: scan plan ready")

        # Step 2: Execute service-specific scans (TOOL — deterministic)
        self._logger.info("Step 2: Execute service-specific scans")
        scan_results = await self._step_execute_scans(recon_result, plan)
        self._logger.info("Step 2 complete: %d service scans done", len(scan_results))

        # Step 3: LLM reviews each tool output (REASONING checkpoint)
        self._logger.info("Step 3: LLM reviews scan results")
        analysis = await self._llm_review_scan_results(scan_results)
        self._logger.info("Step 3 complete: analysis ready")

        # Step 4: LLM checks coverage sufficiency (REASONING checkpoint)
        self._logger.info("Step 4: LLM coverage check")
        coverage = await self._llm_check_coverage(scan_results, analysis)
        self._logger.info(
            "Step 4 complete: sufficient=%s, gaps=%d",
            coverage.sufficient,
            len(coverage.gaps),
        )

        # Step 5: Expand coverage if insufficient (TOOL — conditional).
        # Coverage expansion re-runs the WHOLE HTTP scan per gap — crawl,
        # enrichment, route discovery, schema learning — so it is both the step
        # most likely to push the phase past its budget and the most optional:
        # it adds to a map that already exists.
        #
        # The entry test is "is there enough budget left to finish a pass",
        # not merely "has the budget run out". Those differ, and the difference
        # is the whole fix: with a sliver of budget remaining, one pass starts,
        # overruns, and the orchestrator's backstop force-kills the agent —
        # which loses the ENTIRE map rather than trimming it. Measured on a live
        # SPA, the first expansion pass alone took ~6 minutes.
        if not coverage.sufficient and not self._budget_allows(
            _COST_EXPANSION_PASS, "coverage expansion (Step 5)"
        ):
            self._logger.warning(
                "Step 5: SKIPPED — %d gap(s) left unexpanded: %s",
                len(coverage.gaps),
                "; ".join(coverage.gaps[:3]),
            )
            coverage.gaps.append(
                "Coverage expansion was skipped: the scan phase's wall-clock budget "
                "(SCAN_TIME_BUDGET) would not have covered another pass."
            )
        elif not coverage.sufficient:
            self._logger.info("Step 5: Expanding coverage (%d gaps)", len(coverage.gaps))
            additional = await self._step_expand_coverage(coverage.gaps, recon_result)
            scan_results.extend(additional)
            self._logger.info("Step 5 complete: %d additional scans", len(additional))
        else:
            self._logger.info("Step 5: Skipped (coverage sufficient)")

        # Step 6: Build structured result (CODE — deterministic)
        self._logger.info("Step 6: Building result")
        result = self._build_result(recon_result, scan_results, coverage)
        self._logger.info("ScanAgent v2 complete for %s", target)

        # Persist discovered endpoints to shared state DB
        await self._persist_endpoints(result)

        return {
            "result": result.model_dump(mode="json"),
            "summary": analysis,
            "status": "complete",
        }

    # ------------------------------------------------------------------
    # Public API for Exploit Agent
    # ------------------------------------------------------------------

    async def scan_additional(self, targets: list[str]) -> list[ServiceScanResult]:
        """Scan additional targets requested by the Exploit Agent.

        Args:
            targets: List of target strings (IP:port or URL) to scan.

        Returns:
            List of ServiceScanResult for each scanned target.
        """
        results: list[ServiceScanResult] = []
        for target_str in targets:
            # Try HTTP scan for URLs
            if target_str.startswith(("http://", "https://")):
                http_result = await self._scan_http_service(target_str, 80, [])
                results.append(ServiceScanResult(service_type="http", port=80, result=http_result))
            else:
                self._logger.info("scan_additional: skipping non-HTTP target %s", target_str)
        return results

    # ------------------------------------------------------------------
    # Step 1: LLM Plans Scan Strategy
    # ------------------------------------------------------------------

    async def _llm_plan_scan_strategy(self, recon_result: ReconResult) -> str:
        """Ask LLM to plan the scan strategy based on recon results.

        Args:
            recon_result: Structured recon output.

        Returns:
            LLM-generated scan plan text.
        """
        services_desc = []
        for svc in recon_result.services.services:
            desc = f"Port {svc.port}/{svc.protocol}: {svc.service_name}"
            if svc.version:
                desc += f" ({svc.version})"
            services_desc.append(desc)

        tech_desc = [
            f"{t.name} {t.version or ''} ({t.category})"
            for t in recon_result.tech_stack.technologies
        ]

        prompt = (
            "You are planning a scan strategy for a penetration test.\n"
            f"Target: {recon_result.target}\n"
            f"Open ports: {recon_result.ports.open_ports}\n"
            f"Services:\n" + "\n".join(f"  - {s}" for s in services_desc) + "\n"
            f"Technology stack: {', '.join(tech_desc) or 'unknown'}\n\n"
            "For each service, describe:\n"
            "1. What specific scans should be run\n"
            "2. What tools/capabilities to use\n"
            "3. Priority order\n"
            "4. Any special considerations (authentication, WAF, etc.)\n"
            "Respond concisely."
        )
        return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Step 2: Execute Service-Specific Scans
    # ------------------------------------------------------------------

    async def _step_execute_scans(
        self, recon_result: ReconResult, plan: str
    ) -> list[ServiceScanResult]:
        """Dispatch scans based on service type from recon results.

        Args:
            recon_result: Structured recon output.
            plan: LLM-generated scan plan (for context, not direct execution).

        Returns:
            List of ServiceScanResult, one per scanned service.
        """
        results: list[ServiceScanResult] = []
        target = recon_result.target

        tech_names = [t.name.lower() for t in recon_result.tech_stack.technologies]

        for svc in recon_result.services.services:
            try:
                if svc.is_http:
                    http_result = await self._scan_http_service(target, svc.port, tech_names)
                    results.append(
                        ServiceScanResult(service_type="http", port=svc.port, result=http_result)
                    )
                elif svc.service_name in ("ftp",):
                    ftp_result = await self._scan_ftp_service(target, svc.port)
                    results.append(
                        ServiceScanResult(service_type="ftp", port=svc.port, result=ftp_result)
                    )
                elif svc.service_name in ("ssh",):
                    ssh_result = await self._scan_ssh_service(target, svc.port)
                    results.append(
                        ServiceScanResult(service_type="ssh", port=svc.port, result=ssh_result)
                    )
                elif svc.service_name in ("microsoft-ds", "netbios-ssn"):
                    smb_result = await self._scan_smb_service(target, svc.port)
                    results.append(
                        ServiceScanResult(service_type="smb", port=svc.port, result=smb_result)
                    )
                elif svc.service_name in ("mysql", "postgresql", "mssql", "oracle"):
                    db_result = await self._scan_database_service(
                        target, svc.port, svc.service_name
                    )
                    results.append(
                        ServiceScanResult(service_type="database", port=svc.port, result=db_result)
                    )
                else:
                    self._logger.info(
                        "Unsupported service '%s' on port %d — skipping",
                        svc.service_name,
                        svc.port,
                    )
            except Exception as exc:
                self._logger.error(
                    "Scan failed for %s on port %d: %s",
                    svc.service_name,
                    svc.port,
                    exc,
                )

        return results

    # ------------------------------------------------------------------
    # Service-specific scan methods
    # ------------------------------------------------------------------

    async def _scan_http_service(
        self, target: str, port: int, tech_stack: list[str]
    ) -> HTTPScanResult:
        """Scan an HTTP service using crawling and fuzzing fallback chains.

        Args:
            target: IP, hostname, or URL.
            port: HTTP port number.
            tech_stack: List of technology names (lowercase).

        Returns:
            HTTPScanResult with endpoints, forms, directories.
        """
        # If target is already a URL, use it directly
        if target.startswith(("http://", "https://")):
            parsed_target = urlparse(target)
            host = parsed_target.hostname or target
            scheme = parsed_target.scheme
            actual_port = parsed_target.port or port
            url = (
                f"{scheme}://{host}:{actual_port}"
                if actual_port not in {80, 443}
                else f"{scheme}://{host}"
            )
        else:
            host = target
            scheme = "https" if port in {443, 8443} else "http"
            url = f"{scheme}://{target}:{port}" if port not in {80, 443} else f"{scheme}://{target}"

        endpoints: list[Endpoint] = []
        directories: list[str] = []
        crawl_tool = ""
        fuzz_tool = ""
        # Trigger URL → session-value setter URLs it references, collected as the
        # crawl visits each page and stamped onto the trigger endpoints below.
        # This annotation is what lets the Exploit planner queue the injection
        # family against an otherwise param-less cross-request trigger (DVWA SQLi
        # ``high``, whose ``$_SESSION['id']`` is set via ``session-input.php``).
        self._session_setter_refs: dict[str, list[str]] = {}
        self._response_features: dict[str, dict[str, Any]] = {}

        # Crawl using fallback chain. Skipped outright once the budget is gone:
        # this method is re-entered once per coverage gap, and a crawl started
        # past the deadline cannot deliver anything the caller will still be
        # alive to return.
        if not self._budget_allows(_COST_CRAWL, f"the crawl of {url}"):
            return HTTPScanResult(technologies_detected=list(tech_stack))
        try:
            crawl_tool, crawl_result = await self._resolver.try_until_sufficient(
                "web_crawling",
                5,
                self._run_crawl_tool,
                url,
            )
            if crawl_result:
                # Crawl-safety: never visit or persist links that mutate the
                # target's security posture (WAF/security-level toggles, logout).
                # The enrichment step below GET-visits each URL, so an unfiltered
                # toggle link (e.g. security.php?phpids=on) would poison the
                # shared engagement session for every later phase.
                safe_crawl = [str(u) for u in crawl_result if not is_state_changing_url(str(u))]
                skipped = len(crawl_result) - len(safe_crawl)
                if skipped:
                    self._logger.info(
                        "Crawl-safety: skipped %d state-changing link(s) from crawl output",
                        skipped,
                    )
                for ep_url in safe_crawl:
                    endpoints.append(Endpoint(url=ep_url))
                # Tools like katana return URL strings only — they don't extract
                # form fields or query-string parameters. Without that, every
                # Endpoint downstream has params=[] and the Exploit Agent can't
                # build a single _test_* probe. Visit each discovered URL and
                # extract forms + query params so the data contract holds.
                enriched = await self._enrich_endpoints_with_params(safe_crawl)
                if enriched:
                    self._merge_into_crawl_endpoints(enriched)
        except ValueError:
            self._logger.warning("No crawling tools available — using HTTP client fallback")
            crawl_tool = "http_client_crawl"
            fallback_urls = await self._http_crawl_fallback(url, max_depth=2, max_pages=50)
            for ep_url in fallback_urls:
                if is_state_changing_url(ep_url):
                    continue
                endpoints.append(Endpoint(url=ep_url))

        # SPA/API route discovery — recover JS-runtime routes (/api, /rest,
        # path-param and concat-built search routes) that an HTML/JS crawl
        # under-reports on modern single-page apps. Carries the engagement
        # session via _discovery_http_get and is purely additive: discovered
        # endpoints union into the crawl set, deduped by (url, method).
        #
        # Seeded from every page the crawl found, not only the origin root.
        # Discovery used to read `<script src>` tags from the root document
        # alone, so a script referenced only by `/admin.html` was structurally
        # unreachable: the crawl fetched the file and the code that mines files
        # was never handed it. The two halves were never joined — which is the
        # whole authbypass gap, and it was never a parsing failure.
        page_seeds = self._discovery_page_seeds(endpoints, url)
        try:
            discovered = await run_route_discovery(
                url,
                self._discovery_http_get,
                default_discoverers(page_seeds),
                log=self._logger,
            )
        except Exception as exc:  # discovery must never abort the scan phase
            self._logger.warning("Route discovery failed: %s", exc)
            discovered = []
        if discovered:
            seen_disc = {(ep.url, ep.method) for ep in endpoints}
            added = 0
            for ep in discovered:
                key = (ep.url, ep.method)
                if key not in seen_disc:
                    endpoints.append(ep)
                    seen_disc.add(key)
                    added += 1
            self._logger.info(
                "Route discovery: added %d new endpoint(s) (%d discovered)",
                added,
                len(discovered),
            )

        # Fuzz using fallback chain. Directory fuzzing adds paths, never
        # parameters, so it is the first thing to drop when time is short — and
        # it is the single most expensive step, running about five minutes while
        # logging nothing, which is exactly how the phase overran unnoticed.
        if not self._budget_allows(_COST_FUZZ, f"directory fuzzing of {url}"):
            fuzz_tool = ""
        else:
            try:
                fuzz_tool, fuzz_result = await self._resolver.try_until_sufficient(
                    "directory_fuzzing",
                    3,
                    self._run_fuzz_tool,
                    url,
                )
                if fuzz_result:
                    # Crawl-safety applies to fuzz hits exactly as it does to
                    # crawl output: a wordlist finds `/logout.php` as readily as
                    # `/admin`, and the enrichment/exploit phases GET whatever
                    # lands here.
                    safe_fuzz = [str(d) for d in fuzz_result if not is_state_changing_url(str(d))]
                    dropped = len(fuzz_result) - len(safe_fuzz)
                    if dropped:
                        self._logger.info(
                            "Crawl-safety: skipped %d state-changing path(s) from fuzz output",
                            dropped,
                        )
                    directories = safe_fuzz
                    # Fuzz hits have to become endpoints, not just directory
                    # strings. `directories` reaches the state store and stops
                    # there; the Exploit planner ranks over `HTTPScanResult.
                    # endpoints`, so a path that only ever lands in the
                    # directory list is discovered and then never attacked —
                    # content discovery that finds `/admin` and does nothing
                    # with it has not functioned either.
                    known = {ep.url for ep in endpoints}
                    for path_url in safe_fuzz:
                        if path_url not in known:
                            endpoints.append(Endpoint(url=path_url))
                            known.add(path_url)
            except ValueError:
                self._logger.warning("No fuzzing tools available")

        # Merge parameterized endpoints from crawl fallback (forms, query params).
        if hasattr(self, "_crawl_endpoints") and self._crawl_endpoints:
            self._merge_crawl_endpoints_preferring_params(endpoints, self._crawl_endpoints)
            self._crawl_endpoints = []

        # The proven login shape (observed by the authenticator, not guessed).
        # Replaces any param-less twin of the same route — a discovered
        # `POST /rest/user/login` with no body is the same endpoint with less
        # information.
        self._apply_proven_login(endpoints)

        # Learn from the live target what the frontend's source could not say:
        # which write verbs each route accepts (OPTIONS) and what a write body
        # contains (the collection's own representation). Safe methods only —
        # mapping a surface must never write to it.
        try:
            method_endpoints = await self._learn_api_schemas(endpoints)
        except Exception as exc:  # never abort the scan phase
            self._logger.warning("API schema learning failed: %s", exc)
            method_endpoints = []
        for ep in method_endpoints:
            if (ep.url, ep.method) not in {(e.url, e.method) for e in endpoints}:
                endpoints.append(ep)

        # Stamp session-setter annotations onto their trigger endpoints (or emit
        # a param-less trigger endpoint if the crawl produced none) so the
        # cross-request injection point is queued downstream.
        self._apply_session_setter_annotations(endpoints)

        # Stamp the response features the crawl observed (cookie names set, form
        # present) onto their endpoints, so the Exploit planner can rank a class
        # by whether its precondition is actually present rather than by a path
        # substring.
        self._apply_response_feature_annotations(endpoints)

        return HTTPScanResult(
            endpoints=endpoints,
            directories=directories,
            technologies_detected=list(tech_stack),
            crawl_tool_used=crawl_tool,
            fuzz_tool_used=fuzz_tool,
        )

    def _build_tool_input(self, url: str) -> dict[str, Any]:
        """Build the tool input dict, attaching session cookies when present."""
        tool_input: dict[str, Any] = {"url": url, "target": url}
        if self._session_cookies:
            tool_input["cookies"] = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
        return tool_input

    async def _run_crawl_tool(self, tool_name: str, url: str) -> list[str]:
        """Execute a crawling tool by name and return discovered URLs.

        Args:
            tool_name: Name of the crawl tool (e.g., "katana").
            url: Target URL to crawl.

        Returns:
            List of discovered URL strings.
        """
        match = self._resolver.find_tool("web_crawling")
        if match is None or match.tool_class is None or not match.available:
            return []

        return await self._run_discovery_tool("web_crawling", tool_name, url)

    async def _run_fuzz_tool(self, tool_name: str, url: str) -> list[str]:
        """Execute a fuzzing tool by name and return discovered paths.

        Args:
            tool_name: Name of the fuzz tool (e.g., "ffuf").
            url: Target URL to fuzz.

        Returns:
            List of discovered URL strings, one per surviving hit.
        """
        return await self._run_discovery_tool("directory_fuzzing", tool_name, url)

    @staticmethod
    def _discovery_page_seeds(endpoints: list[Endpoint], base_url: str) -> list[str]:
        """Crawl-discovered pages whose scripts route discovery should also read.

        Filtered to things worth fetching as *documents*: same-origin, not a
        static asset, and never a state-changing URL — discovery GETs these, and
        the crawl-safety rule does not stop applying because a different
        subsystem is doing the fetching.

        The origin comparison covers the SCHEME, not just the host — these URLs
        were read out of the target's own HTML, so a page can offer
        ``ftp://<same-host>/x``, matching netloc while naming a protocol this
        subsystem never intended to speak. That is delegated to the shared fence
        (:mod:`clinkz.agents._origin`) rather than written here: the same
        omission was made independently by this fetcher and by the exploit
        planner (``840ddec``) within one week, which makes it a missing
        abstraction rather than two mistakes.

        Ordered by ``crawl_visit_priority`` for the same reason the enrichment
        budget is: the cap has to fall on the least informative pages, not on
        whichever ones a concurrent crawler happened to emit last.

        Args:
            endpoints: The endpoint set as it stands after crawl + enrichment.
            base_url: Origin root, already seeded by the discoverers themselves.

        Returns:
            Deduplicated page URLs, best-first.
        """
        seen: set[str] = {base_url}
        pages: list[str] = []
        for ep in endpoints:
            page = (ep.url or "").split("#", 1)[0]
            if not page or page in seen:
                continue
            if is_state_changing_url(page):
                continue
            if not same_origin(page, base_url):
                continue
            if path_extension(urlparse(page).path) in STATIC_ASSET_EXTENSIONS:
                continue
            seen.add(page)
            pages.append(page)
        pages.sort(key=crawl_visit_priority)
        return pages

    async def _run_discovery_tool(self, capability: str, tool_name: str, url: str) -> list[str]:
        """Resolve a discovery tool by capability, run it, and read its contract.

        The one seam every surface-discovery tool passes through. It reads the
        producer's **declared** contract (:meth:`ToolOutput.discovered_urls`)
        rather than guessing at field names.

        That guess is not a hypothetical failure mode. This method's predecessor
        read ``parsed.paths`` and ``parsed.directories``; ``FfufOutput`` carries
        neither — it has ``results`` — so both ``hasattr`` checks were False and
        the seam returned an empty list on every run since it was written. ffuf
        executed, found paths, and had 100% of its output discarded, and nothing
        anywhere failed: an empty list from a fuzzer is exactly what a target
        with no hidden content looks like. Content discovery had never
        functioned, and the crawler covered for it well enough that the totals
        never looked wrong.

        So the contract is declared on the producer and the two failure modes are
        now distinguishable:

        * the output type does not declare ``discovered_urls`` → a **dead seam**,
          logged at WARNING and recorded on the ledger as structurally inert;
        * the output type declares it and returns nothing → an honest empty
          result, recorded as a zero contribution the end-of-run summary reports.

        The *tool_name* the resolver's fallback chain nominated is honoured
        rather than ignored. Both predecessors dropped it and re-resolved the
        capability, so ``try_until_sufficient`` walking
        ``katana → gospider → hakrawler`` ran katana three times: the chain was
        declared, iterated, and had no effect.

        Args:
            capability: Capability to resolve (``"web_crawling"``, …).
            tool_name: The chain entry to run. Falls back to capability
                resolution when no wrapper is registered under that name.
            url: Target URL.

        Returns:
            Discovered URL strings, or an empty list when no tool resolved.
        """
        match = self._resolver.find_tool_by_name(tool_name) if tool_name else None
        if match is None or not match.available:
            match = self._resolver.find_tool(capability)
        if match is None or match.tool_class is None or not match.available:
            return []

        tool = match.tool_class(scope=self.scope)
        tool_name = tool.name
        args = tool.validate_input(self._build_tool_input(url))
        raw = await tool.execute(args)
        parsed = tool.parse_output(raw)

        if not type(parsed).declares_discovery():
            note = (
                f"{type(parsed).__name__} declares no discovered_urls() contract — "
                f"{tool_name}'s output cannot reach the surface map"
            )
            self._logger.warning("DEAD SEAM: %s (capability %s) — %s", tool_name, capability, note)
            record_dead_seam(name=tool_name, kind=ComponentKind.TOOL, note=note)
            return []

        urls = [str(u) for u in parsed.discovered_urls() if str(u)]
        record_contribution(
            name=tool_name,
            kind=ComponentKind.TOOL,
            items=len(urls),
            ok=bool(parsed.success),
            note=f"capability={capability}",
        )
        if parsed.success and not urls:
            self._logger.info("%s ran successfully and contributed 0 URL(s) for %s", tool_name, url)
        return urls

    @staticmethod
    def _merge_crawl_endpoints_preferring_params(
        endpoints: list[Endpoint], crawl_endpoints: list[Endpoint]
    ) -> None:
        """Merge parameterised crawl endpoints into *endpoints*, preferring params.

        Deduplicate by ``(url, method)`` but **prefer the version with params**: a
        URL-only crawler (katana) adds a bare ``Endpoint(url=..., params=[])`` for
        every discovered URL, so when enrichment later finds the same URL as a
        parameterised link, its params must **upgrade** the bare endpoint in place
        rather than be skipped. Skipping it (the prior behaviour) left query /
        redirect links such as ``.../open_redirect/source/low.php?redirect=...``
        param-less in the endpoint set, so the Exploit planner's param-gated
        methodologies (open-redirect, SQLi, LFI, …) never ran against them — the
        real endpoint was silently invisible to ``_test_open_redirect``.

        Mutates *endpoints* in place (append new, upgrade bare).
        """
        by_key: dict[tuple[str, str], Endpoint] = {}
        for ep in endpoints:
            by_key.setdefault((ep.url, ep.method), ep)
        for ep in crawl_endpoints:
            key = (ep.url, ep.method)
            existing = by_key.get(key)
            if existing is None:
                endpoints.append(ep)
                by_key[key] = ep
            elif ep.params and not existing.params:
                existing.params = list(ep.params)
                if ep.param_locations and not existing.param_locations:
                    existing.param_locations = dict(ep.param_locations)
                if ep.content_type and not existing.content_type:
                    existing.content_type = ep.content_type

    def _merge_into_crawl_endpoints(self, new_endpoints: list[Endpoint]) -> None:
        """Append new parameterized endpoints into ``self._crawl_endpoints``.

        ``_crawl_endpoints`` is the staging list that ``_scan_http_service``
        merges into the final endpoint set just before assembling
        ``HTTPScanResult``. Tools that produce URL-only output (katana) and
        tools that produce form-aware output (the HTTP fallback) both land
        here so the merge step is the single point of truth.
        """
        existing = getattr(self, "_crawl_endpoints", None)
        if existing is None:
            self._crawl_endpoints = []
            existing = self._crawl_endpoints
        seen: set[tuple[str, str, tuple[str, ...]]] = {
            (ep.url, ep.method, tuple(ep.params)) for ep in existing
        }
        for ep in new_endpoints:
            key = (ep.url, ep.method, tuple(ep.params))
            if key not in seen:
                existing.append(ep)
                seen.add(key)

    def _record_session_setters(self, page_url: str, body: str) -> None:
        """Record session-value setter URLs *page_url* references, for stamping.

        Populates ``self._session_setter_refs`` (trigger URL → resolved,
        same-origin setter URLs) as the crawl visits each page. DVWA's SQLi
        ``high`` page references ``session-input.php`` via
        ``onclick="popUp(...)"``; recording it lets ``_scan_http_service`` stamp
        the trigger endpoint so the Exploit planner queues the injection family
        against it (the injection point is cross-request and invisible to a
        param scan). Scope- and state-change-guarded; the Exploit-side link gate
        is the correctness filter, so a loose match here is safe.
        """
        refs = getattr(self, "_session_setter_refs", None)
        if refs is None or not body:
            return
        resolved = [
            u
            for u in find_session_setter_urls(page_url, body)
            if self.scope.contains(u) and not is_state_changing_url(u)
        ]
        if not resolved:
            return
        existing = refs.setdefault(page_url, [])
        for u in resolved:
            if u not in existing:
                existing.append(u)

    @staticmethod
    def _response_feature_key(url: str) -> str:
        """Normalised identity a response-feature record is filed under.

        The crawl visits ``/vulnerabilities/csrf/`` while the endpoint the
        planner ranks is often that page's form action — ``.../csrf/#``, an
        ``action="#"`` resolved against the page. Same page, two spellings, so
        the annotation is keyed on the URL with its fragment and trailing slash
        removed and both spellings land on one record.
        """
        return url.split("#", 1)[0].rstrip("/")

    def _record_response_features(self, page_url: str, headers: dict[str, str], body: str) -> None:
        """Record the observable response features of a page the crawl fetched.

        Two features, both of which decide whether a whole vuln-class can fire
        at an endpoint at all:

        * **cookie names the response set** — a session-token test measures the
          entropy of tokens a page issues; on a page that issues none it records
          an empty sample and can never confirm. Only the NAMES are kept: a
          cookie value is authentication material and has no business in the
          endpoint inventory, the message bus, or the report.
        * **whether the page rendered a form** — the CSRF, stored-XSS, upload,
          brute-force and client-side-logic classes all evaluate a submission.

        Failure here is silent by design (a malformed ``Set-Cookie`` should not
        abort a crawl); the absence of a record simply means "not observed",
        which ranks the endpoint no worse than it did before the feature existed.

        Args:
            page_url: The URL that was fetched.
            headers: Response headers, lowercased keys.
            body: Response body.
        """
        features = getattr(self, "_response_features", None)
        if features is None:
            return
        raw_cookies = headers.get("set-cookie", "") if headers else ""
        names: list[str] = []
        for chunk in raw_cookies.split("\n"):
            name = chunk.split("=", 1)[0].strip()
            # A comma-joined multi-cookie header keeps only whole name=... pairs.
            if not name or "," in name or " " in name or ";" in name:
                continue
            if name not in names:
                names.append(name)
        record = features.setdefault(
            self._response_feature_key(page_url),
            {"sets_cookies": [], "has_form": False, "has_dom_source": False},
        )
        for name in names:
            if name not in record["sets_cookies"]:
                record["sets_cookies"].append(name)
        if "<form" in body.lower():
            record["has_form"] = True
        # Whether the page's OWN JavaScript reads an attacker-controllable DOM
        # source. This is the only signal that says "a DOM-XSS test could fire
        # here" — the class's path words cannot, since a DOM sink is a property
        # of what the page returned, not of what the route is called.
        if body_reads_dom_source(body):
            record["has_dom_source"] = True

    def _apply_response_feature_annotations(self, endpoints: list[Endpoint]) -> None:
        """Stamp recorded response features onto the endpoints they were seen on.

        Purely additive and never destructive: an endpoint the crawl never
        opened keeps its defaults, so a target where enrichment could not run
        ranks exactly as it did before this signal existed.
        """
        features = getattr(self, "_response_features", None)
        if not features:
            return
        annotated = 0
        for endpoint in endpoints:
            record = features.get(self._response_feature_key(endpoint.url))
            if record is None:
                continue
            cookies = [c for c in record["sets_cookies"] if c not in endpoint.sets_cookies]
            if cookies:
                endpoint.sets_cookies = [*endpoint.sets_cookies, *cookies]
            if record["has_form"]:
                endpoint.has_form = True
            if record.get("has_dom_source"):
                endpoint.has_dom_source = True
            annotated += 1
        self._logger.info(
            "Response features: annotated %d of %d endpoint(s) from %d observed page(s)",
            annotated,
            len(endpoints),
            len(features),
        )

    def _apply_proven_login(self, endpoints: list[Endpoint]) -> None:
        """Union the authenticator's PROVEN login request shape into *endpoints*.

        A login body is the one API schema no other source can reach: it is not
        in any collection's representation, the frontend passes its form object
        straight through without naming the fields, and provoking a validation
        error would mean POSTing to a credential endpoint. But the engagement
        already logged in — so the shape that worked is an observation we hold.

        Mutates *endpoints* in place: upgrades an existing param-less twin of
        the same route rather than appending a duplicate.
        """
        shape = getattr(self, "_proven_login", None) or {}
        url = str(shape.get("url") or "")
        fields = [str(f) for f in (shape.get("fields") or []) if f]
        if not url or not fields:
            return
        method = str(shape.get("method") or "POST").upper()
        content_type = str(shape.get("content_type") or "application/json")
        location = (
            ParamLocation.JSON_BODY if "json" in content_type.lower() else ParamLocation.FORM_BODY
        )
        for ep in endpoints:
            if ep.url.rstrip("/") == url.rstrip("/") and (ep.method or "GET").upper() == method:
                for name in fields:
                    if name not in ep.param_locations:
                        ep.params.append(name)
                        ep.param_locations[name] = location
                ep.content_type = ep.content_type or content_type
                self._logger.info("Login endpoint %s upgraded with its proven body shape", url)
                return
        endpoints.append(
            Endpoint(
                url=url,
                method=method,
                params=list(fields),
                content_type=content_type,
                param_locations=dict.fromkeys(fields, location),
            )
        )
        self._logger.info("Login endpoint %s added with its proven body shape", url)

    def _apply_session_setter_annotations(self, endpoints: list[Endpoint]) -> None:
        """Stamp recorded session-setter refs onto their trigger endpoints.

        For each recorded trigger URL, set ``Endpoint.session_setters`` on the
        matching endpoint (a bare param-less URL the crawler already emitted), or
        append a new param-less trigger endpoint if the crawl produced none —
        either way the annotation reaches the Exploit planner. In-place, so it
        runs just before the ``HTTPScanResult`` is assembled.
        """
        refs = getattr(self, "_session_setter_refs", None)
        if not refs:
            return
        by_url: dict[str, Endpoint] = {}
        for ep in endpoints:
            by_url.setdefault(ep.url, ep)
            by_url.setdefault(ep.url.rstrip("/"), ep)
        for trigger_url, setters in refs.items():
            ep = by_url.get(trigger_url) or by_url.get(trigger_url.rstrip("/"))
            if ep is not None:
                ep.session_setters = list(dict.fromkeys([*ep.session_setters, *setters]))
            else:
                endpoints.append(
                    Endpoint(url=trigger_url, method="GET", session_setters=list(setters))
                )

    async def _discovery_http_get(self, url: str) -> FetchResult | None:
        """Session-carrying GET for route discovery and endpoint enrichment.

        Instantiates the ``http_request`` tool with the engagement session
        (cookies + JWT/bearer headers) and returns a :class:`FetchResult`.
        Returns ``None`` on any failure — no client available, out-of-scope URL
        (the tool's scope check raises), or network error — so a discoverer
        never raises on a single bad fetch.
        """
        http_match = self._resolver.find_tool("http_request")
        if not http_match or not http_match.available or not http_match.tool_class:
            return None
        try:
            tool = http_match.tool_class(
                scope=self.scope, engagement_id=self.engagement_id, stage="scan"
            )
            req_input: dict[str, Any] = {
                "url": url,
                "method": "GET",
                "follow_redirects": True,
            }
            if self._session_cookies:
                req_input["cookies"] = self._session_cookies
            if self._session_headers:
                req_input["headers"] = dict(self._session_headers)
            args = tool.validate_input(req_input)
            raw = await tool.execute(args)
            parsed = tool.parse_output(raw)
        except Exception as exc:
            self._logger.debug("Discovery fetch failed for %s: %s", url, exc)
            return None
        raw_headers = getattr(parsed, "response_headers", {}) or {}
        return FetchResult(
            status=getattr(parsed, "status_code", 0),
            body=getattr(parsed, "response_body", "") or "",
            headers={str(k).lower(): str(v) for k, v in raw_headers.items()},
        )

    async def _safe_method_probe(
        self, method: str, url: str
    ) -> tuple[int, str, dict[str, str]] | None:
        """Send one SAFE-method request for API schema learning.

        Restricted to ``GET``/``HEAD``/``OPTIONS`` — the methods RFC 9110
        defines as not changing the target's state — and asserted here rather
        than trusted from the caller, because this is the seam where a schema
        learner could otherwise turn surface mapping into a write. Returns
        ``(status, body, headers)`` or ``None`` on any failure.
        """
        verb = (method or "GET").upper()
        if verb not in ("GET", "HEAD", "OPTIONS"):
            self._logger.error(
                "Refusing %s during schema learning — only safe methods may map a surface", verb
            )
            return None
        http_match = self._resolver.find_tool("http_request")
        if not http_match or not http_match.available or not http_match.tool_class:
            return None
        try:
            tool = http_match.tool_class(
                scope=self.scope, engagement_id=self.engagement_id, stage="scan"
            )
            req_input: dict[str, Any] = {"url": url, "method": verb, "follow_redirects": False}
            if self._session_cookies:
                req_input["cookies"] = self._session_cookies
            if self._session_headers:
                req_input["headers"] = dict(self._session_headers)
            args = tool.validate_input(req_input)
            raw = await tool.execute(args)
            parsed = tool.parse_output(raw)
        except Exception as exc:
            self._logger.debug("Schema probe %s %s failed: %s", verb, url, exc)
            return None
        raw_headers = getattr(parsed, "response_headers", {}) or {}
        return (
            getattr(parsed, "status_code", 0),
            getattr(parsed, "response_body", "") or "",
            {str(k).lower(): str(v) for k, v in raw_headers.items()},
        )

    async def _learn_api_schemas(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        """Learn accepted methods and missing body schemas from the live target.

        Two safe-method sweeps, both budget-aware and both additive:

        * ``OPTIONS`` per route — the write verbs the target says it accepts,
          which is how a ``PUT``/``PATCH`` injection point becomes reachable at
          all when the frontend only ever calls ``GET``.
        * ``GET`` per write route with no known body — a REST collection's own
          records name the fields its writes take.

        Returns the endpoints discovered by the method sweep (the body schemas
        are filled in place on *endpoints*).
        """
        from clinkz.agents._api_schema import (
            learn_allowed_methods,
            learn_body_schema_from_representation,
        )

        if self._budget_exhausted():
            self._logger.info("API schema learning: skipped — scan budget exhausted")
            return []
        try:
            method_endpoints = await learn_allowed_methods(endpoints, self._safe_method_probe)
        except Exception as exc:  # schema learning must never abort the scan
            self._logger.warning("OPTIONS sweep failed: %s", exc)
            method_endpoints = []

        combined = [*endpoints, *method_endpoints]
        if self._budget_exhausted():
            self._logger.info("API body-schema learning: skipped — scan budget exhausted")
            return method_endpoints
        try:
            filled = await learn_body_schema_from_representation(combined, self._safe_method_probe)
        except Exception as exc:
            self._logger.warning("Representation sweep failed: %s", exc)
            filled = 0
        self._logger.info(
            "API schema learning: +%d method endpoint(s), %d body schema(s) learned",
            len(method_endpoints),
            filled,
        )
        return method_endpoints

    async def _enrich_endpoints_with_params(self, urls: list[str]) -> list[Endpoint]:
        """Fetch each URL and extract forms / query-param links as Endpoints.

        URL-only crawlers (katana, gospider) discover endpoints but don't open
        them and read forms — so without this enrichment the Endpoint objects
        downstream have empty ``params`` lists and the Exploit Agent has
        nothing to probe. We call this after the crawler returns and merge the
        results in alongside the bare URLs.

        Args:
            urls: List of URL strings discovered by the crawler.

        Returns:
            List of Endpoint objects with method + params for each form and
            each parameterized link found on the visited pages.
        """
        if not urls:
            return []

        # De-duplicate URLs (strip fragment + trailing slash) before visiting.
        # Cap the visit count so a giant katana run doesn't make scan O(n).
        max_visits = 80
        visited: set[str] = set()
        candidates: list[str] = []
        for u in urls:
            if is_state_changing_url(u):
                continue
            norm = u.split("#", 1)[0].rstrip("/")
            if norm and norm not in visited:
                visited.add(norm)
                candidates.append(u)

        # WHICH urls the budget covers is decided by relevance, not by the order
        # the crawler happened to emit them. A concurrent crawler's output order
        # varies run to run, so "the first 80" was a different 80 each time: the
        # DVWA brute-force page's login form was enriched in 2 of 3 identical
        # runs, which is a form endpoint appearing and disappearing from the
        # engagement for no reason on the target's side. Ordering by
        # :func:`crawl_visit_priority` (with the normalised URL as the
        # tie-break) makes the visited set a deterministic function of the
        # discovered set — and spends the budget on application pages before
        # static assets, doc files, source viewers and doubled-path artifacts.
        # The budget itself is unchanged; only the order is.
        prioritised = sorted(
            candidates, key=lambda u: (crawl_visit_priority(u), u.split("#", 1)[0])
        )
        ordered_urls = prioritised[:max_visits]
        if len(prioritised) > max_visits:
            self._logger.info(
                "Endpoint enrichment: %d of %d candidate URL(s) exceed the %d-visit budget and "
                "were not opened (lowest-priority dropped first) — first omitted: %s",
                len(prioritised) - max_visits,
                len(prioritised),
                max_visits,
                prioritised[max_visits],
            )

        enriched: list[Endpoint] = []
        seen_keys: set[tuple[str, str, tuple[str, ...]]] = set()
        visited_count = 0
        for current_url in ordered_urls:
            # Rate-limited enrichment of a large crawl is the single longest
            # stretch of the phase. Stopping here keeps every endpoint already
            # enriched — and because the list is priority-ordered, what is
            # dropped is the tail, not a random slice.
            if self._budget_exhausted():
                self._logger.warning(
                    "Endpoint enrichment: stopping at %d/%d URL(s) — scan budget exhausted",
                    visited_count,
                    len(ordered_urls),
                )
                break
            visited_count += 1
            try:
                res = await self._discovery_http_get(current_url)
                if res is None:
                    continue
                status, body = res.status, res.body
                if status < 200 or status >= 400 or not body:
                    continue

                # Record any session-value setter this page references (DVWA SQLi
                # ``high``'s ``session-input.php``) for cross-request injection.
                self._record_session_setters(current_url, body)

                # Record what the RESPONSE showed (a cookie issued, a form
                # rendered) so the exploit planner can rank a class by whether
                # its precondition is present rather than by a path substring.
                self._record_response_features(current_url, res.headers, body)

                # Extract forms — Endpoint per form action.
                for action_url, method, param_names in self._extract_forms(body, current_url):
                    if not param_names or is_state_changing_url(action_url):
                        continue
                    key = (action_url, method, tuple(param_names))
                    if key not in seen_keys:
                        enriched.append(Endpoint(url=action_url, method=method, params=param_names))
                        seen_keys.add(key)

                # Extract query-param links — Endpoint per parameterized link.
                base_origin = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
                for link in self._extract_links(body, current_url, base_origin):
                    if is_state_changing_url(link):
                        continue
                    link_parsed = urlparse(link)
                    if not link_parsed.query:
                        continue
                    param_names = [
                        p.split("=", 1)[0] for p in link_parsed.query.split("&") if "=" in p
                    ]
                    if not param_names:
                        continue
                    key = (link, "GET", tuple(param_names))
                    if key not in seen_keys:
                        enriched.append(Endpoint(url=link, method="GET", params=param_names))
                        seen_keys.add(key)
            except Exception as exc:
                self._logger.debug("Endpoint enrichment failed for %s: %s", current_url, exc)
                continue

        self._logger.info(
            "Endpoint enrichment: visited %d URLs, produced %d parameterized endpoints",
            visited_count,
            len(enriched),
        )
        return enriched

    async def _http_crawl_fallback(
        self, base_url: str, max_depth: int = 2, max_pages: int = 50
    ) -> list[str]:
        """Crawl a website using the HTTP client tool when no dedicated crawler is available.

        Fetches pages, parses links from HTML, and follows them up to max_depth.
        Also stores discovered forms in ``self._crawl_forms`` for the scan result.

        Args:
            base_url: Starting URL to crawl.
            max_depth: Maximum link-following depth.
            max_pages: Maximum number of pages to fetch.

        Returns:
            List of discovered URL strings.
        """
        http_match = self._resolver.find_tool("http_request")
        if not http_match or not http_match.available or not http_match.tool_class:
            self._logger.warning("No HTTP client tool available for crawl fallback")
            return []

        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        visited: set[str] = set()
        discovered: list[str] = []
        self._crawl_endpoints: list[Endpoint] = []
        queue: list[tuple[str, int]] = [(base_url, 0)]

        while queue and len(visited) < max_pages:
            current_url, depth = queue.pop(0)
            # Normalize for dedup (strip fragment/query)
            normalized = current_url.split("#")[0].split("?")[0].rstrip("/")
            if normalized in visited:
                continue
            visited.add(normalized)

            # Crawl-safety: don't fetch links that toggle a WAF / security level
            # or log out — they poison the shared engagement session.
            if is_state_changing_url(current_url):
                continue

            try:
                tool = http_match.tool_class(
                    scope=self.scope, engagement_id=self.engagement_id, stage="scan"
                )
                req_input: dict[str, Any] = {
                    "url": current_url,
                    "method": "GET",
                    "follow_redirects": True,
                }
                if self._session_cookies:
                    req_input["cookies"] = self._session_cookies
                if self._session_headers:
                    req_input["headers"] = dict(self._session_headers)
                args = tool.validate_input(req_input)
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                status = getattr(parsed, "status_code", 0)
                body = getattr(parsed, "response_body", "")
                if status < 200 or status >= 400 or not body:
                    continue

                discovered.append(current_url)

                # Record any session-value setter this page references (DVWA SQLi
                # ``high``'s ``session-input.php``) for cross-request injection.
                self._record_session_setters(current_url, body)

                # Same response-feature capture as the enrichment path, so the
                # planner's class preconditions do not depend on which crawler
                # the resolver happened to find.
                raw_headers = getattr(parsed, "response_headers", {}) or {}
                self._record_response_features(
                    current_url,
                    {str(k).lower(): str(v) for k, v in raw_headers.items()},
                    body,
                )

                # Extract forms and their parameters
                forms = self._extract_forms(body, current_url)
                for action_url, method, param_names in forms:
                    if is_state_changing_url(action_url):
                        continue
                    self._crawl_endpoints.append(
                        Endpoint(url=action_url, method=method, params=param_names)
                    )

                # Extract query parameters from links
                links = self._extract_links(body, current_url, base_origin)
                for link in links:
                    if is_state_changing_url(link):
                        continue
                    link_parsed = urlparse(link)
                    if link_parsed.query:
                        param_names = [
                            p.split("=")[0] for p in link_parsed.query.split("&") if "=" in p
                        ]
                        if param_names:
                            self._crawl_endpoints.append(
                                Endpoint(url=link, method="GET", params=param_names)
                            )

                # Follow links
                if depth < max_depth:
                    for link in links:
                        if is_state_changing_url(link):
                            continue
                        link_norm = link.split("#")[0].split("?")[0].rstrip("/")
                        if link_norm not in visited:
                            queue.append((link, depth + 1))

            except Exception as exc:
                self._logger.debug("Crawl fallback failed for %s: %s", current_url, exc)
                continue

        self._logger.info(
            "HTTP crawl fallback: discovered %d URLs, %d parameterized endpoints",
            len(discovered),
            len(self._crawl_endpoints),
        )
        return discovered

    @staticmethod
    def _extract_links(html: str, page_url: str, base_origin: str) -> list[str]:
        """Extract same-origin links from HTML content."""
        links: list[str] = []
        for match in _re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, _re.I):
            raw_link = match.group(1)
            if raw_link.startswith(("javascript:", "mailto:", "data:", "#")):
                continue
            absolute = urljoin(page_url, raw_link)
            if absolute.startswith(base_origin):
                links.append(absolute)
        return list(set(links))

    @staticmethod
    def _extract_forms(html: str, page_url: str) -> list[tuple[str, str, list[str]]]:
        """Extract form action URLs, methods, and input field names from HTML.

        Returns:
            List of (action_url, method, [param_names]).
        """
        forms: list[tuple[str, str, list[str]]] = []
        # Split on <form tags
        form_blocks = _re.split(r"<form\b", html, flags=_re.I)
        for block in form_blocks[1:]:  # skip text before first <form
            # Extract action and method
            action_match = _re.search(r'action\s*=\s*["\']([^"\']*)["\']', block, _re.I)
            method_match = _re.search(r'method\s*=\s*["\']([^"\']*)["\']', block, _re.I)
            action = action_match.group(1) if action_match else ""
            method = (method_match.group(1) if method_match else "GET").upper()
            action_url = urljoin(page_url, action) if action else page_url

            # Extract input names (up to </form> or next <form)
            form_end = block.find("</form")
            form_html = block[:form_end] if form_end > 0 else block
            param_names: list[str] = []
            for inp in _re.finditer(
                r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
                form_html,
                _re.I,
            ):
                name = inp.group(1)
                if name.lower() not in ("submit", "user_token"):
                    param_names.append(name)

            if param_names:
                forms.append((action_url, method, param_names))
        return forms

    async def _scan_ftp_service(self, target: str, port: int) -> FTPScanResult:
        """Scan an FTP service using nmap scripts.

        Args:
            target: IP or hostname.
            port: FTP port number.

        Returns:
            FTPScanResult with anonymous access and version info.
        """
        anonymous = False
        writable_dirs: list[str] = []
        version_vulns: list[str] = []

        match = self._resolver.find_tool("port_scanning")
        if match and match.available and match.tool_class:
            try:
                tool = match.tool_class(scope=self.scope)
                args = tool.validate_input(
                    {
                        "target": target,
                        "ports": str(port),
                        "flags": "--script=ftp-anon,ftp-bounce,ftp-vsftpd-backdoor",
                    }
                )
                raw = await tool.execute(args)

                raw_lower = raw.lower()
                if "anonymous" in raw_lower and "allowed" in raw_lower:
                    anonymous = True
                if "vsftpd" in raw_lower and "backdoor" in raw_lower:
                    version_vulns.append("vsftpd-backdoor")

                await self.state.log_action(
                    engagement_id=self.engagement_id,
                    phase="scan",
                    agent="ScanAgent",
                    tool=match.name,
                    input_data={"target": target, "port": port, "service": "ftp"},
                )
            except Exception as exc:
                self._logger.warning("FTP scan failed: %s", exc)

        return FTPScanResult(
            anonymous_access=anonymous,
            writable_dirs=writable_dirs,
            version_vulns=version_vulns,
        )

    async def _scan_ssh_service(self, target: str, port: int) -> SSHScanResult:
        """Scan an SSH service for version and auth methods.

        Args:
            target: IP or hostname.
            port: SSH port number.

        Returns:
            SSHScanResult with version and auth methods.
        """
        version = ""
        auth_methods: list[str] = []
        weak_config: list[str] = []

        match = self._resolver.find_tool("port_scanning")
        if match and match.available and match.tool_class:
            try:
                tool = match.tool_class(scope=self.scope)
                args = tool.validate_input(
                    {
                        "target": target,
                        "ports": str(port),
                        "flags": "--script=ssh-auth-methods -sV",
                    }
                )
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                # Extract version from parsed output
                if hasattr(parsed, "hosts"):
                    for host in parsed.hosts:
                        for svc in getattr(host, "services", []):
                            if svc.port == port:
                                version = (
                                    getattr(svc, "version", "") or getattr(svc, "product", "") or ""
                                )

                # Parse auth methods from raw output
                if "publickey" in raw.lower():
                    auth_methods.append("publickey")
                if "password" in raw.lower():
                    auth_methods.append("password")

                await self.state.log_action(
                    engagement_id=self.engagement_id,
                    phase="scan",
                    agent="ScanAgent",
                    tool=match.name,
                    input_data={"target": target, "port": port, "service": "ssh"},
                )
            except Exception as exc:
                self._logger.warning("SSH scan failed: %s", exc)

        return SSHScanResult(
            version=version,
            auth_methods=auth_methods,
            weak_config=weak_config,
        )

    async def _scan_smb_service(self, target: str, port: int) -> SMBScanResult:
        """Scan an SMB service for shares and null sessions.

        Args:
            target: IP or hostname.
            port: SMB port number.

        Returns:
            SMBScanResult with shares and signing status.
        """
        shares: list[dict[str, Any]] = []
        null_session = False
        signing_required = True

        match = self._resolver.find_tool("port_scanning")
        if match and match.available and match.tool_class:
            try:
                tool = match.tool_class(scope=self.scope)
                args = tool.validate_input(
                    {
                        "target": target,
                        "ports": str(port),
                        "flags": "--script=smb-enum-shares,smb-security-mode",
                    }
                )
                raw = await tool.execute(args)

                raw_lower = raw.lower()
                if "null session" in raw_lower or "anonymous" in raw_lower:
                    null_session = True
                if "signing" in raw_lower and "not required" in raw_lower:
                    signing_required = False

                await self.state.log_action(
                    engagement_id=self.engagement_id,
                    phase="scan",
                    agent="ScanAgent",
                    tool=match.name,
                    input_data={"target": target, "port": port, "service": "smb"},
                )
            except Exception as exc:
                self._logger.warning("SMB scan failed: %s", exc)

        return SMBScanResult(
            shares=shares,
            null_session=null_session,
            signing_required=signing_required,
        )

    async def _scan_database_service(self, target: str, port: int, db_type: str) -> DBScanResult:
        """Scan a database service for version and default credentials.

        Args:
            target: IP or hostname.
            port: Database port number.
            db_type: Database type (mysql, postgresql, mssql, oracle).

        Returns:
            DBScanResult with accessibility and version info.
        """
        accessible = False
        version: str | None = None
        default_creds = False

        match = self._resolver.find_tool("port_scanning")
        if match and match.available and match.tool_class:
            try:
                tool = match.tool_class(scope=self.scope)
                args = tool.validate_input(
                    {
                        "target": target,
                        "ports": str(port),
                        "flags": "-sV",
                    }
                )
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                if hasattr(parsed, "hosts"):
                    for host in parsed.hosts:
                        for svc in getattr(host, "services", []):
                            if svc.port == port:
                                version = getattr(svc, "version", None) or getattr(
                                    svc, "product", None
                                )
                                accessible = True

                await self.state.log_action(
                    engagement_id=self.engagement_id,
                    phase="scan",
                    agent="ScanAgent",
                    tool=match.name,
                    input_data={"target": target, "port": port, "service": db_type},
                )
            except Exception as exc:
                self._logger.warning("Database scan failed: %s", exc)

        return DBScanResult(
            accessible=accessible,
            version=version,
            default_creds=default_creds,
            db_type=db_type,
        )

    # ------------------------------------------------------------------
    # Step 3: LLM Reviews Scan Results
    # ------------------------------------------------------------------

    async def _llm_review_scan_results(self, scan_results: list[ServiceScanResult]) -> str:
        """Ask LLM to review and analyze all scan results.

        Args:
            scan_results: List of per-service scan results.

        Returns:
            LLM-generated analysis text.
        """
        if not scan_results:
            return "No services were scanned."

        summaries = []
        for sr in scan_results:
            summary = f"Service: {sr.service_type} (port {sr.port})"
            result = sr.result
            if isinstance(result, HTTPScanResult):
                summary += (
                    f" — {len(result.endpoints)} endpoints, "
                    f"{len(result.forms)} forms, "
                    f"{len(result.directories)} directories"
                )
            elif isinstance(result, FTPScanResult):
                summary += f" — anonymous={result.anonymous_access}"
            elif isinstance(result, SSHScanResult):
                summary += f" — version={result.version}, auth={result.auth_methods}"
            elif isinstance(result, SMBScanResult):
                summary += f" — null_session={result.null_session}"
            elif isinstance(result, DBScanResult):
                summary += f" — accessible={result.accessible}, type={result.db_type}"
            summaries.append(summary)

        prompt = (
            "Review the following scan results from a penetration test.\n"
            "For each service, identify:\n"
            "1. Key findings and potential vulnerabilities\n"
            "2. Interesting patterns or anomalies\n"
            "3. What the Exploit Agent should prioritize\n\n"
            "Scan results:\n" + "\n".join(f"  - {s}" for s in summaries) + "\n\n"
            "Provide a concise analysis."
        )
        return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Step 4: LLM Coverage Check
    # ------------------------------------------------------------------

    async def _llm_check_coverage(
        self, scan_results: list[ServiceScanResult], analysis: str
    ) -> CoverageAssessment:
        """Ask LLM to assess whether scan coverage is sufficient.

        Args:
            scan_results: List of per-service scan results.
            analysis: LLM analysis from step 3.

        Returns:
            CoverageAssessment indicating sufficiency and gaps.
        """
        # Count totals
        total_endpoints = 0
        total_forms = 0
        for sr in scan_results:
            if isinstance(sr.result, HTTPScanResult):
                total_endpoints += len(sr.result.endpoints)
                total_forms += len(sr.result.forms)

        prompt = (
            "Assess whether the scan coverage is sufficient for a penetration test.\n"
            f"Total endpoints discovered: {total_endpoints}\n"
            f"Total forms discovered: {total_forms}\n"
            f"Services scanned: {len(scan_results)}\n"
            f"Analysis: {analysis[:500]}\n\n"
            "Respond as JSON with keys:\n"
            '  "sufficient": true/false\n'
            '  "gaps": ["gap1", "gap2"] (what\'s missing)\n'
            '  "recommendations": ["rec1", "rec2"] (how to fill gaps)\n\n'
            "JSON:"
        )

        response = await self.llm.generate_text(prompt)

        # Parse LLM JSON response
        try:
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
            else:
                data = json.loads(response)

            return CoverageAssessment(
                sufficient=data.get("sufficient", True),
                gaps=data.get("gaps", []),
                recommendations=data.get("recommendations", []),
            )
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            self._logger.warning("Failed to parse coverage assessment: %s", exc)
            return CoverageAssessment(sufficient=True)

    # ------------------------------------------------------------------
    # Step 5: Expand Coverage
    # ------------------------------------------------------------------

    async def _step_expand_coverage(
        self, gaps: list[str], recon_result: ReconResult
    ) -> list[ServiceScanResult]:
        """Run additional scans to fill coverage gaps.

        Every addressable gap re-runs the WHOLE HTTP scan for a service, with
        the SAME arguments. So the second and third gap naming the same service
        do byte-identical work: measured on a live SPA, three passes each
        produced 112 routes and the same seven body schemas, at six minutes
        apiece, and the third one is what pushed the phase past its budget and
        got the entire attack surface thrown away.

        Each (service, port) therefore gets **one** expansion pass, and each
        pass is entered only when enough budget remains to finish it. A gap
        naming a service already re-scanned is recorded rather than re-run —
        this is a repeat, not extra coverage.

        Args:
            gaps: List of gap descriptions from coverage assessment.
            recon_result: Original recon results for target info.

        Returns:
            List of additional ServiceScanResult from expansion scans.
        """
        additional: list[ServiceScanResult] = []
        target = recon_result.target
        rescanned_ports: set[int] = set()

        for index, gap in enumerate(gaps):
            if not self._budget_allows(
                _COST_EXPANSION_PASS, f"the remaining {len(gaps) - index} coverage gap(s)"
            ):
                break
            gap_lower = gap.lower()
            try:
                addressable = any(
                    token in gap_lower
                    for token in ("endpoint", "url", "crawl", "directory", "fuzz")
                )
                if addressable:
                    http_services = [s for s in recon_result.services.services if s.is_http]
                    for svc in http_services:
                        if svc.port in rescanned_ports:
                            self._logger.info(
                                "Coverage expansion: port %d already re-scanned this phase — "
                                "gap '%s' would repeat identical work, not extend coverage",
                                svc.port,
                                gap[:80],
                            )
                            continue
                        if not self._budget_allows(
                            _COST_EXPANSION_PASS, f"re-scanning port {svc.port}"
                        ):
                            break
                        rescanned_ports.add(svc.port)
                        result = await self._scan_http_service(target, svc.port, [])
                        additional.append(
                            ServiceScanResult(service_type="http", port=svc.port, result=result)
                        )
                else:
                    self._logger.info("Cannot address gap: %s", gap)
            except Exception as exc:
                self._logger.warning("Coverage expansion failed for gap '%s': %s", gap, exc)

        return additional

    # ------------------------------------------------------------------
    # Step 6: Build Result
    # ------------------------------------------------------------------

    def _build_result(
        self,
        recon_result: ReconResult,
        scan_results: list[ServiceScanResult],
        coverage: CoverageAssessment,
    ) -> ScanResult:
        """Assemble all scan data into the final ScanResult.

        Pure code — no LLM or tool calls.

        Args:
            recon_result: Original recon results.
            scan_results: All service scan results.
            coverage: Coverage assessment.

        Returns:
            ScanResult ready for consumption by Orchestrator/downstream agents.
        """
        total_endpoints = 0
        total_forms = 0
        total_params = 0

        for sr in scan_results:
            if isinstance(sr.result, HTTPScanResult):
                total_endpoints += len(sr.result.endpoints)
                total_forms += len(sr.result.forms)
                for ep in sr.result.endpoints:
                    total_params += len(ep.params)

        return ScanResult(
            target=recon_result.target,
            service_scans=scan_results,
            total_endpoints=total_endpoints,
            total_forms=total_forms,
            total_params=total_params,
            coverage_assessment=coverage,
        )

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    async def _persist_endpoints(self, result: ScanResult) -> None:
        """Write discovered endpoints to the shared state DB.

        Enables the Exploit Agent to poll for new targets via
        ``state.get_new_endpoints()``.

        Args:
            result: The completed ScanResult.
        """
        for sr in result.service_scans:
            if isinstance(sr.result, HTTPScanResult):
                for ep in sr.result.endpoints:
                    try:
                        await self.state.add_endpoint(
                            engagement_id=self.engagement_id,
                            url=ep.url,
                            method=ep.method,
                            parameters={name: "" for name in ep.params},
                            discovered_by=self.name,
                            # The observed response features and the parameter
                            # structure the Exploit planner ranks on. Without
                            # them an Endpoint rebuilt from the store is missing
                            # exactly the evidence the ranking reads, so a
                            # replay scores every candidate on absent signals
                            # and reports no change — which reads as "the fix
                            # did nothing" rather than "nothing was asked".
                            features={
                                "param_locations": {
                                    k: v.value if hasattr(v, "value") else str(v)
                                    for k, v in (ep.param_locations or {}).items()
                                },
                                "session_setters": list(ep.session_setters or []),
                                "sets_cookies": list(ep.sets_cookies or []),
                                "has_form": ep.has_form,
                                "has_dom_source": ep.has_dom_source,
                                "content_type": ep.content_type or "",
                            },
                        )
                    except Exception as exc:
                        self._logger.warning("Failed to persist endpoint %s: %s", ep.url, exc)

                for directory in sr.result.directories:
                    try:
                        await self.state.add_endpoint(
                            engagement_id=self.engagement_id,
                            url=directory,
                            discovered_by=self.name,
                        )
                    except Exception as exc:
                        self._logger.warning("Failed to persist directory %s: %s", directory, exc)
