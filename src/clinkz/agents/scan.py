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
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

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
    ScanResult,
    ServiceScanResult,
    SMBScanResult,
    SSHScanResult,
)
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase
from clinkz.tools.resolver import ToolResolver

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "scan_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


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
        self._session_cookies: dict[str, str] = input_data.get("session_cookies", {})
        if self._session_cookies:
            self._logger.info(
                "ScanAgent received session cookies: %s",
                list(self._session_cookies.keys()),
            )
        self._logger.info("ScanAgent v2 starting — target: %s", target)

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

        # Step 5: Expand coverage if insufficient (TOOL — conditional)
        if not coverage.sufficient:
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

        # Crawl using fallback chain
        try:
            crawl_tool, crawl_result = await self._resolver.try_until_sufficient(
                "web_crawling",
                5,
                self._run_crawl_tool,
                url,
            )
            if crawl_result:
                for ep_url in crawl_result:
                    endpoints.append(Endpoint(url=str(ep_url)))
                # Tools like katana return URL strings only — they don't extract
                # form fields or query-string parameters. Without that, every
                # Endpoint downstream has params=[] and the Exploit Agent can't
                # build a single _test_* probe. Visit each discovered URL and
                # extract forms + query params so the data contract holds.
                enriched = await self._enrich_endpoints_with_params([str(u) for u in crawl_result])
                if enriched:
                    self._merge_into_crawl_endpoints(enriched)
        except ValueError:
            self._logger.warning("No crawling tools available — using HTTP client fallback")
            crawl_tool = "http_client_crawl"
            fallback_urls = await self._http_crawl_fallback(url, max_depth=2, max_pages=50)
            for ep_url in fallback_urls:
                endpoints.append(Endpoint(url=ep_url))

        # Fuzz using fallback chain
        try:
            fuzz_tool, fuzz_result = await self._resolver.try_until_sufficient(
                "directory_fuzzing",
                3,
                self._run_fuzz_tool,
                url,
            )
            if fuzz_result:
                directories = [str(d) for d in fuzz_result]
        except ValueError:
            self._logger.warning("No fuzzing tools available")

        # Merge parameterized endpoints from crawl fallback (forms, query params)
        if hasattr(self, "_crawl_endpoints") and self._crawl_endpoints:
            # Deduplicate by (url, method) — prefer the version with params
            seen: set[tuple[str, str]] = {(ep.url, ep.method) for ep in endpoints}
            for ep in self._crawl_endpoints:
                key = (ep.url, ep.method)
                if key not in seen:
                    endpoints.append(ep)
                    seen.add(key)
            self._crawl_endpoints = []

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

        tool = match.tool_class(scope=self.scope)
        args = tool.validate_input(self._build_tool_input(url))
        raw = await tool.execute(args)
        parsed = tool.parse_output(raw)

        urls: list[str] = []
        for field_name in ("endpoints", "urls"):
            if hasattr(parsed, field_name):
                urls.extend(str(u) for u in getattr(parsed, field_name))
        return urls

    async def _run_fuzz_tool(self, tool_name: str, url: str) -> list[str]:
        """Execute a fuzzing tool by name and return discovered paths.

        Args:
            tool_name: Name of the fuzz tool (e.g., "ffuf").
            url: Target URL to fuzz.

        Returns:
            List of discovered path strings.
        """
        match = self._resolver.find_tool("directory_fuzzing")
        if match is None or match.tool_class is None or not match.available:
            return []

        tool = match.tool_class(scope=self.scope)
        args = tool.validate_input(self._build_tool_input(url))
        raw = await tool.execute(args)
        parsed = tool.parse_output(raw)

        paths: list[str] = []
        if hasattr(parsed, "paths"):
            paths.extend(str(p) for p in parsed.paths)
        if hasattr(parsed, "directories"):
            paths.extend(str(d) for d in parsed.directories)
        return paths

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
        http_match = self._resolver.find_tool("http_request")
        if not http_match or not http_match.available or not http_match.tool_class:
            self._logger.debug("No HTTP client available for endpoint enrichment")
            return []

        # De-duplicate URLs (strip fragment + trailing slash) before visiting.
        # Cap the visit count so a giant katana run doesn't make scan O(n).
        max_visits = 80
        visited: set[str] = set()
        ordered_urls: list[str] = []
        for u in urls:
            norm = u.split("#", 1)[0].rstrip("/")
            if norm and norm not in visited:
                visited.add(norm)
                ordered_urls.append(u)
                if len(ordered_urls) >= max_visits:
                    break

        enriched: list[Endpoint] = []
        seen_keys: set[tuple[str, str, tuple[str, ...]]] = set()
        for current_url in ordered_urls:
            try:
                tool = http_match.tool_class(scope=self.scope, engagement_id=self.engagement_id)
                req_input: dict[str, Any] = {
                    "url": current_url,
                    "method": "GET",
                    "follow_redirects": True,
                }
                if self._session_cookies:
                    req_input["cookies"] = self._session_cookies
                args = tool.validate_input(req_input)
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                status = getattr(parsed, "status_code", 0)
                body = getattr(parsed, "response_body", "")
                if status < 200 or status >= 400 or not body:
                    continue

                # Extract forms — Endpoint per form action.
                for action_url, method, param_names in self._extract_forms(body, current_url):
                    if not param_names:
                        continue
                    key = (action_url, method, tuple(param_names))
                    if key not in seen_keys:
                        enriched.append(Endpoint(url=action_url, method=method, params=param_names))
                        seen_keys.add(key)

                # Extract query-param links — Endpoint per parameterized link.
                base_origin = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
                for link in self._extract_links(body, current_url, base_origin):
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
            len(ordered_urls),
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

            try:
                tool = http_match.tool_class(scope=self.scope, engagement_id=self.engagement_id)
                req_input: dict[str, Any] = {
                    "url": current_url,
                    "method": "GET",
                    "follow_redirects": True,
                }
                if self._session_cookies:
                    req_input["cookies"] = self._session_cookies
                args = tool.validate_input(req_input)
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                status = getattr(parsed, "status_code", 0)
                body = getattr(parsed, "response_body", "")
                if status < 200 or status >= 400 or not body:
                    continue

                discovered.append(current_url)

                # Extract forms and their parameters
                forms = self._extract_forms(body, current_url)
                for action_url, method, param_names in forms:
                    self._crawl_endpoints.append(
                        Endpoint(url=action_url, method=method, params=param_names)
                    )

                # Extract query parameters from links
                links = self._extract_links(body, current_url, base_origin)
                for link in links:
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

        For each gap, tries next tool in the fallback chain or adjusts parameters
        (bigger wordlist, deeper crawl depth).

        Args:
            gaps: List of gap descriptions from coverage assessment.
            recon_result: Original recon results for target info.

        Returns:
            List of additional ServiceScanResult from expansion scans.
        """
        additional: list[ServiceScanResult] = []
        target = recon_result.target

        for gap in gaps:
            gap_lower = gap.lower()
            try:
                if "endpoint" in gap_lower or "url" in gap_lower or "crawl" in gap_lower:
                    # Re-crawl with deeper settings
                    http_services = [s for s in recon_result.services.services if s.is_http]
                    for svc in http_services:
                        result = await self._scan_http_service(target, svc.port, [])
                        additional.append(
                            ServiceScanResult(service_type="http", port=svc.port, result=result)
                        )
                elif "directory" in gap_lower or "fuzz" in gap_lower:
                    # Re-fuzz with bigger wordlist
                    http_services = [s for s in recon_result.services.services if s.is_http]
                    for svc in http_services:
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
                            discovered_by=self.name,
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
