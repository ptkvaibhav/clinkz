"""Deterministic Recon Agent (v2) — structured steps with LLM reasoning checkpoints.

Unlike the v1 ReconAgent (which ran a free-form ReAct loop), this agent
follows a fixed sequence of tool steps with LLM analysis at key checkpoints:

    1. Full TCP port scan          (TOOL — deterministic)
    2. LLM analyzes port results   (REASONING checkpoint)
    3. Service/version detection    (TOOL — deterministic)
    4. LLM extracts tech stack     (REASONING checkpoint)
    5. Web-specific recon           (TOOL — deterministic, conditional)
    6. LLM synthesizes summary     (REASONING checkpoint)
    7. Build structured result     (CODE — deterministic)

Every tool call goes through the ToolResolver (never direct imports).
Every LLM call goes through self.llm (from BaseAgent).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from clinkz.agents.base import BaseAgent
from clinkz.llm.base import LLMClient
from clinkz.llm.call_purpose import LLMCallPurpose, llm_call_purpose
from clinkz.models.recon import (
    DetectedComponent,
    PortScanResult,
    ReconResult,
    ReconService,
    ServiceScanResult,
    Technology,
    TechStack,
    WebReconResult,
    dedupe_components,
)
from clinkz.models.scope import EngagementScope
from clinkz.observability.ledger import ComponentKind, record_contribution, record_dead_seam
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase
from clinkz.tools.resolver import ToolResolver

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "recon_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


class ReconAgent(BaseAgent):
    """Deterministic recon with LLM reasoning at checkpoints.

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

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "recon"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Execute the 7-step deterministic recon pipeline.

        Args:
            input_data: Must contain ``target`` (str) or ``targets`` (list[str]).

        Returns:
            Dict with ``result`` (ReconResult dict), ``summary``, and ``status``.
        """
        target = input_data.get("target") or ""
        if not target:
            targets = input_data.get("targets") or []
            target = targets[0] if targets else ""
        if not target:
            # Extract from scope dict (as passed by the Orchestrator)
            scope_data = input_data.get("scope") or {}
            scope_targets = scope_data.get("targets") or []
            if scope_targets:
                target = (
                    scope_targets[0].get("value", "")
                    if isinstance(scope_targets[0], dict)
                    else str(scope_targets[0])
                )
        if not target:
            raise ValueError("ReconAgent requires a 'target' in input_data")

        self._logger.info("ReconAgent v2 starting — target: %s", target)

        # Detect if the target is a URL — if so, we already know the port/protocol
        parsed_url = urlparse(target) if target.startswith(("http://", "https://")) else None
        url_port: int | None = None
        url_host: str = target
        if parsed_url and parsed_url.hostname:
            url_host = parsed_url.hostname
            url_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

        # Step 1: Full TCP port scan (TOOL — deterministic)
        self._logger.info("Step 1: Port scan — %s", target)
        with self._record_step(
            "port_scan",
            inputs={"target": url_host},
            replay_info={"method_name": "_step_port_scan"},
        ):
            ports = await self._step_port_scan(url_host)

        # If port scan found nothing but we have a URL, infer the port
        if not ports.open_ports and url_port is not None:
            self._logger.info("Port scan empty but target is a URL — inferring port %d", url_port)
            ports = PortScanResult(open_ports=[url_port], tool_used="url_inference")
        self._logger.info("Step 1 complete: %d open ports found", len(ports.open_ports))

        # Step 2: LLM reviews port scan output (REASONING checkpoint)
        self._logger.info("Step 2: LLM port analysis")
        await self._llm_analyze_ports(ports)  # reasoning checkpoint — logged
        self._logger.info("Step 2 complete: port analysis ready")

        # Step 3: Service + version detection on open ports (TOOL — deterministic)
        self._logger.info("Step 3: Service scan on %d ports", len(ports.open_ports))
        with self._record_step(
            "service_scan",
            inputs={"target": url_host, "open_ports": list(ports.open_ports)},
            replay_info={"method_name": "_step_service_scan"},
        ):
            services = await self._step_service_scan(url_host, ports.open_ports)

        # If service scan found nothing but we have a URL, create synthetic HTTP service
        if not services.services and parsed_url:
            self._logger.info(
                "Service scan empty but target is a URL — creating synthetic HTTP service"
            )
            scheme = parsed_url.scheme or "http"
            svc_name = "https" if scheme == "https" else "http"
            services = ServiceScanResult(
                services=[
                    ReconService(
                        port=url_port or 80,
                        protocol="tcp",
                        service_name=svc_name,
                    )
                ],
                tool_used="url_inference",
            )
        self._logger.info("Step 3 complete: %d services identified", len(services.services))

        # Step 4: LLM extracts technology fingerprint (REASONING checkpoint)
        self._logger.info("Step 4: LLM technology extraction")
        tech_stack = await self._llm_extract_technologies(services)
        self._logger.info(
            "Step 4 complete: %d technologies identified",
            len(tech_stack.technologies),
        )

        # Step 5: HTTP-specific recon if web services found (TOOL — deterministic)
        web_info: WebReconResult | None = None
        has_http = any(s.is_http for s in services.services)
        if has_http:
            self._logger.info("Step 5: Web recon (HTTP services detected)")
            with self._record_step(
                "web_recon",
                inputs={
                    "target": url_host,
                    "services": services.model_dump(mode="json"),
                },
                replay_info={"method_name": "_step_web_recon"},
            ):
                web_info = await self._step_web_recon(url_host, services)
            self._logger.info("Step 5 complete: web recon done")
        else:
            self._logger.info("Step 5: Skipped (no HTTP services)")

        # Step 6: LLM synthesizes final recon summary (REASONING checkpoint)
        self._logger.info("Step 6: LLM synthesis")
        summary = await self._llm_synthesize(ports, services, web_info, tech_stack)
        self._logger.info("Step 6 complete: synthesis ready")

        # Step 7: Structure output (CODE — deterministic)
        self._logger.info("Step 7: Building result")
        result = self._build_result(target, ports, services, web_info, tech_stack, summary)
        self._logger.info("ReconAgent v2 complete for %s", target)

        return {
            "result": result.model_dump(mode="json"),
            "summary": summary,
            "status": "complete",
        }

    # ------------------------------------------------------------------
    # Step 1: Port Scan
    # ------------------------------------------------------------------

    async def _step_port_scan(self, target: str) -> PortScanResult:
        """Run a full TCP port scan using the tool resolver fallback chain.

        Tries tools from ``find_tools_ranked("port_scanning")`` in order.
        Returns a PortScanResult even if all tools fail (empty open_ports).

        Args:
            target: IP or hostname to scan.

        Returns:
            PortScanResult with discovered open ports.
        """
        ranked = self._resolver.find_tools_ranked("port_scanning")
        if not ranked:
            self._logger.warning("No port scanning tools available")
            return PortScanResult(tool_used="none")

        for tool_name in ranked:
            self._logger.info("Port scan: trying %s", tool_name)
            match = self._resolver.find_tool("port_scanning")
            if match is None or match.tool_class is None or not match.available:
                continue

            try:
                tool = match.tool_class(scope=self.scope)
                args = tool.validate_input(
                    {
                        "target": target,
                        "ports": "1-65535",
                        "flags": "-sS --min-rate 1000",
                    }
                )
                raw = await tool.execute(args)
                parsed = tool.parse_output(raw)

                # Extract open ports from the parsed output
                open_ports: list[int] = []
                if hasattr(parsed, "open_ports"):
                    open_ports = list(parsed.open_ports)
                elif hasattr(parsed, "hosts"):
                    for host in parsed.hosts:
                        for svc in getattr(host, "services", []):
                            open_ports.append(svc.port)
                    open_ports = sorted(set(open_ports))

                await self.state.log_action(
                    engagement_id=self.engagement_id,
                    phase="recon",
                    agent="ReconAgent",
                    tool=tool_name,
                    input_data={"target": target, "step": "port_scan"},
                )

                return PortScanResult(
                    open_ports=open_ports,
                    raw_output=raw,
                    tool_used=tool_name,
                )

            except Exception as exc:
                self._logger.warning("Port scan with %s failed: %s", tool_name, exc)
                continue

        self._logger.warning("All port scanning tools failed for %s", target)
        return PortScanResult(tool_used="none")

    # ------------------------------------------------------------------
    # Step 2: LLM Analyze Ports
    # ------------------------------------------------------------------

    async def _llm_analyze_ports(self, ports: PortScanResult) -> str:
        """Send port scan results to LLM for analysis.

        Args:
            ports: Structured port scan result.

        Returns:
            LLM analysis text.
        """
        if not ports.open_ports:
            return "No open ports found. The host may be firewalled or down."

        prompt = (
            "You are analyzing port scan results for a penetration test. "
            f"Open ports found: {ports.open_ports}\n"
            f"Tool used: {ports.tool_used}\n\n"
            "Identify:\n"
            "1. Notable open ports and their likely services\n"
            "2. Any unusual port combinations that suggest specific infrastructure\n"
            "3. Priority services to investigate further\n"
            "Respond concisely."
        )
        with llm_call_purpose(LLMCallPurpose.PLANNING, site="recon._llm_analyze_ports"):
            return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Step 3: Service Scan
    # ------------------------------------------------------------------

    async def _step_service_scan(self, target: str, open_ports: list[int]) -> ServiceScanResult:
        """Run service/version detection on discovered open ports.

        Uses nmap -sV -sC on the specific ports (not a full 65535 re-scan).

        Args:
            target: IP or hostname.
            open_ports: List of port numbers to fingerprint.

        Returns:
            ServiceScanResult with service details.
        """
        if not open_ports:
            return ServiceScanResult(tool_used="none")

        match = self._resolver.find_tool("service_detection")
        if match is None or match.tool_class is None or not match.available:
            self._logger.warning("No service detection tool available")
            return ServiceScanResult(tool_used="none")

        port_spec = ",".join(str(p) for p in open_ports)
        try:
            tool = match.tool_class(scope=self.scope)
            args = tool.validate_input(
                {
                    "target": target,
                    "ports": port_spec,
                    "flags": "-sV -sC",
                }
            )
            raw = await tool.execute(args)
            parsed = tool.parse_output(raw)

            # Convert parsed hosts/services into ReconService objects
            services: list[ReconService] = []
            if hasattr(parsed, "hosts"):
                for host in parsed.hosts:
                    for svc in getattr(host, "services", []):
                        scripts_text = ""
                        if hasattr(svc, "scripts") and svc.scripts:
                            scripts_text = json.dumps(svc.scripts)
                        services.append(
                            ReconService(
                                port=svc.port,
                                protocol=str(getattr(svc, "protocol", "tcp")),
                                service_name=getattr(svc, "name", ""),
                                version=(
                                    getattr(svc, "version", None) or getattr(svc, "product", None)
                                ),
                                scripts_output=scripts_text or None,
                            )
                        )

            # The service scanner is the richest component source the engine
            # has: ``-sV`` resolves a banner to a product AND a version through
            # nmap's own signature database, already split. Read through the
            # declared contract, not off ``parsed.hosts`` again — a wrapper that
            # forgets to declare it is a dead seam that says so.
            components: list[DetectedComponent] = []
            if type(parsed).declares_components():
                components = parsed.detected_components()
                record_contribution(
                    name=match.name,
                    kind=ComponentKind.TOOL,
                    items=len(components),
                    note=f"service scan: {sum(1 for c in components if c.version)} versioned",
                )
            else:
                record_dead_seam(
                    name=match.name,
                    kind=ComponentKind.PARSER_SEAM,
                    note=(
                        f"{type(parsed).__name__} declares no component contract — service "
                        "versions cannot reach the component inventory"
                    ),
                )

            await self.state.log_action(
                engagement_id=self.engagement_id,
                phase="recon",
                agent="ReconAgent",
                tool=match.name,
                input_data={"target": target, "ports": port_spec, "step": "service_scan"},
            )

            return ServiceScanResult(
                services=services,
                raw_output=raw,
                tool_used=match.name,
                components=dedupe_components(components),
            )

        except Exception as exc:
            self._logger.error("Service scan failed: %s", exc)
            # A failed service scan is a LEDGER row, not just a log line — the
            # same rule, and the same reason, as the fingerprinter's own handler
            # below. This is the OTHER component source for the published-CVE
            # path, and the richer of the two: ``-sV`` resolves a banner to a
            # product AND a version through nmap's own signature database,
            # already split, which is why its provenance outranks a ``Server:``
            # header. When it raises, that inventory is empty — and an empty
            # inventory has two causes that are indistinguishable from every
            # downstream position. A target that genuinely exposes no versioned
            # service yields no components; a parser that raised on the tool's
            # real bytes also yields no components, and only the component's own
            # failure record separates them. ``whatweb`` proved that is not
            # hypothetical: it discarded a complete Apache/PHP fingerprint on
            # every run for years, silently, because nobody recorded the raise.
            #
            # ``ok=False`` and not ``not_applicable``: open ports were present
            # and a tool resolved, so the precondition held and the component
            # failed to read it. The exception's TYPE plus a bounded slice of
            # its text — a tool error can carry the argv that produced it, and
            # ``add_note`` redacts, but this bounds what reaches the redactor.
            record_contribution(
                name=match.name,
                kind=ComponentKind.TOOL,
                items=0,
                ok=False,
                note=(
                    f"service scan of {target} raised {type(exc).__name__}: "
                    f"{str(exc)[:200]} — no service version reached the component "
                    "inventory or the CVE path"
                ),
            )
            return ServiceScanResult(tool_used="none")

    # ------------------------------------------------------------------
    # Step 4: LLM Extract Technologies
    # ------------------------------------------------------------------

    async def _llm_extract_technologies(self, services: ServiceScanResult) -> TechStack:
        """Ask LLM to extract the technology stack from service scan results.

        Args:
            services: Structured service scan result.

        Returns:
            TechStack with identified technologies.
        """
        if not services.services:
            return TechStack()

        service_descriptions = []
        for svc in services.services:
            desc = f"Port {svc.port}/{svc.protocol}: {svc.service_name}"
            if svc.version:
                desc += f" (version: {svc.version})"
            if svc.scripts_output:
                desc += f" [scripts: {svc.scripts_output[:500]}]"
            service_descriptions.append(desc)

        prompt = (
            "Extract the complete technology stack from these service scan results.\n"
            "For each technology, provide: name, version (if known), category "
            "(web_server, language, framework, database, os, other).\n"
            "Respond as a JSON array of objects with keys: name, version, category.\n\n"
            "Services:\n" + "\n".join(service_descriptions) + "\n\n"
            "JSON array:"
        )

        with llm_call_purpose(LLMCallPurpose.PLANNING, site="recon._llm_extract_technologies"):
            response = await self.llm.generate_text(prompt)

        # Parse LLM JSON response into TechStack
        try:
            # Try to extract JSON from the response
            json_start = response.find("[")
            json_end = response.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                tech_list = json.loads(response[json_start:json_end])
            else:
                tech_list = json.loads(response)

            technologies = []
            for item in tech_list:
                if isinstance(item, dict):
                    technologies.append(
                        Technology(
                            name=item.get("name", "unknown"),
                            version=item.get("version"),
                            category=item.get("category", "other"),
                        )
                    )
            return TechStack(technologies=technologies)

        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            self._logger.warning("Failed to parse LLM tech stack response: %s", exc)
            return TechStack()

    # ------------------------------------------------------------------
    # Step 5: Web Recon
    # ------------------------------------------------------------------

    async def _step_web_recon(self, target: str, services: ServiceScanResult) -> WebReconResult:
        """Run HTTP-specific recon tools on web services.

        For each HTTP service:
        1. WhatWeb/httpx for fingerprinting (via tool resolver)
        2. wafw00f for WAF detection
        3. Extract response headers via HTTP GET

        Args:
            target: IP or hostname.
            services: Service scan results (filtered to HTTP services).

        Returns:
            WebReconResult with fingerprint, WAF, and header data.
        """
        http_services = [s for s in services.services if s.is_http]
        if not http_services:
            return WebReconResult()

        fingerprints: list[dict[str, Any]] = []
        technologies_found: list[str] = []
        components: list[DetectedComponent] = []
        headers: dict[str, str] = {}
        waf_detected = False
        waf_name: str | None = None

        for svc in http_services:
            scheme = "https" if svc.port in {443, 8443} or "ssl" in svc.service_name else "http"
            url = f"{scheme}://{target}:{svc.port}"

            # 1. Web fingerprinting (whatweb/httpx)
            fp_match = self._resolver.find_tool("web_fingerprinting")
            if fp_match and fp_match.available and fp_match.tool_class:
                try:
                    fp_tool = fp_match.tool_class(scope=self.scope)
                    fp_args = fp_tool.validate_input({"target": url})
                    fp_raw = await fp_tool.execute(fp_args)
                    fp_parsed = fp_tool.parse_output(fp_raw)

                    fp_data = fp_parsed.model_dump()
                    fingerprints.append({"url": url, "tool": fp_match.name, "data": fp_data})

                    # The PRODUCER declares what it fingerprinted. This used to
                    # read ``hasattr(r, "technologies")`` then ``hasattr(r,
                    # "tech")`` over ``parsed.results`` — two field names because
                    # two wrappers spell it differently, and a third spelling
                    # would have contributed nothing with nothing said about it.
                    # It also read names only, so the versions whatweb had
                    # already parsed were never consumed by anything.
                    if not type(fp_parsed).declares_components():
                        note = (
                            f"{type(fp_parsed).__name__} declares no component contract — "
                            "no technology or version can reach recon from this tool"
                        )
                        self._logger.warning(
                            "Fingerprint seam is DEAD: %s returns %s", fp_match.name, note
                        )
                        record_dead_seam(
                            name=fp_match.name, kind=ComponentKind.PARSER_SEAM, note=note
                        )
                    else:
                        found = fp_parsed.detected_components()
                        components.extend(found)
                        technologies_found.extend(c.name for c in found)
                        record_contribution(
                            name=fp_match.name,
                            kind=ComponentKind.TOOL,
                            items=len(found),
                            note=f"{sum(1 for c in found if c.version)} with a version",
                        )
                        self._logger.info(
                            "Fingerprinted %s with %s — %d component(s), %d with a version",
                            url,
                            fp_match.name,
                            len(found),
                            sum(1 for c in found if c.version),
                        )
                except Exception as exc:
                    self._logger.warning("Fingerprinting %s failed: %s", url, exc)
                    # A failed fingerprint is a LEDGER row, not just a log line.
                    # This is the component source for the whole published-CVE
                    # path: fingerprint -> component+version -> known CVE -> our
                    # own oracle. When it raises, the inventory is empty — and an
                    # empty inventory has two causes that look identical from
                    # every downstream position. A genuinely patched or
                    # unfingerprintable stack yields no components; a parser that
                    # raised on the tool's real bytes also yields no components.
                    # ``whatweb --log-json=-`` interleaves its human log with the
                    # JSON array, so whole-blob ``json.loads`` raised here on
                    # every run for years, discarding a complete Apache/PHP
                    # fingerprint, and nothing anywhere recorded that it had
                    # happened. Only the fingerprinter's OWN failure record
                    # separates the two readings, which is why it is made here
                    # rather than inferred downstream from a zero.
                    #
                    # ``ok=False`` and not ``not_applicable``: the precondition
                    # was present (an HTTP service was there to fingerprint) and
                    # the component failed to read it. The exception's TYPE plus
                    # a bounded slice of its text — a tool error can carry the
                    # argv that produced it, and ``add_note`` redacts, but this
                    # bounds what reaches the redactor.
                    record_contribution(
                        name=fp_match.name,
                        kind=ComponentKind.TOOL,
                        items=0,
                        ok=False,
                        note=(
                            f"fingerprinting {url} raised {type(exc).__name__}: "
                            f"{str(exc)[:200]} — no component or version reached the "
                            "CVE path from this service"
                        ),
                    )

            # 2. WAF detection
            waf_match = self._resolver.find_tool("waf_detection")
            if waf_match and waf_match.available and waf_match.tool_class:
                try:
                    waf_tool = waf_match.tool_class(scope=self.scope)
                    waf_args = waf_tool.validate_input({"target": url})
                    waf_raw = await waf_tool.execute(waf_args)
                    waf_parsed = waf_tool.parse_output(waf_raw)

                    if hasattr(waf_parsed, "results"):
                        for wr in waf_parsed.results:
                            if getattr(wr, "waf_detected", False):
                                waf_detected = True
                                waf_name = getattr(wr, "waf_name", None)

                    self._logger.info("WAF check on %s: detected=%s", url, waf_detected)
                except Exception as exc:
                    self._logger.warning("WAF detection on %s failed: %s", url, exc)

            # 3. HTTP headers + body fingerprinting via simple GET
            # Resolved OUTSIDE the try so the handler can name the component
            # that failed. Recording under a literal like
            # ``recon.header_collection`` would key the ledger on a place in
            # this file rather than on the tool, and would need its own registry
            # declaration; the tool's own name is already declared from
            # TOOL_CHAINS, which is the computed source.
            http_match = self._resolver.find_tool("http_request")
            try:
                if http_match and http_match.available and http_match.tool_class:
                    http_tool = http_match.tool_class(
                        scope=self.scope, engagement_id=self.engagement_id, stage="recon"
                    )
                    http_args = http_tool.validate_input(
                        {
                            "url": url,
                            "method": "GET",
                            "follow_redirects": True,
                        }
                    )
                    http_raw = await http_tool.execute(http_args)
                    http_parsed = http_tool.parse_output(http_raw)
                    if hasattr(http_parsed, "response_headers"):
                        headers.update(http_parsed.response_headers)
                    # Extract app identity from response body
                    body = getattr(http_parsed, "response_body", "")
                    if body:
                        body_techs = self._fingerprint_from_body(body)
                        technologies_found.extend(body_techs)
                    self._logger.info("Collected headers from %s", url)
                else:
                    self._logger.warning("No http_request tool available for header collection")
            except Exception as exc:
                self._logger.warning("Header collection from %s failed: %s", url, exc)
                # The third component-adjacent source in this method, and the
                # one that carries the header set every WSTG-CONF-07 rule is a
                # pure function of, plus the body fingerprints that reach
                # ``technologies_found``. Recorded for the same reason as its two
                # siblings above: an empty header set reads as a target that
                # sends no interesting headers, which is a finding, and it must
                # not be produced by a GET that raised.
                if http_match is not None:
                    record_contribution(
                        name=http_match.name,
                        kind=ComponentKind.TOOL,
                        items=0,
                        ok=False,
                        note=(
                            f"header collection from {url} raised {type(exc).__name__}: "
                            f"{str(exc)[:200]} — no header or body fingerprint from this "
                            "service reached recon"
                        ),
                    )

        # Deduplicate technologies
        technologies_found = sorted(set(technologies_found))

        return WebReconResult(
            components=dedupe_components(components),
            fingerprints=fingerprints,
            waf_detected=waf_detected,
            waf_name=waf_name,
            headers=headers,
            technologies_found=technologies_found,
        )

    @staticmethod
    def _fingerprint_from_body(body: str) -> list[str]:
        """Extract application/framework identity from HTML response body.

        Checks for common signatures in page titles, meta tags, and body content.

        Args:
            body: Raw HTML response body.

        Returns:
            List of identified technology/application names.
        """
        import re

        techs: list[str] = []
        body_lower = body.lower()

        # Known application signatures: (pattern, tech_name)
        signatures = [
            ("damn vulnerable web application", "dvwa"),
            ("dvwa", "dvwa"),
            ("owasp juice shop", "juice_shop"),
            ("wp-content", "wordpress"),
            ("wp-login", "wordpress"),
            ("/wp-admin", "wordpress"),
            ("joomla", "joomla"),
            ("drupal", "drupal"),
            ("phpmyadmin", "phpmyadmin"),
            ("tomcat", "tomcat"),
            ("jenkins", "jenkins"),
            ("gitlab", "gitlab"),
            ("grafana", "grafana"),
            ("kibana", "kibana"),
            ("nextcloud", "nextcloud"),
        ]
        for pattern, tech_name in signatures:
            if pattern in body_lower:
                techs.append(tech_name)

        # Extract from meta generator tag
        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body,
            re.I,
        )
        if gen_match:
            techs.append(gen_match.group(1).strip().lower())

        # Server-side language hints
        if "x-powered-by" not in body_lower:
            if ".php" in body_lower:
                techs.append("php")
            if ".asp" in body_lower or ".aspx" in body_lower:
                techs.append("asp.net")
            if ".jsp" in body_lower:
                techs.append("java")

        return list(set(techs))

    # ------------------------------------------------------------------
    # Step 6: LLM Synthesize
    # ------------------------------------------------------------------

    async def _llm_synthesize(
        self,
        ports: PortScanResult,
        services: ServiceScanResult,
        web_info: WebReconResult | None,
        tech_stack: TechStack,
    ) -> str:
        """Synthesize all recon data into a final summary.

        Args:
            ports: Port scan results.
            services: Service scan results.
            web_info: Web recon results (None if no HTTP services).
            tech_stack: Extracted technology stack.

        Returns:
            LLM-generated recon summary with attack surface and next steps.
        """
        parts = [
            f"Open ports: {ports.open_ports}",
            f"Services: {[(s.port, s.service_name, s.version) for s in services.services]}",
            f"Tech stack: {[(t.name, t.version, t.category) for t in tech_stack.technologies]}",
        ]
        if web_info:
            parts.append(f"WAF detected: {web_info.waf_detected} ({web_info.waf_name or 'N/A'})")
            parts.append(f"Web technologies: {web_info.technologies_found}")
            if web_info.headers:
                security_headers = {
                    k: v
                    for k, v in web_info.headers.items()
                    if any(
                        h in k.lower()
                        for h in [
                            "x-frame",
                            "x-content",
                            "strict-transport",
                            "content-security",
                            "x-xss",
                            "server",
                            "x-powered",
                        ]
                    )
                }
                parts.append(f"Security headers: {security_headers}")

        prompt = (
            "You are synthesizing reconnaissance results for a penetration test.\n"
            "Based on the following data, provide:\n"
            "1. Attack surface overview\n"
            "2. Key risk areas and potential vulnerabilities\n"
            "3. Recommended next steps for scanning and exploitation\n"
            "4. Priority targets\n\n"
            "Data:\n" + "\n".join(parts) + "\n\n"
            "Provide a concise but thorough synthesis."
        )
        with llm_call_purpose(LLMCallPurpose.PLANNING, site="recon._llm_synthesize"):
            return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Step 7: Build Result
    # ------------------------------------------------------------------

    def _build_result(
        self,
        target: str,
        ports: PortScanResult,
        services: ServiceScanResult,
        web_info: WebReconResult | None,
        tech_stack: TechStack,
        summary: str,
    ) -> ReconResult:
        """Assemble all data into the final ReconResult.

        Pure code — no LLM or tool calls.

        Args:
            target: The scan target.
            ports: Port scan results.
            services: Service scan results.
            web_info: Web recon results (or None).
            tech_stack: Extracted technology stack.
            summary: LLM synthesis summary.

        Returns:
            ReconResult ready for consumption by Orchestrator/downstream agents.
        """
        # The unified inventory: service banners first (nmap's signature match
        # is the more precise version source), then whatever the web-layer
        # fingerprinter added. ``dedupe_components`` prefers whichever observer
        # actually had a version, so an unversioned duplicate never displaces a
        # versioned one — a downstream CVE lookup keys on this, and "nginx, no
        # version" is not an answer when another tool said "nginx 1.24.0".
        inventory = dedupe_components(
            [*services.components, *(web_info.components if web_info else [])]
        )
        return ReconResult(
            target=target,
            ports=ports,
            services=services,
            web_info=web_info,
            tech_stack=tech_stack,
            llm_summary=summary,
            components=inventory,
        )
