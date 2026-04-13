"""Scan agent — phase 2: attack surface mapping.

Discovers endpoints, hidden paths, parameters, and API routes via dynamic
capability-based tool resolution.  The agent never references tool names
directly; instead it calls ``execute_capability`` and the ToolResolver finds
the best available tool for the requested capability.

Flow
----
1. ``run()`` builds the initial observation from recon results and calls
   ``_react_loop()``.
2. The LLM calls ``execute_capability`` with a capability string
   (e.g., ``"web_crawling"``).
3. ``_execute_tool()`` intercepts the call, queries the ToolResolver, and
   dispatches to the resolved tool.
4. Parsed tool output is returned to the LLM and persisted to the state store.
5. After the LLM returns a final answer, ``run()`` retrieves all persisted
   endpoints/targets and returns them alongside the summary.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase
from clinkz.llm.base import LLMClient, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — loaded once at module import from the .md file
# ---------------------------------------------------------------------------

_PROMPT_PATH = Path(__file__).parent / "prompts" / "scan_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ScanAgent
# ---------------------------------------------------------------------------


class ScanAgent(BaseAgent):
    """Attack surface mapping phase agent with dynamic tool discovery.

    Instead of holding a fixed set of tools, the ScanAgent exposes a single
    ``execute_capability`` meta-tool to the LLM.  When the LLM calls it, the
    agent queries the ToolResolver for the best available tool that satisfies
    the requested capability, executes it, and returns structured output.

    This ensures:
    - The LLM (and agent code) never hard-codes tool names.
    - The resolver can swap in MCP tools when they become available without
      any agent-side changes.
    - Tests can inject a mock resolver to control tool dispatch precisely.

    Args:
        llm: LLM client (Sonnet-tier recommended for this agent).
        tools: Passed to BaseAgent but not directly exposed to the LLM;
               the ToolResolver handles discovery independently.
        scope: Engagement scope for target validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        resolver: Optional pre-built ToolResolver.  A fresh resolver is
                  created automatically when not provided (production usage).
    """

    #: Schema for the research meta-tool — calls LLM research() directly.
    _RESEARCH_TECHNOLOGY_SCHEMA: dict[str, Any] = {
        "name": "research_technology",
        "description": (
            "Perform live research on a specific technology, service, or version "
            "to learn about its attack surface, common misconfigurations, and CVEs. "
            "Returns LLM-generated intelligence — NOT a tool resolver lookup."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Research query. Examples: "
                        "'hidden parameters in PHP applications', "
                        "'API endpoint discovery for Node.js Express'."
                    ),
                },
            },
            "required": ["query"],
        },
    }

    #: Schema for the http_request meta-tool — dispatches to HTTPClientTool.
    _HTTP_REQUEST_SCHEMA: dict[str, Any] = {
        "name": "http_request",
        "description": (
            "Send an arbitrary HTTP request to a target URL. Useful for testing "
            "authentication, probing endpoints, or verifying scan findings."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).",
                    "default": "GET",
                },
                "url": {
                    "type": "string",
                    "description": "Full URL to send the request to.",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers as key-value pairs.",
                    "default": {},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT/PATCH).",
                    "default": "",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow HTTP redirects.",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    }

    #: Schema for the capability meta-tool exposed to the LLM.
    _EXECUTE_CAPABILITY_SCHEMA: dict[str, Any] = {
        "name": "execute_capability",
        "description": (
            "Discover and execute the best scan tool for a given capability. "
            "Always specify the CAPABILITY you need (e.g., 'web_crawling', "
            "'directory_fuzzing', 'parameter_discovery', 'web_fingerprinting'), "
            "never a specific tool name. The system resolves the right tool automatically."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "capability": {
                    "type": "string",
                    "description": (
                        "The scanning capability to exercise. Examples: "
                        "'web_crawling', 'directory_fuzzing', 'parameter_discovery', "
                        "'web_fingerprinting', 'virtual_host_fuzzing', 'api_discovery'."
                    ),
                },
                "arguments": {
                    "type": "object",
                    "description": (
                        "Arguments forwarded to the resolved tool. Common keys: "
                        "'url' for HTTP crawling/fuzzing tools, 'target' for host-level tools. "
                        "Check the capability description for details."
                    ),
                },
            },
            "required": ["capability", "arguments"],
        },
    }

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
        self._discovered_endpoints: list[dict[str, Any]] = []
        self._session_cookies: str = ""
        self._auth_skip_urls: set[str] = set()  # Login URLs to never revisit after auth

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
    # Tool schema override — expose only the capability meta-tool
    # ------------------------------------------------------------------

    def _get_tool_schemas(self) -> list[dict[str, Any]]:
        """Return the scan meta-tool schemas.

        The LLM never sees raw tool names; it only knows how to ask for
        capabilities.  The ToolResolver handles the name-to-tool mapping.

        Returns:
            List containing execute_capability, research_technology,
            http_request, and shared meta-tools (request_help, tool_installation).
        """
        return [
            self._EXECUTE_CAPABILITY_SCHEMA,
            self._RESEARCH_TECHNOLOGY_SCHEMA,
            self._HTTP_REQUEST_SCHEMA,
        ] + self._get_shared_meta_schemas()

    # ------------------------------------------------------------------
    # Tool dispatch override — intercept execute_capability calls
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_call: ToolCall) -> str:
        """Dispatch tool calls, intercepting meta-tools for resolution.

        Args:
            tool_call: ToolCall from the LLM.

        Returns:
            JSON-serialised tool output or an error string.
        """
        if tool_call.name == "execute_capability":
            return await self._resolve_and_execute(tool_call.arguments)
        if tool_call.name == "research_technology":
            return await self._do_research(tool_call.arguments)
        if tool_call.name == "http_request":
            return await self._do_http_request(tool_call.arguments)
        return await super()._execute_tool(tool_call)

    # ------------------------------------------------------------------
    # Research handler — calls LLM directly, NOT tool resolver
    # ------------------------------------------------------------------

    async def _do_research(self, args: dict[str, Any]) -> str:
        """Execute a research query via ``llm.research()``.

        Args:
            args: Must contain ``query`` (str).

        Returns:
            Research result string from the LLM.
        """
        query: str = args.get("query", "").strip()
        if not query:
            return "Error: 'query' is required for research_technology."
        self._logger.info("Runtime research: %s", query)
        return await self.llm.research(query)

    # ------------------------------------------------------------------
    # HTTP request handler — dispatches to HTTPClientTool directly
    # ------------------------------------------------------------------

    async def _do_http_request(self, args: dict[str, Any]) -> str:
        """Send an HTTP request via HTTPClientTool.

        Args:
            args: HTTP request arguments (url, method, headers, body, etc.).

        Returns:
            JSON-serialised HTTPClientOutput.
        """
        # Block re-visiting login URLs after successful authentication
        url = args.get("url", "")
        if url and self._is_auth_skip_url(url):
            return (
                "SKIPPED: Already authenticated via this login URL. "
                "Do not revisit login pages — use your session cookies instead."
            )

        from clinkz.tools.http_client import HTTPClientTool

        http = HTTPClientTool(scope=self.scope, engagement_id=self.engagement_id)
        try:
            validated = http.validate_input(args)
            raw = await http.execute(validated)
            parsed = http.parse_output(raw)
            return parsed.model_dump_json(indent=2)
        except Exception as exc:
            self._logger.error("http_request failed: %s", exc, exc_info=True)
            return f"http_request failed: {exc}"

    def _is_auth_skip_url(self, url: str) -> bool:
        """Check if a URL matches any login URL that should be skipped.

        Normalises URLs for comparison by stripping trailing slashes and
        query strings.

        Args:
            url: The URL to check.

        Returns:
            True if the URL should be skipped (already authenticated).
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalised = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        return normalised in self._auth_skip_urls

    # ------------------------------------------------------------------
    # Capability resolution and execution
    # ------------------------------------------------------------------

    async def _resolve_and_execute(self, args: dict[str, Any]) -> str:
        """Resolve a capability to a tool, execute it, and persist results.

        Queries the ToolResolver for the best available tool, then:
        1. Instantiates the tool with the current scope.
        2. Validates and runs the tool.
        3. Logs the action to the state store.
        4. Persists any discovered endpoints/paths.

        Args:
            args: Must contain ``capability`` (str) and ``arguments`` (dict).

        Returns:
            JSON-serialised ToolOutput, or an error description string.
        """
        capability: str = args.get("capability", "").strip()
        tool_args: dict[str, Any] = args.get("arguments") or {}

        if not capability:
            return "Error: 'capability' is required in execute_capability arguments."

        # Inject session cookies into crawling tools when available
        if (
            self._session_cookies
            and capability in ("web_crawling", "endpoint_discovery", "url_enumeration")
            and "cookies" not in tool_args
        ):
            tool_args = {**tool_args, "cookies": self._session_cookies}

        match = self._resolver.find_tool(capability)
        if match is None:
            return (
                f"No tool is registered for capability '{capability}'. "
                "Try a different capability string or check the available capabilities."
            )
        if not match.available:
            return (
                f"Tool '{match.name}' is registered for capability '{capability}' "
                "but is not installed on this system. Consider an alternative capability."
            )
        if match.tool_class is None:
            return (
                f"Tool '{match.name}' for '{capability}' has no local class "
                "(MCP-only tools are not yet supported in this version)."
            )

        tool = match.tool_class(scope=self.scope)

        action_id = await self.state.log_action(
            engagement_id=self.engagement_id,
            phase=self.name,
            agent=self.__class__.__name__,
            tool=match.name,
            input_data=tool_args,
        )

        try:
            self._logger.info(
                "Resolved '%s' → '%s'; args: %s",
                capability,
                match.name,
                tool_args,
            )
            validated = tool.validate_input(tool_args)
            raw_output = await tool.execute(validated)
            parsed = tool.parse_output(raw_output)

            await self.state.complete_action(action_id, output_data=parsed.model_dump())
            await self._persist_tool_output(parsed)

            return parsed.model_dump_json(indent=2)

        except Exception as exc:
            self._logger.error(
                "Tool '%s' (capability '%s') failed: %s",
                match.name,
                capability,
                exc,
                exc_info=True,
            )
            await self.state.complete_action(
                action_id,
                output_data={"error": str(exc)},
                status="failed",
            )
            return f"Tool '{match.name}' failed with error: {exc}"

    # ------------------------------------------------------------------
    # State persistence helpers
    # ------------------------------------------------------------------

    async def _persist_tool_output(self, parsed: ToolOutput) -> None:
        """Persist discovered endpoints and paths from tool output.

        Writes each discovery to BOTH:
        - ``targets`` table (via ``upsert_target``) for backward compat
        - ``endpoints`` table (via ``add_endpoint``) so the Exploit Agent
          can pick them up via ``get_new_endpoints()``

        Args:
            parsed: The ToolOutput returned by a tool's parse_output().
        """
        # Katana and crawlers return a list of endpoint URL strings
        for field_name in ("endpoints", "urls"):
            if hasattr(parsed, field_name):
                for url in getattr(parsed, field_name):  # type: ignore[attr-defined]
                    url_str = str(url)
                    endpoint_data: dict[str, Any] = {
                        "ip": url_str,
                        "hostnames": [url_str],
                        "tags": ["endpoint", "scan"],
                    }
                    target_id = await self.state.upsert_target(self.engagement_id, endpoint_data)
                    # Write to endpoints table for Exploit Agent polling
                    ep_id = await self.state.add_endpoint(
                        engagement_id=self.engagement_id,
                        url=url_str,
                        discovered_by=self.name,
                    )
                    self._discovered_endpoints.append({**endpoint_data, "id": target_id})
                    self._logger.info(
                        "Persisted endpoint: %s (target_id=%s, endpoint_id=%s)",
                        url_str,
                        target_id,
                        ep_id,
                    )

        # ffuf and directory fuzzers return a list of path strings
        if hasattr(parsed, "paths"):
            for path in parsed.paths:  # type: ignore[attr-defined]
                path_str = str(path)
                path_data: dict[str, Any] = {
                    "ip": path_str,
                    "hostnames": [path_str],
                    "tags": ["path", "scan"],
                }
                target_id = await self.state.upsert_target(self.engagement_id, path_data)
                ep_id = await self.state.add_endpoint(
                    engagement_id=self.engagement_id,
                    url=path_str,
                    discovered_by=self.name,
                )
                self._discovered_endpoints.append({**path_data, "id": target_id})
                self._logger.info(
                    "Persisted path: %s (target_id=%s, endpoint_id=%s)",
                    path_str,
                    target_id,
                    ep_id,
                )

        # Parameter discovery tools return a list of parameter name strings
        if hasattr(parsed, "parameters"):
            for param in parsed.parameters:  # type: ignore[attr-defined]
                param_str = str(param)
                param_data: dict[str, Any] = {
                    "ip": param_str,
                    "hostnames": [param_str],
                    "tags": ["parameter", "scan"],
                }
                target_id = await self.state.upsert_target(self.engagement_id, param_data)
                self._discovered_endpoints.append({**param_data, "id": target_id})
                self._logger.info("Persisted parameter: %s", param_str)

    # ------------------------------------------------------------------
    # Authentication helper
    # ------------------------------------------------------------------

    async def _authenticate_with_creds(
        self,
        authenticator: Any,
        creds: list[dict[str, Any]],
        scope_values: list[str],
    ) -> str:
        """Try each valid credential via WebAuthenticator, return cookie string.

        Uses the WebAuthenticator's deterministic CSRF-aware login flow
        instead of manually crafting POST requests.

        Args:
            authenticator: WebAuthenticator instance.
            creds: List of credential dicts (must have ``username``, ``password``).
            scope_values: Scope target values for constructing the login URL.

        Returns:
            Cookie header string (``"k=v; k2=v2"``), or ``""`` on failure.
        """
        # Discover the login URL by probing common paths
        import asyncio as _asyncio

        login_url = ""
        if scope_values:
            from clinkz.tools.http_client import HTTPClientTool

            probe_paths = ["/login.php", "/login", "/signin", "/admin", "/auth"]
            base = f"http://{scope_values[0]}"
            for path in probe_paths:
                probe = f"{base}{path}"
                try:
                    http = HTTPClientTool(
                        scope=self.scope, timeout=10, engagement_id=self.engagement_id
                    )
                    validated = http.validate_input({"url": probe, "method": "HEAD"})
                    raw = await _asyncio.wait_for(http.execute(validated), timeout=10)
                    parsed = http.parse_output(raw)
                    if parsed.status_code and parsed.status_code < 400:
                        login_url = probe
                        self._logger.info("Discovered login URL for scan auth: %s", login_url)
                        break
                except Exception:
                    continue
            if not login_url:
                login_url = f"{base}/login"

        for cred in creds:
            if not cred.get("valid", False):
                continue
            result = await authenticator.authenticate(
                login_url,
                cred.get("username", ""),
                cred.get("password", ""),
            )
            if result.success:
                cookie_str = "; ".join(f"{k}={v}" for k, v in result.session_cookies.items())
                # Add login URL (and common variants) to skip list so we
                # never revisit login pages after successful authentication
                if login_url:
                    from urllib.parse import urlparse

                    parsed = urlparse(login_url)
                    normalised = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
                    self._auth_skip_urls.add(normalised)
                    self._logger.info("Added login URL to skip list: %s", normalised)
                self._logger.info(
                    "Authenticated for scan via WebAuthenticator — cookies: %s",
                    list(result.session_cookies.keys()),
                )
                return cookie_str

        self._logger.warning("All credential attempts failed for scan authentication")
        return ""

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run attack surface mapping against discovered web services.

        Builds an initial observation from ``input_data``, runs the ReAct
        loop until the LLM signals completion, then retrieves all persisted
        endpoints from the state store.

        Args:
            input_data: Accepts the following optional keys:

                - ``hosts``: list of host dicts from recon (each should have
                  services to identify HTTP/HTTPS ports).
                - ``urls``: list of URL strings to scan directly (overrides
                  host-based URL derivation when provided).
                - ``task``: free-text description of the scan task (e.g.,
                  from the Orchestrator for a focused sub-task).

        Returns:
            Dict with keys:

            - ``summary``: LLM final_answer string.
            - ``endpoints``: list of all persisted endpoint/path dicts.
            - ``status``: always ``"complete"`` on success.
        """
        self._discovered_endpoints = []

        # Load session cookies for authenticated crawling.
        # Priority order:
        # 1. session_cookies passed directly from orchestrator (already verified)
        # 2. Sessions in state store (verify, re-auth if expired)
        # 3. Credentials in input_data (authenticate from scratch)
        from clinkz.tools.auth import WebAuthenticator

        authenticator = WebAuthenticator(
            scope=self.scope,
            engagement_id=self.engagement_id,
        )
        scope_values = [str(e.value) for e in self.scope.targets]
        creds = input_data.get("credentials", [])

        # 1. Check for cookies passed directly from the orchestrator
        direct_cookies: dict[str, str] = input_data.get("session_cookies") or {}
        if direct_cookies and isinstance(direct_cookies, dict):
            check_url = f"http://{scope_values[0]}/" if scope_values else ""
            if check_url:
                session_valid = await authenticator.verify_session(check_url, direct_cookies)
                if session_valid:
                    self._session_cookies = "; ".join(f"{k}={v}" for k, v in direct_cookies.items())
                    self._logger.info(
                        "Using orchestrator-provided session cookies (%d cookies, verified)",
                        len(direct_cookies),
                    )
                else:
                    self._logger.warning("Orchestrator session cookies expired — re-authenticating")
                    self._session_cookies = await self._authenticate_with_creds(
                        authenticator, creds, scope_values
                    )
            else:
                self._session_cookies = "; ".join(f"{k}={v}" for k, v in direct_cookies.items())
                self._logger.info(
                    "Using orchestrator-provided session cookies (%d, unverified)",
                    len(direct_cookies),
                )

        # 2. Fall back to sessions in state store
        if not self._session_cookies:
            sessions = await self.state.get_sessions(self.engagement_id)

            if sessions:
                latest = sessions[-1]
                cookies_dict: dict[str, str] = latest.get("cookies", {})
                if cookies_dict:
                    check_url = f"http://{scope_values[0]}/" if scope_values else ""

                    if check_url:
                        session_valid = await authenticator.verify_session(check_url, cookies_dict)
                        if session_valid:
                            self._session_cookies = "; ".join(
                                f"{k}={v}" for k, v in cookies_dict.items()
                            )
                            self._logger.info(
                                "Verified state-store session cookies (%d cookies)",
                                len(cookies_dict),
                            )
                        else:
                            self._logger.warning("State-store session expired — re-authenticating")
                            self._session_cookies = await self._authenticate_with_creds(
                                authenticator, creds, scope_values
                            )
                    else:
                        self._session_cookies = "; ".join(
                            f"{k}={v}" for k, v in cookies_dict.items()
                        )
                        self._logger.info(
                            "Loaded session cookies (unverified) for crawling (%d cookies)",
                            len(cookies_dict),
                        )
            elif creds:
                # No session at all — authenticate from scratch
                self._logger.info(
                    "No existing session — authenticating via WebAuthenticator with %d credentials",
                    len(creds),
                )
                self._session_cookies = await self._authenticate_with_creds(
                    authenticator, creds, scope_values
                )

        hosts: list[dict[str, Any]] = input_data.get("hosts") or []
        urls: list[str] = [str(u) for u in (input_data.get("urls") or [])]
        task_text: str = input_data.get("task", "")
        scope_values: list[str] = [str(e.value) for e in self.scope.targets]

        # Derive URLs from host data if not explicitly provided
        if not urls:
            for host in hosts:
                for svc in host.get("services") or []:
                    port = svc.get("port")
                    ip = host.get("ip", "")
                    if port == 80:
                        urls.append(f"http://{ip}")
                    elif port == 443:
                        urls.append(f"https://{ip}")
                    elif port and svc.get("name", "").startswith("http"):
                        scheme = "https" if "ssl" in svc.get("name", "") else "http"
                        urls.append(f"{scheme}://{ip}:{port}")

        # Build the initial observation for the LLM
        parts: list[str] = []
        if task_text:
            parts.append(f"Task: {task_text}")
        if urls:
            parts.append(f"Target URLs: {', '.join(urls)}")
        elif hosts:
            parts.append(f"Target hosts: {', '.join(h.get('ip', '') for h in hosts)}")
        parts.append(f"In-scope targets: {', '.join(scope_values)}")
        # Inject session/credential context for the LLM
        if self._session_cookies:
            parts.append(
                "AUTHENTICATED SESSION: You have session "
                f"cookies ({self._session_cookies[:80]}...). "
                "Crawl authenticated. Pass cookies to "
                "crawling tools."
            )
        parts.append(
            "\nYou are a REASONING-FIRST attack surface mapper. Your approach:"
            "\n1. AUTHENTICATE FIRST: If credentials or session cookies are available, log in."
            "\n2. EXPLORE the application: Visit each page, understand what it DOES."
            "\n3. CRAWL: web_crawling with cookies for authenticated surface."
            "\n4. FUZZ: directory_fuzzing to find hidden paths."
            "\n5. For EVERY form/parameter: REASON about what the server does with the input."
            "\n   Tag each parameter with WHY it's a vulnerability candidate."
            "\n6. If crawling returns few results, THINK about why and adapt."
            "\n7. Check for info disclosure: headers, comments, JS secrets, error messages."
            "\n\nDo NOT just collect URLs. UNDERSTAND the application and TAG parameters "
            "with reasoning for the Exploit Agent."
            "\nWhen you have thoroughly mapped the attack surface, return your final_answer "
            "with parameter analysis including vulnerability reasoning."
        )
        initial_observation = "\n".join(parts)

        self._logger.info(
            "ScanAgent starting — target URLs: %s",
            urls or [h.get("ip") for h in hosts],
        )

        final_answer = await self._react_loop(initial_observation)
        endpoints_data = await self.state.get_targets(self.engagement_id)

        return {
            "summary": final_answer,
            "endpoints": endpoints_data,
            "status": "complete",
        }
