"""Tool Resolver — dynamic capability-based tool discovery.

Agents never reference tools by name.  Instead they describe what capability
they need (e.g., "port_scanning") and the resolver finds the best available
tool — MCP server first, local CLI tool second.

Usage::

    resolver = ToolResolver()

    # Connect to configured MCP servers (call once at startup)
    await resolver.initialize()

    # Find the best tool for a capability
    match = await resolver.find_tool("port_scanning")
    if match and match.available:
        if match.source == "mcp":
            result = await match.mcp_client.call_tool(match.name, args)
        else:
            tool = match.tool_class(scope=scope)
            result = tool.parse_output(await tool.execute(args))

    # List everything the system can do
    caps = resolver.get_all_capabilities()

    # Check if a specific binary exists
    ok = resolver.is_available("nmap")

    # Tear down MCP connections when finished
    await resolver.shutdown()
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import shutil
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from clinkz.tools.base import ToolBase
from clinkz.tools.binary_identity import BINARY_SIGNATURES, verify_binary_identity

if TYPE_CHECKING:
    from clinkz.tools.mcp_client import MCPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool modules to import for auto-discovery.
# Add new tool modules here when they are created.
# ---------------------------------------------------------------------------
_TOOL_MODULES = [
    "clinkz.tools.nmap",
    "clinkz.tools.subfinder",
    "clinkz.tools.httpx_tool",
    "clinkz.tools.whatweb",
    "clinkz.tools.wafw00f",
    "clinkz.tools.ffuf",
    "clinkz.tools.katana",
    "clinkz.tools.nikto",
    "clinkz.tools.nuclei",
    "clinkz.tools.sqlmap",
    "clinkz.tools.http_client",
    "clinkz.tools.auth",
    "clinkz.tools.installer",
    "clinkz.browser.oracle",
]

# ---------------------------------------------------------------------------
# Keyword map: capability string → words to look for in tool name/description
# Used to infer capabilities from MCP tools that don't self-report them.
# ---------------------------------------------------------------------------
_CAPABILITY_KEYWORDS: dict[str, list[str]] = {
    "port_scanning": ["port scan", "port", "nmap", "network scan"],
    "service_detection": ["service detect", "service version", "banner grab"],
    "os_fingerprinting": ["os fingerprint", "os detect"],
    "host_discovery": ["host discover", "ping sweep", "alive"],
    "subdomain_enumeration": ["subdomain", "dns enum", "domain discover"],
    "passive_recon": ["passive", "osint", "shodan", "censys"],
    "dns_enumeration": ["dns", "resolver", "zone transfer"],
    "http_probing": ["http probe", "http check", "http alive", "httpx"],
    "technology_detection": ["technology detect", "tech detect", "stack detect"],
    "alive_check": ["alive check", "ping", "reachable"],
    "technology_fingerprinting": ["fingerprint", "whatweb", "wappalyzer"],
    "cms_detection": ["cms detect", "wordpress", "drupal", "joomla"],
    "web_technology_detection": ["web tech", "web technology"],
    "waf_detection": ["waf detect", "web application firewall", "wafw00f"],
    "firewall_detection": ["firewall detect", "bypass"],
    "directory_fuzzing": ["directory fuzz", "dir fuzz", "ffuf", "gobuster", "dirbust"],
    "parameter_fuzzing": ["parameter fuzz", "param fuzz"],
    "endpoint_discovery": ["endpoint discover", "path discover", "url discover"],
    "web_crawling": ["crawl", "spider", "katana"],
    "url_enumeration": ["url enum", "sitemap", "linkfinder"],
    "web_vulnerability_scanning": ["web vuln", "nikto", "web scan"],
    "misconfiguration_detection": ["misconfigur", "default cred", "exposed"],
    "header_analysis": ["header analys", "security header"],
    "vulnerability_scanning": ["vuln scan", "nuclei", "cve scan", "template"],
    "cve_detection": ["cve detect", "cve check"],
    "template_based_scanning": ["template scan", "yaml template"],
    "sql_injection_testing": ["sql inject", "sqli", "sqlmap"],
    "sqli_detection": ["sqli detect", "blind sql"],
    "database_fingerprinting": ["database fingerprint", "db fingerprint"],
    "http_request": ["http request", "http client", "http get", "http post"],
    "client_side_execution": [
        "headless browser",
        "browser automation",
        "playwright",
        "puppeteer",
        "render page",
        "execute javascript",
    ],
}

# ---------------------------------------------------------------------------
# Tool fallback chains — ranked preference order per capability.
# Agents request a capability; the resolver tries tools in this order.
# ---------------------------------------------------------------------------

TOOL_CHAINS: dict[str, list[str]] = {
    "web_crawling": ["katana", "gospider", "hakrawler", "zap_spider"],
    "directory_fuzzing": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "port_scanning": ["nmap", "masscan", "rustscan"],
    "vulnerability_scanning": ["nuclei", "nikto", "zap_active"],
    "sql_injection_testing": ["sqlmap", "ghauri"],
    "web_fingerprinting": ["whatweb", "wappalyzer", "httpx"],
    "waf_detection": ["wafw00f"],
    "subdomain_discovery": ["subfinder", "amass", "knockpy"],
    "http_request": ["http_client"],
    # P7 — the client-side execution oracle. Ranked like every other chain; the
    # alternates are declared preference order, not a claim that they ship.
    # ``find_tools_ranked`` filters to what is actually available, so an absent
    # oracle yields an empty chain and the caller keeps its unproven lead.
    "client_side_execution": ["playwright_chromium", "playwright_firefox", "selenium_chromium"],
}

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class ToolMatch:
    """Result returned by find_tool() / find_tools().

    Attributes:
        name: Tool binary / server name (e.g., "nmap", "subfinder").
        source: Where the tool lives — "mcp" or "local".
        available: True if the tool is currently accessible.
        tool_class: ToolBase subclass for local tools (None for MCP).
        mcp_endpoint: URL/endpoint for MCP tools (None for local).
        mcp_client: Live MCPClient instance for MCP tools (None for local).
    """

    name: str
    source: str  # "mcp" | "local"
    available: bool
    tool_class: type[ToolBase] | None = field(default=None)
    mcp_endpoint: str | None = field(default=None)
    mcp_client: Any = field(default=None)  # MCPClient | None


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class ToolResolver:
    """Discovers and indexes all available tools by capability.

    On construction, imports all tool modules so that ToolBase.__subclasses__()
    returns every registered tool, and builds two local indexes:

    - ``_capability_map``: capability string → list of ToolBase subclasses
    - ``_name_map``:       tool binary name  → ToolBase subclass

    Call ``await resolver.initialize()`` at startup to probe configured MCP
    servers.  MCP tool connections are cached — no reconnection per call.
    Call ``await resolver.shutdown()`` to close all MCP connections.

    Args:
        mcp_servers: Optional list of MCP server commands or URLs to probe.
                     If None, reads ``settings.mcp_servers`` from config.
    """

    def __init__(self, mcp_servers: list[str] | None = None) -> None:
        # Support legacy kwarg name used by existing tests
        self._mcp_endpoints: list[str] = mcp_servers or []
        self._capability_map: dict[str, list[type[ToolBase]]] = defaultdict(list)
        self._name_map: dict[str, type[ToolBase]] = {}

        # MCP state (populated by initialize())
        self._mcp_tools_cache: list[dict[str, Any]] = []
        self._mcp_clients: dict[str, MCPClient] = {}  # server_key → client

        # Capabilities the run actually ASKED for. Recorded because "this tool
        # never ran" has two readings that call for opposite follow-up: nothing
        # in the engine reaches for its capability (nuclei, subfinder — both
        # deliberately unwired), or a phase asked and the tool still contributed
        # nothing (the ffuf shape). Without this the contribution ledger cannot
        # tell them apart, and a permanent false alarm for the first kind is how
        # an alarm section stops being read.
        self.requested_capabilities: set[str] = set()

        self._discover()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self, extra_servers: list[str] | None = None) -> None:
        """Connect to all configured MCP servers and cache their tool lists.

        Safe to call multiple times — already-connected servers are skipped.
        Servers that fail to connect are logged and skipped (graceful fallback).

        Args:
            extra_servers: Additional server specs to probe on top of those
                           passed to ``__init__``.
        """
        from clinkz.tools.mcp_client import MCPClient

        servers = list(self._mcp_endpoints) + (extra_servers or [])
        if not servers:
            # Also check global settings
            try:
                from clinkz.config import settings

                servers = list(settings.mcp_servers)
            except Exception:
                pass

        for spec in servers:
            server_key = spec if isinstance(spec, str) else "|".join(spec)
            if server_key in self._mcp_clients:
                continue  # already connected

            client = MCPClient()
            try:
                await client.connect(spec)
                tools = await client.list_tools()
                self._mcp_clients[server_key] = client

                for tool_info in tools:
                    caps = _infer_capabilities(tool_info.name, tool_info.description)
                    from clinkz.tools.mcp_client import _is_url

                    endpoint = spec if isinstance(spec, str) and _is_url(spec) else None
                    self._mcp_tools_cache.append(
                        {
                            "name": tool_info.name,
                            "endpoint": endpoint,
                            "capabilities": caps,
                            "server_key": server_key,
                            "tool_info": tool_info,
                        }
                    )
                logger.info(
                    "Resolver: MCP server %s — %d tool(s) indexed",
                    spec,
                    len(tools),
                )
            except Exception as exc:
                logger.warning(
                    "Resolver: MCP server %s unavailable (%s) — skipping",
                    spec,
                    exc,
                )

    async def shutdown(self) -> None:
        """Disconnect all cached MCP clients."""
        for key, client in list(self._mcp_clients.items()):
            try:
                await client.disconnect()
            except Exception as exc:
                logger.warning("Resolver: error disconnecting %s: %s", key, exc)
        self._mcp_clients.clear()
        self._mcp_tools_cache.clear()
        logger.debug("Resolver: all MCP connections closed")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_tool(self, capability: str) -> ToolMatch | None:
        """Return the best tool for a given capability (synchronous).

        Checks cached MCP tools first, then locally installed binaries.
        Returns None if no tool is registered for the capability.

        .. note::

            MCP results are only available after ``await initialize()`` has
            been called.  In a purely synchronous context (or before
            initialisation) this will only return local tools.

        Args:
            capability: Capability string (e.g., "port_scanning").

        Returns:
            Best ToolMatch or None if unknown capability.
        """
        self.requested_capabilities.add(capability)

        # MCP takes priority when available (populated by initialize())
        for entry in self._mcp_tools_cache:
            if capability in entry.get("capabilities", []):
                server_key = entry["server_key"]
                return ToolMatch(
                    name=entry["name"],
                    source="mcp",
                    available=True,
                    mcp_endpoint=entry.get("endpoint"),
                    mcp_client=self._mcp_clients.get(server_key),
                )

        # Local tools, in the capability's DECLARED preference order.
        matches = self._chain_ordered(capability)
        if not matches:
            return None

        for cls in matches:
            tool_name = self._class_to_name(cls)
            if tool_name and self.is_available(tool_name):
                return ToolMatch(
                    name=tool_name,
                    source="local",
                    available=True,
                    tool_class=cls,
                )

        # No available binary — return first match so caller can decide
        cls = matches[0]
        tool_name = self._class_to_name(cls) or "unknown"
        return ToolMatch(name=tool_name, source="local", available=False, tool_class=cls)

    def _chain_ordered(self, capability: str) -> list[type[ToolBase]]:
        """Candidate classes for *capability*, ordered by :data:`TOOL_CHAINS`.

        ``_capability_map`` is built by walking ``ToolBase.__subclasses__()``, so
        its order is MODULE IMPORT order — which is alphabetical, arbitrary with
        respect to preference, and was never the declared chain. That went
        unnoticed for as long as every chained capability resolved to exactly one
        wrapper: with one candidate, any order is the right order.

        The moment a fallback becomes real the defect becomes live. Declaring
        ``web_fingerprinting`` on the httpx wrapper (so the chain's stated
        fallback could actually fire) made ``find_tool`` return httpx ahead of
        whatweb, silently inverting a preference the chain states explicitly.
        A declared order that the resolver does not read is not an order.

        Tools not named in the chain keep their existing relative position after
        the named ones — a capability with no chain entry (``login``,
        ``dom_rendering``) is unaffected, and a wrapper that declares a chained
        capability without being listed in the chain is a usable last resort
        rather than an error.

        Args:
            capability: The capability being resolved.

        Returns:
            Candidate classes, best-first.
        """
        candidates = list(self._capability_map.get(capability, []))
        chain = TOOL_CHAINS.get(capability)
        if not chain or len(candidates) < 2:
            return candidates
        rank = {name: position for position, name in enumerate(chain)}
        return sorted(
            candidates,
            key=lambda cls: (
                rank.get(self._class_to_name(cls) or "", len(chain)),
                candidates.index(cls),
            ),
        )

    def find_tool_by_name(self, tool_name: str) -> ToolMatch | None:
        """Return the ToolMatch for one specific tool, by binary name.

        The companion to :meth:`find_tool`, and the piece
        :meth:`try_until_sufficient` was missing. That method walks a chain of
        tool NAMES and hands each one to a callback — but a callback that
        answers by calling ``find_tool(capability)`` re-resolves the same
        first-available class on every iteration, so a chain of four crawlers
        runs the first crawler four times. The declared fallback order was
        nominal for as long as the callbacks ignored their ``tool_name``
        argument, which is all of them.

        Args:
            tool_name: Binary name as it appears in ``TOOL_CHAINS``.

        Returns:
            A ToolMatch for that exact tool, or ``None`` when no local wrapper
            is registered under that name (chain entries name tools we have no
            wrapper for — ``gospider``, ``feroxbuster`` — which is a preference
            order, not a claim that they ship).
        """
        cls = self._name_map.get(tool_name)
        if cls is None:
            return None
        return ToolMatch(
            name=tool_name,
            source="local",
            available=self.is_available(tool_name),
            tool_class=cls,
        )

    def find_tools(self, capability: str) -> list[ToolMatch]:
        """Return ALL tools registered for a capability (MCP + local).

        Args:
            capability: Capability string to look up.

        Returns:
            List of ToolMatch objects, MCP entries first.  May be empty.
        """
        self.requested_capabilities.add(capability)
        results: list[ToolMatch] = []

        for entry in self._mcp_tools_cache:
            if capability in entry.get("capabilities", []):
                server_key = entry["server_key"]
                results.append(
                    ToolMatch(
                        name=entry["name"],
                        source="mcp",
                        available=True,
                        mcp_endpoint=entry.get("endpoint"),
                        mcp_client=self._mcp_clients.get(server_key),
                    )
                )

        for cls in self._chain_ordered(capability):
            tool_name = self._class_to_name(cls)
            if tool_name:
                results.append(
                    ToolMatch(
                        name=tool_name,
                        source="local",
                        available=self.is_available(tool_name),
                        tool_class=cls,
                    )
                )

        return results

    # Tools that don't need a binary check — they're Python-native or
    # use other binaries internally (e.g., http_client uses aiohttp,
    # tool_installer uses apt-get/pip inside Docker).
    _ALWAYS_AVAILABLE: set[str] = {"http_client", "web_authenticator", "tool_installer"}

    def is_available(self, tool_name: str) -> bool:
        """Check whether a tool binary is available *and* is the expected program.

        Tools in ``_ALWAYS_AVAILABLE`` are Python-native and don't need a
        binary check.  For all others, when ``TOOL_EXEC_MODE=docker``, checks
        inside the configured Docker container via ``docker exec ... which <tool>``.
        Otherwise checks the host PATH with ``shutil.which()``.

        In both modes, when ``binary_identity.BINARY_SIGNATURES`` lists the
        tool, its ``--version`` output is additionally verified against the
        expected signature so that unrelated programs sharing the same name
        (e.g. the Python ``httpx`` library CLI) are not mistaken for the
        tool Clinkz actually wants.

        Args:
            tool_name: Binary name (e.g., "nmap", "ffuf").

        Returns:
            True if the binary is found *and* identity-verified (or not
            registered for verification).

        Raises:
            RuntimeError: If the Docker container is not running.
        """
        if tool_name in self._ALWAYS_AVAILABLE:
            return True

        # A tool whose runtime is a Python package (P7's browser oracle) answers
        # for itself; only a PATH binary falls through to the binary check.
        cls = self._name_map.get(tool_name)
        if cls is not None:
            native = cls.native_availability()
            if native is not None:
                return native

        from clinkz.config import settings

        if settings.tool_exec_mode == "docker":
            import subprocess

            try:
                result = subprocess.run(
                    ["docker", "exec", settings.docker_container, "which", tool_name],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    stderr = result.stderr.decode(errors="replace").lower()
                    if "is not running" in stderr or "no such container" in stderr:
                        raise RuntimeError(
                            f"Docker container '{settings.docker_container}' is not "
                            f"running. Start it with: docker start {settings.docker_container}"
                        )
                    return False
                exec_prefix: list[str] = [
                    "docker",
                    "exec",
                    settings.docker_container,
                ]
            except RuntimeError:
                raise
            except Exception:
                return False
        else:
            if shutil.which(tool_name) is None:
                return False
            exec_prefix = []

        return _identity_ok(tool_name, exec_prefix)

    def get_all_capabilities(self) -> list[str]:
        """Return every capability the system knows about (sorted).

        Includes both local tool capabilities and MCP-discovered capabilities.

        Returns:
            Sorted list of capability strings from all registered tools.
        """
        caps = set(self._capability_map.keys())
        for entry in self._mcp_tools_cache:
            caps.update(entry.get("capabilities", []))
        return sorted(caps)

    def get_tools_by_category(self, category: str) -> list[str]:
        """Return tool names whose category matches.

        Args:
            category: Category string — "recon", "scan", "exploit", "utility".

        Returns:
            Sorted list of tool names in that category.
        """
        return sorted(
            name
            for name, cls in self._name_map.items()
            if getattr(cls, "category", "utility") == category
        )

    def check_mcp_servers(self) -> list[dict[str, Any]]:
        """Return currently cached MCP tool entries.

        Each entry represents one tool discovered on an MCP server::

            {
                "name": "tool_name",
                "endpoint": "http://..." or None,
                "capabilities": ["cap1", "cap2"],
                "server_key": "...",
            }

        Returns an empty list until :meth:`initialize` has been awaited.

        Returns:
            List of MCP tool descriptor dicts.
        """
        return [
            {k: v for k, v in entry.items() if k != "tool_info"} for entry in self._mcp_tools_cache
        ]

    def get_mcp_client_for_tool(self, tool_name: str) -> MCPClient | None:
        """Return the live MCPClient that hosts the named tool.

        Args:
            tool_name: Tool name as discovered via :meth:`find_tool`.

        Returns:
            The connected MCPClient, or None if not found.
        """
        for entry in self._mcp_tools_cache:
            if entry["name"] == tool_name:
                return self._mcp_clients.get(entry["server_key"])
        return None

    # ------------------------------------------------------------------
    # Fallback chain API
    # ------------------------------------------------------------------

    def find_tools_ranked(self, capability: str) -> list[str]:
        """Return available tool names from the fallback chain for a capability.

        Tools are returned in preference order (first = best). Only tools
        that are currently available (binary found) are included.

        Args:
            capability: Capability key from TOOL_CHAINS (e.g. "port_scanning").

        Returns:
            List of available tool names in ranked order. Empty list if the
            capability is unknown or no tools are available.
        """
        self.requested_capabilities.add(capability)
        return list(self.available_chain(capability))

    def available_chain(self, capability: str) -> tuple[str, ...]:
        """The declared chain for *capability*, filtered to what is available.

        Identical to :meth:`find_tools_ranked` except that it does NOT record
        the capability as requested — the observability layer asks this at report
        time to work out which tool a chain would have resolved to, and a
        question asked *about* the run must never become part of what the run
        did. Reading the request set through a method that also writes to it is
        how a measurement starts measuring itself.
        """
        return tuple(name for name in TOOL_CHAINS.get(capability, []) if self.is_available(name))

    async def try_until_sufficient(
        self,
        capability: str,
        min_results: int,
        run_fn: Callable[..., Any],
        *args: Any,
    ) -> tuple[str, Any]:
        """Try each tool in a fallback chain until output meets threshold.

        Calls ``await run_fn(tool_name, *args)`` for each available tool in
        the chain. The *run_fn* must return a result whose length (or other
        measure) the caller uses to decide sufficiency — if ``len(result)``
        meets *min_results*, the search stops.

        If no tool meets the threshold, returns whichever tool produced the
        best (largest) result.

        Args:
            capability: Capability key from TOOL_CHAINS.
            min_results: Minimum number of results considered sufficient.
            run_fn: Async callable ``(tool_name, *args) -> result``.
            *args: Extra arguments forwarded to *run_fn*.

        Returns:
            Tuple of (tool_name, result) for the first sufficient tool, or
            the best result seen if none met the threshold.

        Raises:
            ValueError: If no tools are available for the capability.
        """
        ranked = self.find_tools_ranked(capability)
        if not ranked:
            raise ValueError(f"No available tools for capability '{capability}'")

        best_tool = ranked[0]
        best_result: Any = None

        for tool_name in ranked:
            try:
                result = await run_fn(tool_name, *args)
            except Exception as exc:
                logger.warning(
                    "Resolver: %s failed for capability '%s': %s",
                    tool_name,
                    capability,
                    exc,
                )
                continue

            # Track best result seen
            try:
                result_size = len(result) if result is not None else 0
            except TypeError:
                result_size = 1 if result else 0

            if best_result is None:
                best_tool, best_result = tool_name, result

            try:
                best_size = len(best_result) if best_result is not None else 0
            except TypeError:
                best_size = 1 if best_result else 0

            if result_size > best_size:
                best_tool, best_result = tool_name, result

            if result_size >= min_results:
                logger.info(
                    "Resolver: %s sufficient for '%s' (%d results)",
                    tool_name,
                    capability,
                    result_size,
                )
                return tool_name, result

        logger.info(
            "Resolver: no tool met threshold for '%s', returning best: %s",
            capability,
            best_tool,
        )
        return best_tool, best_result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover(self) -> None:
        """Import all tool modules and index ToolBase subclasses."""
        _import_tool_modules()

        for cls in ToolBase.__subclasses__():
            tool_name = self._class_to_name(cls)
            if not tool_name:
                continue

            self._name_map[tool_name] = cls
            logger.debug("Resolver: registered tool '%s' (%s)", tool_name, cls.__name__)

            for cap in getattr(cls, "capabilities", []):
                self._capability_map[cap].append(cls)
                logger.debug("  capability '%s' → %s", cap, tool_name)

    def _class_to_name(self, cls: type[ToolBase]) -> str | None:
        """Return the tool's binary name by creating a throw-away instance.

        Args:
            cls: ToolBase subclass to inspect.

        Returns:
            The tool's name string, or None on error.
        """
        try:
            from clinkz.models.scope import EngagementScope

            dummy_scope = EngagementScope(name="_resolver", targets=[])
            return cls(scope=dummy_scope).name
        except Exception as exc:
            logger.warning("Resolver: could not instantiate %s: %s", cls.__name__, exc)
            return None


# ---------------------------------------------------------------------------
# Module import helper
# ---------------------------------------------------------------------------


def _import_tool_modules() -> None:
    """Import all tool modules so ToolBase.__subclasses__() is fully populated."""
    for module_path in _TOOL_MODULES:
        try:
            importlib.import_module(module_path)
        except ImportError as exc:
            logger.warning("Resolver: could not import %s: %s", module_path, exc)


# ---------------------------------------------------------------------------
# MCP capability inference
# ---------------------------------------------------------------------------


def _identity_ok(tool_name: str, exec_prefix: list[str]) -> bool:
    """Sync wrapper around :func:`verify_binary_identity`.

    Tools without a registered signature short-circuit to True (unchanged
    legacy behavior). Otherwise the async verifier is run to completion —
    driven via ``asyncio.run`` when no loop is active, or via a throw-away
    thread when called from within a running loop.
    """
    if tool_name not in BINARY_SIGNATURES:
        return True

    # If we're already inside a running event loop, hop to a helper thread
    # with its own loop. Otherwise drive the coroutine directly.
    try:
        asyncio.get_running_loop()
        in_loop = True
    except RuntimeError:
        in_loop = False

    if not in_loop:
        return asyncio.run(verify_binary_identity(tool_name, exec_prefix))

    import threading

    result: dict[str, bool] = {"ok": False}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            result["ok"] = loop.run_until_complete(verify_binary_identity(tool_name, exec_prefix))
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join(timeout=10.0)
    return result["ok"]


def _infer_capabilities(tool_name: str, description: str) -> list[str]:
    """Infer capability strings from an MCP tool's name and description.

    Uses keyword matching against ``_CAPABILITY_KEYWORDS``.  Always adds the
    normalised tool name itself as a fallback capability so agents can always
    look up an MCP tool by name.

    Args:
        tool_name: Tool name from the MCP server.
        description: Tool description from the MCP server.

    Returns:
        Deduplicated list of inferred capability strings.
    """
    text = f"{tool_name} {description}".lower()
    caps: set[str] = set()

    for capability, keywords in _CAPABILITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            caps.add(capability)

    # Always include the normalised tool name itself
    normalised = tool_name.lower().replace("-", "_").replace(" ", "_")
    caps.add(normalised)

    return sorted(caps)
