"""Tool Resolver — dynamic capability-based tool discovery.

Agents never reference tools by name.  Instead they describe what capability
they need (e.g., "port_scanning") and the resolver finds the best available
tool — MCP server first, local CLI tool second.

Usage::

    resolver = ToolResolver()

    # Find the best tool for a capability
    match = resolver.find_tool("port_scanning")
    if match and match.available:
        print(f"Use {match.name} via {match.source}")

    # List everything the system can do
    caps = resolver.get_all_capabilities()

    # Check if a specific binary exists
    ok = resolver.is_available("nmap")
"""

from __future__ import annotations

import importlib
import logging
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from clinkz.tools.base import ToolBase

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
]

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
    """

    name: str
    source: str  # "mcp" | "local"
    available: bool
    tool_class: type[ToolBase] | None = field(default=None)
    mcp_endpoint: str | None = field(default=None)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class ToolResolver:
    """Discovers and indexes all available tools by capability.

    On construction, imports all tool modules so that ToolBase.__subclasses__()
    returns every registered tool.  Builds two indexes:

    - ``_capability_map``: capability string → list of ToolBase subclasses
    - ``_name_map``:       tool binary name  → ToolBase subclass

    MCP server discovery is built as a stub interface — call
    ``check_mcp_servers()`` which returns an empty list until real MCP
    endpoints are configured.

    Args:
        mcp_endpoints: Optional list of MCP server base URLs to probe.
    """

    def __init__(self, mcp_endpoints: list[str] | None = None) -> None:
        self._mcp_endpoints: list[str] = mcp_endpoints or []
        self._capability_map: dict[str, list[type[ToolBase]]] = defaultdict(list)
        self._name_map: dict[str, type[ToolBase]] = {}
        self._discover()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_tool(self, capability: str) -> ToolMatch | None:
        """Return the best tool for a given capability.

        Preference order: MCP server → locally available binary → unavailable local.
        Returns None if no tool is registered for the capability.

        Args:
            capability: Capability string (e.g., "port_scanning").

        Returns:
            Best ToolMatch or None if unknown capability.
        """
        # MCP takes priority when available
        for server in self.check_mcp_servers():
            if capability in server.get("capabilities", []):
                return ToolMatch(
                    name=server["name"],
                    source="mcp",
                    available=True,
                    mcp_endpoint=server.get("endpoint"),
                )

        # Local tools
        matches = self._capability_map.get(capability, [])
        if not matches:
            return None

        # Prefer tools whose binary is on PATH
        for cls in matches:
            tool_name = self._class_to_name(cls)
            if tool_name and self.is_available(tool_name):
                return ToolMatch(
                    name=tool_name,
                    source="local",
                    available=True,
                    tool_class=cls,
                )

        # No available binary found — return first match anyway so the caller
        # can decide whether to install the tool or skip
        cls = matches[0]
        tool_name = self._class_to_name(cls) or "unknown"
        return ToolMatch(name=tool_name, source="local", available=False, tool_class=cls)

    def find_tools(self, capability: str) -> list[ToolMatch]:
        """Return ALL tools registered for a capability (MCP + local).

        Args:
            capability: Capability string to look up.

        Returns:
            List of ToolMatch objects, MCP entries first.  May be empty.
        """
        results: list[ToolMatch] = []

        for server in self.check_mcp_servers():
            if capability in server.get("capabilities", []):
                results.append(
                    ToolMatch(
                        name=server["name"],
                        source="mcp",
                        available=True,
                        mcp_endpoint=server.get("endpoint"),
                    )
                )

        for cls in self._capability_map.get(capability, []):
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

    def is_available(self, tool_name: str) -> bool:
        """Check whether a tool binary is available on PATH.

        Args:
            tool_name: Binary name (e.g., "nmap", "ffuf").

        Returns:
            True if ``shutil.which(tool_name)`` finds the binary.
        """
        return shutil.which(tool_name) is not None

    def get_all_capabilities(self) -> list[str]:
        """Return every capability the system knows about (sorted).

        Returns:
            Sorted list of capability strings from all registered tools.
        """
        return sorted(self._capability_map.keys())

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
        """Probe configured MCP endpoints and return available servers.

        This is a stub interface.  Actual MCP client probing is implemented
        in tools/mcp_client.py (future work).  Until then it always returns
        an empty list so the resolver falls back to local tools.

        Returns:
            List of server descriptor dicts with keys:
            ``name``, ``endpoint``, ``capabilities``.
        """
        # TODO: iterate self._mcp_endpoints, attempt HTTP probe, return live servers
        return []

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

        The ``name`` property is defined on instances, not on the class, so
        we must instantiate with a dummy scope (no targets — only used to
        read the name, never to run).

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
