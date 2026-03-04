"""Unit tests for ToolResolver.

Tests cover:
- All 10 tools are discovered and indexed
- Capability-based lookup returns correct tool
- find_tool returns best match (available preferred)
- find_tools returns all matches for a capability
- is_available correctly uses shutil.which
- get_all_capabilities returns expected capability strings
- get_tools_by_category returns correct tools per category
- Graceful handling when no tool matches a capability
- MCP stub returns empty list
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from clinkz.tools.resolver import ToolResolver

# ---------------------------------------------------------------------------
# Expected values
# ---------------------------------------------------------------------------

# All 10 tool binary names that must be discovered
_EXPECTED_TOOLS = {
    "nmap",
    "subfinder",
    "httpx",
    "whatweb",
    "wafw00f",
    "ffuf",
    "katana",
    "nikto",
    "nuclei",
    "sqlmap",
}

# A sample capability → expected tool name mapping for lookup assertions
_CAPABILITY_TOOL_MAP: dict[str, str] = {
    "port_scanning": "nmap",
    "service_detection": "nmap",
    "os_fingerprinting": "nmap",
    "host_discovery": "nmap",
    "subdomain_enumeration": "subfinder",
    "passive_recon": "subfinder",
    "dns_enumeration": "subfinder",
    "http_probing": "httpx",
    "technology_detection": "httpx",
    "alive_check": "httpx",
    "technology_fingerprinting": "whatweb",
    "cms_detection": "whatweb",
    "web_technology_detection": "whatweb",
    "waf_detection": "wafw00f",
    "firewall_detection": "wafw00f",
    "directory_fuzzing": "ffuf",
    "parameter_fuzzing": "ffuf",
    "endpoint_discovery": "ffuf",  # ffuf comes before katana alphabetically?
    "web_crawling": "katana",
    "url_enumeration": "katana",
    "web_vulnerability_scanning": "nikto",
    "misconfiguration_detection": "nikto",
    "header_analysis": "nikto",
    "vulnerability_scanning": "nuclei",
    "cve_detection": "nuclei",
    "template_based_scanning": "nuclei",
    "sql_injection_testing": "sqlmap",
    "sqli_detection": "sqlmap",
    "database_fingerprinting": "sqlmap",
}

_RECON_TOOLS = {"nmap", "subfinder", "httpx", "whatweb", "wafw00f"}
_SCAN_TOOLS = {"ffuf", "katana"}
_EXPLOIT_TOOLS = {"nikto", "nuclei", "sqlmap"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def resolver() -> ToolResolver:
    """Return a fresh ToolResolver with no MCP endpoints."""
    return ToolResolver()


# ---------------------------------------------------------------------------
# Discovery tests
# ---------------------------------------------------------------------------


def test_all_tools_discovered(resolver: ToolResolver) -> None:
    """All 10 tool binaries must be present in the resolver's name map."""
    found = set(resolver._name_map.keys())
    assert _EXPECTED_TOOLS == found, (
        f"Missing: {_EXPECTED_TOOLS - found}, Extra: {found - _EXPECTED_TOOLS}"
    )


def test_get_all_capabilities_non_empty(resolver: ToolResolver) -> None:
    """get_all_capabilities() must return at least one capability per tool."""
    caps = resolver.get_all_capabilities()
    assert isinstance(caps, list)
    assert len(caps) > 0
    # Should be sorted
    assert caps == sorted(caps)


def test_all_expected_capabilities_present(resolver: ToolResolver) -> None:
    """Every capability listed in _CAPABILITY_TOOL_MAP must be discoverable."""
    caps = set(resolver.get_all_capabilities())
    for cap in _CAPABILITY_TOOL_MAP:
        assert cap in caps, f"Capability '{cap}' not found in resolver"


# ---------------------------------------------------------------------------
# find_tool tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("capability,expected_tool", list(_CAPABILITY_TOOL_MAP.items()))
def test_find_tool_returns_correct_tool_when_available(
    capability: str, expected_tool: str, resolver: ToolResolver
) -> None:
    """find_tool(cap) returns the expected tool when its binary is available."""
    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/fake"):
        match = resolver.find_tool(capability)

    assert match is not None, f"No tool found for capability '{capability}'"
    assert match.name == expected_tool, (
        f"Expected '{expected_tool}' for '{capability}', got '{match.name}'"
    )
    assert match.source == "local"
    assert match.available is True
    assert match.tool_class is not None


def test_find_tool_returns_none_for_unknown_capability(resolver: ToolResolver) -> None:
    """find_tool returns None when no tool supports the capability."""
    result = resolver.find_tool("time_travel")
    assert result is None


def test_find_tool_returns_unavailable_match_when_binary_missing(
    resolver: ToolResolver,
) -> None:
    """find_tool returns a match with available=False when binary not on PATH."""
    with patch("clinkz.tools.resolver.shutil.which", return_value=None):
        match = resolver.find_tool("port_scanning")

    assert match is not None
    assert match.available is False
    assert match.name == "nmap"


# ---------------------------------------------------------------------------
# find_tools tests
# ---------------------------------------------------------------------------


def test_find_tools_returns_all_matching_tools(resolver: ToolResolver) -> None:
    """find_tools() returns every local tool for a capability."""
    # "endpoint_discovery" is shared by ffuf and katana
    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/fake"):
        matches = resolver.find_tools("endpoint_discovery")

    names = {m.name for m in matches}
    assert "ffuf" in names
    assert "katana" in names


def test_find_tools_empty_for_unknown_capability(resolver: ToolResolver) -> None:
    """find_tools() returns an empty list for an unknown capability."""
    result = resolver.find_tools("phoning_home")
    assert result == []


def test_find_tools_marks_unavailable_correctly(resolver: ToolResolver) -> None:
    """find_tools marks each match's available field via shutil.which."""
    def _mock_which(name: str) -> str | None:
        return "/usr/bin/ffuf" if name == "ffuf" else None

    with patch("clinkz.tools.resolver.shutil.which", side_effect=_mock_which):
        matches = resolver.find_tools("endpoint_discovery")

    by_name = {m.name: m for m in matches}
    assert by_name["ffuf"].available is True
    assert by_name["katana"].available is False


# ---------------------------------------------------------------------------
# is_available tests
# ---------------------------------------------------------------------------


def test_is_available_true_when_which_finds_binary(resolver: ToolResolver) -> None:
    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
        assert resolver.is_available("nmap") is True


def test_is_available_false_when_which_returns_none(resolver: ToolResolver) -> None:
    with patch("clinkz.tools.resolver.shutil.which", return_value=None):
        assert resolver.is_available("nmap") is False


# ---------------------------------------------------------------------------
# Category tests
# ---------------------------------------------------------------------------


def test_get_tools_by_category_recon(resolver: ToolResolver) -> None:
    recon = set(resolver.get_tools_by_category("recon"))
    assert _RECON_TOOLS == recon, f"Expected {_RECON_TOOLS}, got {recon}"


def test_get_tools_by_category_scan(resolver: ToolResolver) -> None:
    scan = set(resolver.get_tools_by_category("scan"))
    assert _SCAN_TOOLS == scan, f"Expected {_SCAN_TOOLS}, got {scan}"


def test_get_tools_by_category_exploit(resolver: ToolResolver) -> None:
    exploit = set(resolver.get_tools_by_category("exploit"))
    assert _EXPLOIT_TOOLS == exploit, f"Expected {_EXPLOIT_TOOLS}, got {exploit}"


def test_get_tools_by_category_unknown_returns_empty(resolver: ToolResolver) -> None:
    assert resolver.get_tools_by_category("unicorn") == []


# ---------------------------------------------------------------------------
# MCP stub tests
# ---------------------------------------------------------------------------


def test_check_mcp_servers_returns_empty_list(resolver: ToolResolver) -> None:
    """MCP discovery stub always returns empty until implemented."""
    result = resolver.check_mcp_servers()
    assert result == []


def test_find_tool_falls_back_to_local_when_no_mcp(resolver: ToolResolver) -> None:
    """find_tool() works correctly when MCP returns nothing."""
    with patch.object(resolver, "check_mcp_servers", return_value=[]):
        with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
            match = resolver.find_tool("port_scanning")

    assert match is not None
    assert match.source == "local"
    assert match.name == "nmap"


def test_find_tool_prefers_mcp_over_local(resolver: ToolResolver) -> None:
    """When MCP server advertises a capability, it is preferred over local."""
    mcp_server = {
        "name": "mcp-recon",
        "endpoint": "http://localhost:5000",
        "capabilities": ["port_scanning"],
    }
    with patch.object(resolver, "check_mcp_servers", return_value=[mcp_server]):
        with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
            match = resolver.find_tool("port_scanning")

    assert match is not None
    assert match.source == "mcp"
    assert match.name == "mcp-recon"
    assert match.mcp_endpoint == "http://localhost:5000"


# ---------------------------------------------------------------------------
# ToolBase capability / category attribute tests
# ---------------------------------------------------------------------------


def test_tool_base_classes_have_capabilities_attribute(resolver: ToolResolver) -> None:
    """Every discovered tool class must have a non-empty capabilities list."""
    for name, cls in resolver._name_map.items():
        caps = getattr(cls, "capabilities", [])
        assert isinstance(caps, list), f"{name}: capabilities is not a list"
        assert len(caps) > 0, f"{name}: capabilities list is empty"


def test_tool_base_classes_have_category_attribute(resolver: ToolResolver) -> None:
    """Every discovered tool class must have a category string."""
    valid_categories = {"recon", "scan", "exploit", "utility"}
    for name, cls in resolver._name_map.items():
        cat = getattr(cls, "category", None)
        assert cat is not None, f"{name}: category is missing"
        assert cat in valid_categories, f"{name}: category '{cat}' is not valid"
