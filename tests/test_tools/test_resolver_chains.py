"""Tests for tool fallback chains in ToolResolver."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from clinkz.tools.resolver import TOOL_CHAINS, ToolResolver


@pytest.fixture
def resolver():
    """Create a resolver instance with mocked tool availability."""
    return ToolResolver()


def test_find_tools_ranked_returns_available_only(resolver):
    """Only available tools appear in the ranked list."""
    # Mock is_available to say only "nmap" is available
    with patch.object(resolver, "is_available", side_effect=lambda name: name == "nmap"):
        ranked = resolver.find_tools_ranked("port_scanning")
        assert ranked == ["nmap"]
        assert "masscan" not in ranked
        assert "rustscan" not in ranked


def test_find_tools_ranked_unknown_capability(resolver):
    """Unknown capability returns empty list."""
    result = resolver.find_tools_ranked("quantum_hacking")
    assert result == []


def test_tool_chains_keys_exist():
    """All expected capability keys are defined in TOOL_CHAINS."""
    expected_keys = {
        "web_crawling",
        "directory_fuzzing",
        "port_scanning",
        "vulnerability_scanning",
        "sql_injection_testing",
        "web_fingerprinting",
        "waf_detection",
        "subdomain_discovery",
    }
    assert set(TOOL_CHAINS.keys()) == expected_keys

    # Each chain has at least one tool
    for capability, tools in TOOL_CHAINS.items():
        assert len(tools) >= 1, f"{capability} has no tools in chain"
