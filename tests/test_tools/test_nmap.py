"""Unit tests for the nmap tool wrapper.

Tests parse_output() against fixture data — no real nmap required.

Fixtures: tests/fixtures/nmap_output.xml (create from a real nmap run)
"""

from __future__ import annotations

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.nmap import NmapTool

SAMPLE_SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)


def make_tool() -> NmapTool:
    return NmapTool(scope=SAMPLE_SCOPE)


def test_schema_has_required_fields() -> None:
    tool = make_tool()
    schema = tool.get_schema()
    assert schema["name"] == "nmap"
    assert "target" in schema["parameters"]["properties"]
    assert "target" in schema["parameters"]["required"]


def test_validate_input_checks_scope() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool.validate_input({"target": "8.8.8.8"})


def test_validate_input_accepts_in_scope() -> None:
    tool = make_tool()
    result = tool.validate_input({"target": "127.0.0.1"})
    assert result["target"] == "127.0.0.1"
    assert result["ports"] == "1-1000"  # default


def test_parse_output_empty() -> None:
    tool = make_tool()
    output = tool.parse_output("")
    assert output.tool_name == "nmap"
    assert output.success is False
    assert output.hosts == []


# TODO: add test_parse_output_with_fixture() once nmap XML fixture is available
