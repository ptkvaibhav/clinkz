"""Unit tests for the subfinder tool wrapper.

Tests parse_output() against a realistic fixture — no real subfinder required.

Fixture: tests/fixtures/subfinder_output.txt
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.subfinder import SubfinderTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "subfinder_output.txt"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

OUT_OF_SCOPE = EngagementScope(
    name="other",
    targets=[ScopeEntry(value="other.com", type=ScopeType.DOMAIN)],
)


def make_tool(scope: EngagementScope = SCOPE) -> SubfinderTool:
    return SubfinderTool(scope=scope)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "subfinder"
    assert "domain" in schema["parameters"]["properties"]
    assert "domain" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_accepts_in_scope() -> None:
    result = make_tool().validate_input({"domain": "example.com"})
    assert result["domain"] == "example.com"
    assert result["all_sources"] is False


def test_validate_input_checks_scope() -> None:
    with pytest.raises(ValueError, match="outside the engagement scope"):
        make_tool(OUT_OF_SCOPE).validate_input({"domain": "example.com"})


def test_validate_input_requires_domain() -> None:
    with pytest.raises(ValueError, match="'domain' is required"):
        make_tool().validate_input({})


def test_validate_input_all_sources_flag() -> None:
    result = make_tool().validate_input({"domain": "example.com", "all_sources": True})
    assert result["all_sources"] is True


# ---------------------------------------------------------------------------
# parse_output — edge cases
# ---------------------------------------------------------------------------


def test_parse_output_empty() -> None:
    out = make_tool().parse_output("")
    assert out.success is False
    assert out.subdomains == []


def test_parse_output_whitespace_only() -> None:
    out = make_tool().parse_output("   \n\n  ")
    assert out.success is False
    assert out.subdomains == []


def test_parse_output_blank_lines_filtered() -> None:
    raw = "api.example.com\n\nwww.example.com\n  \nblog.example.com\n"
    out = make_tool().parse_output(raw)
    assert "" not in out.subdomains
    assert len(out.subdomains) == 3


def test_parse_output_deduplicates() -> None:
    raw = "api.example.com\napi.example.com\nwww.example.com\n"
    out = make_tool().parse_output(raw)
    assert out.subdomains.count("api.example.com") == 1


def test_parse_output_strips_trailing_whitespace() -> None:
    raw = "api.example.com   \n  www.example.com\n"
    out = make_tool().parse_output(raw)
    assert "api.example.com" in out.subdomains
    assert "www.example.com" in out.subdomains


# ---------------------------------------------------------------------------
# parse_output — fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "subfinder"


def test_fixture_subdomain_count(parsed) -> None:
    assert len(parsed.subdomains) == 12


def test_fixture_contains_specific_subdomains(parsed) -> None:
    expected = {"api.example.com", "www.example.com", "mail.example.com",
                "dev.example.com", "staging.example.com", "admin.example.com"}
    assert expected.issubset(set(parsed.subdomains))


def test_fixture_subdomains_sorted(parsed) -> None:
    assert parsed.subdomains == sorted(parsed.subdomains)


def test_fixture_no_empty_entries(parsed) -> None:
    assert all(s for s in parsed.subdomains)
