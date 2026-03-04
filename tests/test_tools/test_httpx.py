"""Unit tests for the httpx tool wrapper.

Tests parse_output() against a realistic JSONL fixture — no real httpx required.

Fixture: tests/fixtures/httpx_output.jsonl
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.httpx_tool import HttpxTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "httpx_output.jsonl"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="192.168.1.0/24", type=ScopeType.CIDR)],
)

OUT_OF_SCOPE = EngagementScope(
    name="other",
    targets=[ScopeEntry(value="10.0.0.0/24", type=ScopeType.CIDR)],
)


def make_tool(scope: EngagementScope = SCOPE) -> HttpxTool:
    return HttpxTool(scope=scope)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "httpx"
    assert "targets" in schema["parameters"]["properties"]
    assert "targets" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_accepts_in_scope() -> None:
    result = make_tool().validate_input({"targets": ["192.168.1.100"]})
    assert result["targets"] == ["192.168.1.100"]
    assert result["follow_redirects"] is True


def test_validate_input_checks_scope() -> None:
    with pytest.raises(ValueError, match="outside the engagement scope"):
        make_tool(OUT_OF_SCOPE).validate_input({"targets": ["192.168.1.100"]})


def test_validate_input_requires_targets() -> None:
    with pytest.raises(ValueError, match="'targets' list is required"):
        make_tool().validate_input({})


def test_validate_input_empty_targets_list() -> None:
    with pytest.raises(ValueError, match="'targets' list is required"):
        make_tool().validate_input({"targets": []})


# ---------------------------------------------------------------------------
# parse_output — edge cases
# ---------------------------------------------------------------------------


def test_parse_output_empty() -> None:
    out = make_tool().parse_output("")
    assert out.success is False
    assert out.results == []


def test_parse_output_whitespace_only() -> None:
    out = make_tool().parse_output("  \n  ")
    assert out.success is False


def test_parse_output_invalid_json_lines_skipped() -> None:
    raw = '{"url":"http://host","status-code":200,"technologies":[]}\nnot-json\n'
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1


def test_parse_output_legacy_tech_key() -> None:
    """Older httpx versions used 'tech' instead of 'technologies'."""
    raw = '{"url":"http://host","status-code":200,"tech":["nginx"]}\n'
    out = make_tool().parse_output(raw)
    assert out.results[0].tech == ["nginx"]


def test_parse_output_legacy_underscore_keys() -> None:
    """Also accept underscore variants (status_code, content_length)."""
    raw = '{"url":"http://host","status_code":301,"content_length":42}\n'
    out = make_tool().parse_output(raw)
    assert out.results[0].status_code == 301
    assert out.results[0].content_length == 42


# ---------------------------------------------------------------------------
# parse_output — fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "httpx"


def test_fixture_result_count(parsed) -> None:
    # 4 valid JSON lines + 1 invalid line that is silently skipped
    assert len(parsed.results) == 4


def test_fixture_result_urls(parsed) -> None:
    urls = [r.url for r in parsed.results]
    assert "http://192.168.1.100" in urls
    assert "https://192.168.1.100" in urls
    assert "http://192.168.1.100:8080" in urls
    assert "http://192.168.1.100/admin" in urls


def test_fixture_status_codes(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://192.168.1.100"].status_code == 200
    assert by_url["https://192.168.1.100"].status_code == 200
    assert by_url["http://192.168.1.100:8080"].status_code == 200
    assert by_url["http://192.168.1.100/admin"].status_code == 403


def test_fixture_titles(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://192.168.1.100"].title == "Welcome to nginx!"
    assert by_url["http://192.168.1.100:8080"].title == "Apache Tomcat/9.0.70"
    assert by_url["http://192.168.1.100/admin"].title == ""


def test_fixture_technologies(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert "Nginx" in by_url["http://192.168.1.100"].tech
    assert "Bootstrap" in by_url["https://192.168.1.100"].tech
    assert "Apache Tomcat" in by_url["http://192.168.1.100:8080"].tech
    assert "Java" in by_url["http://192.168.1.100:8080"].tech


def test_fixture_content_lengths(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://192.168.1.100"].content_length == 615
    assert by_url["https://192.168.1.100"].content_length == 2048
    assert by_url["http://192.168.1.100:8080"].content_length == 11356


def test_fixture_webservers(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://192.168.1.100"].webserver == "nginx/1.24.0"
    assert by_url["http://192.168.1.100:8080"].webserver == "Apache-Coyote/1.1"
