"""Unit tests for the WhatWeb tool wrapper.

Tests parse_output() against a realistic JSON fixture — no real WhatWeb required.

Fixture: tests/fixtures/whatweb_output.json
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.whatweb import WhatWebTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "whatweb_output.json"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


def make_tool() -> WhatWebTool:
    return WhatWebTool(scope=SCOPE)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "whatweb"
    assert "target" in schema["parameters"]["properties"]
    assert "target" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_accepts_in_scope() -> None:
    result = make_tool().validate_input({"target": "example.com"})
    assert result["target"] == "example.com"
    assert result["aggression"] == 1


def test_validate_input_checks_scope() -> None:
    from pytest import raises
    with raises(ValueError, match="outside the engagement scope"):
        make_tool().validate_input({"target": "other.com"})


def test_validate_input_requires_target() -> None:
    with pytest.raises(ValueError, match="'target' is required"):
        make_tool().validate_input({})


def test_validate_input_aggression_range() -> None:
    with pytest.raises(ValueError, match="aggression must be between"):
        make_tool().validate_input({"target": "example.com", "aggression": 5})


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


def test_parse_output_invalid_json() -> None:
    out = make_tool().parse_output("{not valid json")
    assert out.success is False
    assert "JSON parse error" in out.error


def test_parse_output_single_object_normalised() -> None:
    """A bare JSON object (not array) is accepted."""
    raw = '{"target":"http://x/","http_status":200,"plugins":{"nginx":{"version":["1.24"]}}}'
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1


# ---------------------------------------------------------------------------
# parse_output — fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "whatweb"


def test_fixture_result_count(parsed) -> None:
    assert len(parsed.results) == 3


def test_fixture_result_targets(parsed) -> None:
    targets = [r.target for r in parsed.results]
    assert "http://192.168.1.100/" in targets
    assert "http://192.168.1.100:8080/" in targets
    assert "https://192.168.1.100/" in targets


def test_fixture_http_statuses(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    assert by_target["http://192.168.1.100/"].http_status == 200
    assert by_target["http://192.168.1.100:8080/"].http_status == 200


def test_fixture_nginx_technologies(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    nginx_result = by_target["http://192.168.1.100/"]
    assert "nginx" in nginx_result.technologies
    assert "HTTPServer" in nginx_result.technologies
    assert "Title" in nginx_result.technologies


def test_fixture_nginx_version(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    nginx_result = by_target["http://192.168.1.100/"]
    assert nginx_result.versions.get("nginx") == "1.24.0"


def test_fixture_nginx_server_header(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    assert by_target["http://192.168.1.100/"].server == "nginx/1.24.0"


def test_fixture_tomcat_technologies(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    tomcat_result = by_target["http://192.168.1.100:8080/"]
    assert "Apache-Tomcat" in tomcat_result.technologies
    assert "Java" in tomcat_result.technologies


def test_fixture_tomcat_version(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    assert by_target["http://192.168.1.100:8080/"].versions.get("Apache-Tomcat") == "9.0.70"


def test_fixture_tomcat_server_header(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    assert by_target["http://192.168.1.100:8080/"].server == "Apache-Coyote/1.1"


def test_fixture_https_frameworks(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    https_result = by_target["https://192.168.1.100/"]
    assert "Bootstrap" in https_result.technologies
    assert "jQuery" in https_result.technologies
    assert https_result.versions.get("Bootstrap") == "5.3.0"
    assert https_result.versions.get("jQuery") == "3.7.1"


def test_fixture_technologies_map(parsed) -> None:
    """The flat technologies dict (url -> list) is also populated."""
    assert "http://192.168.1.100/" in parsed.technologies
    assert "nginx" in parsed.technologies["http://192.168.1.100/"]
