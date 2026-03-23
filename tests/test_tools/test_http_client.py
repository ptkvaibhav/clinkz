"""Unit tests for the HTTP client tool wrapper."""

from __future__ import annotations

import json

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.http_client import HTTPClientTool

SAMPLE_SCOPE = EngagementScope(
    name="test",
    targets=[
        ScopeEntry(value="example.com", type=ScopeType.DOMAIN),
        ScopeEntry(value="192.168.1.0/24", type=ScopeType.CIDR),
    ],
)


def make_tool() -> HTTPClientTool:
    return HTTPClientTool(scope=SAMPLE_SCOPE)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    tool = make_tool()
    schema = tool.get_schema()
    assert schema["name"] == "http_client"
    assert "url" in schema["parameters"]["properties"]
    assert "url" in schema["parameters"]["required"]


def test_capabilities() -> None:
    tool = make_tool()
    assert "http_request" in tool.capabilities
    assert "authentication_testing" in tool.capabilities
    assert tool.category == "utility"


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_in_scope_url() -> None:
    tool = make_tool()
    result = tool.validate_input({"url": "http://example.com/login"})
    assert result["url"] == "http://example.com/login"
    assert result["method"] == "GET"


def test_validate_in_scope_ip_url() -> None:
    tool = make_tool()
    result = tool.validate_input({"url": "http://192.168.1.50:8080/api"})
    assert result["url"] == "http://192.168.1.50:8080/api"


def test_validate_out_of_scope_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool.validate_input({"url": "http://evil.com/hack"})


def test_validate_empty_url_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="'url' is required"):
        tool.validate_input({"url": ""})


def test_validate_invalid_url_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="Invalid URL"):
        tool.validate_input({"url": "not-a-url"})


def test_validate_invalid_method_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="Invalid HTTP method"):
        tool.validate_input({"url": "http://example.com", "method": "HACK"})


def test_validate_post_with_body() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "url": "http://example.com/login",
            "method": "POST",
            "body": "username=admin&password=password",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        }
    )
    assert result["method"] == "POST"
    assert result["body"] == "username=admin&password=password"
    assert result["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_validate_with_cookies() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "url": "http://example.com/dashboard",
            "cookies": {"session": "abc123"},
        }
    )
    assert result["cookies"] == {"session": "abc123"}


def test_validate_follow_redirects() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "url": "http://example.com",
            "follow_redirects": True,
        }
    )
    assert result["follow_redirects"] is True


# ---------------------------------------------------------------------------
# parse_output
# ---------------------------------------------------------------------------


def test_parse_output_success() -> None:
    tool = make_tool()
    raw = json.dumps(
        {
            "status_code": 200,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": "<html>OK</html>",
            "redirect_chain": [],
            "response_time_ms": 42.5,
            "raw": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>OK</html>",
        }
    )
    output = tool.parse_output(raw)
    assert output.success is True
    assert output.status_code == 200
    assert output.response_body == "<html>OK</html>"
    assert output.response_time_ms == 42.5


def test_parse_output_with_redirects() -> None:
    tool = make_tool()
    raw = json.dumps(
        {
            "status_code": 200,
            "response_headers": {},
            "response_body": "final",
            "redirect_chain": ["http://example.com/old", "http://example.com/new"],
            "response_time_ms": 100.0,
            "raw": "",
        }
    )
    output = tool.parse_output(raw)
    assert len(output.redirect_chain) == 2


def test_parse_output_error() -> None:
    tool = make_tool()
    raw = json.dumps(
        {
            "status_code": 0,
            "response_headers": {},
            "response_body": "",
            "redirect_chain": [],
            "response_time_ms": 5.0,
            "error": "Connection refused",
        }
    )
    output = tool.parse_output(raw)
    assert output.success is False
    assert "Connection refused" in output.error


def test_parse_output_empty() -> None:
    tool = make_tool()
    output = tool.parse_output("")
    assert output.success is False
    assert output.error == "Empty response"


def test_parse_output_invalid_json() -> None:
    tool = make_tool()
    output = tool.parse_output("not json at all")
    assert output.success is False
    assert "JSON parse error" in output.error
