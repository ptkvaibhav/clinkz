"""Unit tests for the HTTP client tool wrapper."""

from __future__ import annotations

import json

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.http_client import HTTPClientOutput, HTTPClientTool

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


# ===========================================================================
# The peer address — who did this request actually reach?
# ===========================================================================
#
# A URL string names a host; whether two host spellings are one server is a fact
# about RESOLUTION, and this client is the only code that observed it. Consumed
# by ``OriginIdentity`` so a target reachable by hostname and by address emits
# one finding per issue instead of two.


_OLD_RECORDING = (
    'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"a":1}\n__CURL_TIMING__0.123\n'
)
_NEW_RECORDING = (
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
    '{"a":1}\n__CURL_REMOTE__172.20.0.2\n__CURL_TIMING__0.123\n'
)


def test_a_recording_made_before_the_marker_parses_identically() -> None:
    """The replay corpus re-parses recorded bytes, so this must not drift.

    The marker is prepended rather than appended for exactly this reason: the
    timing regex is anchored at end-of-output, and every stdout on disk was
    written with timing last. An appended marker would have stopped those
    recordings' timing from being stripped and landed it in the body, drifting
    ``body_len`` and ``body_sha`` across the whole baseline.
    """
    parsed = json.loads(make_tool()._parse_curl_output(_OLD_RECORDING, 0.0))
    assert parsed["response_body"] == '{"a":1}\n'
    assert parsed["resolved_address"] == ""
    assert parsed["status_code"] == 200


def test_the_address_is_captured_and_kept_out_of_the_body() -> None:
    parsed = json.loads(make_tool()._parse_curl_output(_NEW_RECORDING, 0.0))
    assert parsed["resolved_address"] == "172.20.0.2"
    assert parsed["response_body"] == '{"a":1}\n', "the marker is not body"
    assert parsed["status_code"] == 200


def test_a_curl_that_never_connected_reports_no_address() -> None:
    """``%{remote_ip}`` is empty when there was no connection."""
    raw = "HTTP/1.1 000 \r\n\r\n\n__CURL_REMOTE__\n__CURL_TIMING__0.001\n"
    parsed = json.loads(make_tool()._parse_curl_output(raw, 0.0))
    assert parsed["resolved_address"] == ""


def test_the_address_reaches_the_output_model() -> None:
    tool = make_tool()
    envelope = tool._parse_curl_output(_NEW_RECORDING, 0.0)
    assert tool.parse_output(envelope).resolved_address == "172.20.0.2"


def test_the_model_defaults_to_no_address() -> None:
    """The aiohttp path reports none, and absence must merge nothing."""
    assert HTTPClientOutput(tool_name="http_client", success=True).resolved_address == ""
