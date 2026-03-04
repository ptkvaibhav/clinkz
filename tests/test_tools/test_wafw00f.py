"""Unit tests for the wafw00f tool wrapper.

Tests parse_output() against a realistic text fixture — no real wafw00f required.

Fixture: tests/fixtures/wafw00f_output.txt
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.wafw00f import Wafw00fTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "wafw00f_output.txt"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


def make_tool() -> Wafw00fTool:
    return Wafw00fTool(scope=SCOPE)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "wafw00f"
    assert "target" in schema["parameters"]["properties"]
    assert "target" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_accepts_in_scope() -> None:
    result = make_tool().validate_input({"target": "example.com"})
    assert result["target"] == "example.com"


def test_validate_input_checks_scope() -> None:
    with pytest.raises(ValueError, match="outside the engagement scope"):
        make_tool().validate_input({"target": "other.com"})


def test_validate_input_requires_target() -> None:
    with pytest.raises(ValueError, match="'target' is required"):
        make_tool().validate_input({})


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


def test_parse_output_no_waf_only() -> None:
    raw = "[*] Checking https://clean.example.com\n[-] No WAF detected by the simple tests\n"
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1
    assert out.results[0].waf_detected is False
    assert out.results[0].target == "https://clean.example.com"


def test_parse_output_waf_without_manufacturer() -> None:
    raw = "[*] Checking https://x.com\n[+] The site https://x.com is behind SomeWAF WAF.\n"
    out = make_tool().parse_output(raw)
    assert out.results[0].waf_name == "SomeWAF"
    assert out.results[0].manufacturer == ""


def test_parse_output_deduplicates_targets() -> None:
    """Same target appearing twice should produce only one result."""
    raw = (
        "[*] Checking https://x.com\n"
        "[+] The site https://x.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
        "[*] Checking https://x.com\n"
        "[+] The site https://x.com is behind Cloudflare (Cloudflare Inc.) WAF.\n"
    )
    out = make_tool().parse_output(raw)
    assert len(out.results) == 1


# ---------------------------------------------------------------------------
# parse_output — fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "wafw00f"


def test_fixture_result_count(parsed) -> None:
    # shop → Cloudflare, api → AWS WAF, blog → no WAF
    assert len(parsed.results) == 3


def test_fixture_cloudflare_detected(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    cf = by_target["https://shop.example.com"]
    assert cf.waf_detected is True
    assert cf.waf_name == "Cloudflare"
    assert cf.manufacturer == "Cloudflare Inc."


def test_fixture_aws_waf_detected(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    aws = by_target["https://api.example.com"]
    assert aws.waf_detected is True
    assert aws.waf_name == "AWS WAF"
    assert aws.manufacturer == "Amazon"


def test_fixture_no_waf_for_blog(parsed) -> None:
    by_target = {r.target: r for r in parsed.results}
    blog = by_target["https://blog.example.com"]
    assert blog.waf_detected is False
    assert blog.waf_name == ""
    assert blog.manufacturer == ""
