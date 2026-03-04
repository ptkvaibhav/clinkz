"""Unit tests for the Nikto tool wrapper.

Tests parse_output() against a realistic XML fixture — no real Nikto required.

Fixture: tests/fixtures/nikto_output.xml
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.nikto import NiktoTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "nikto_output.xml"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="192.168.1.100", type=ScopeType.IP)],
)

OUT_OF_SCOPE = EngagementScope(
    name="other",
    targets=[ScopeEntry(value="10.0.0.1", type=ScopeType.IP)],
)


def make_tool() -> NiktoTool:
    return NiktoTool(scope=SCOPE)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "nikto"
    assert "target" in schema["parameters"]["properties"]
    assert "target" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_accepts_in_scope() -> None:
    result = make_tool().validate_input({"target": "192.168.1.100"})
    assert result["target"] == "192.168.1.100"
    assert result["port"] == 80
    assert result["ssl"] is False


def test_validate_input_checks_scope() -> None:
    with pytest.raises(ValueError, match="outside the engagement scope"):
        make_tool().validate_input({"target": "10.0.0.1"})


def test_validate_input_requires_target() -> None:
    with pytest.raises(ValueError, match="'target' is required"):
        make_tool().validate_input({})


def test_validate_input_ssl_and_port() -> None:
    result = make_tool().validate_input({"target": "192.168.1.100", "port": 443, "ssl": True})
    assert result["port"] == 443
    assert result["ssl"] is True


# ---------------------------------------------------------------------------
# parse_output — edge cases
# ---------------------------------------------------------------------------


def test_parse_output_empty() -> None:
    out = make_tool().parse_output("")
    assert out.success is False
    assert out.findings == []


def test_parse_output_whitespace_only() -> None:
    out = make_tool().parse_output("  \n  ")
    assert out.success is False


def test_parse_output_invalid_xml() -> None:
    out = make_tool().parse_output("<niktoscan><BROKEN")
    assert out.success is False
    assert "XML parse error" in out.error


def test_parse_output_item_without_description_skipped() -> None:
    raw = """<?xml version="1.0" ?>
<niktoscan>
  <niktoscandetails>
    <item id="1" method="GET"><uri>/</uri></item>
    <item id="2" method="GET"><description>Real finding</description><uri>/x</uri></item>
  </niktoscandetails>
</niktoscan>"""
    out = make_tool().parse_output(raw)
    assert len(out.findings) == 1
    assert out.findings[0].id == "2"


# ---------------------------------------------------------------------------
# parse_output — fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "nikto"


def test_fixture_finding_count(parsed) -> None:
    assert len(parsed.findings) == 6


def test_fixture_finding_ids(parsed) -> None:
    ids = {f.id for f in parsed.findings}
    assert "999103" in ids
    assert "999986" in ids
    assert "999957" in ids
    assert "600328" in ids
    assert "601009" in ids
    assert "400148" in ids


def test_fixture_xframe_finding(parsed) -> None:
    f = next(x for x in parsed.findings if x.id == "999103")
    assert "X-Frame-Options" in f.description
    assert f.uri == "/"
    assert f.method == "GET"


def test_fixture_xss_protection_finding(parsed) -> None:
    f = next(x for x in parsed.findings if x.id == "999986")
    assert "X-XSS-Protection" in f.description
    assert f.uri == "/"


def test_fixture_phpinfo_finding(parsed) -> None:
    f = next(x for x in parsed.findings if x.id == "600328")
    assert "phpinfo" in f.description.lower()
    assert f.uri == "/phpinfo.php"
    assert f.method == "GET"


def test_fixture_admin_finding(parsed) -> None:
    f = next(x for x in parsed.findings if x.id == "601009")
    assert "admin" in f.description.lower()
    assert f.uri == "/admin/"


def test_fixture_put_method_finding(parsed) -> None:
    f = next(x for x in parsed.findings if x.id == "400148")
    assert "PUT" in f.description
    assert f.uri == "/upload/"
    assert f.method == "PUT"


def test_fixture_all_findings_have_descriptions(parsed) -> None:
    assert all(f.description for f in parsed.findings)
