"""Unit tests for the ffuf tool wrapper.

Tests parse_output() against a realistic JSON fixture — no real ffuf required.

Fixture: tests/fixtures/real_ffuf.json
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.ffuf import FfufTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "real_ffuf.json"

SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="172.20.0.0/24", type=ScopeType.CIDR)],
)

OUT_OF_SCOPE = EngagementScope(
    name="other",
    targets=[ScopeEntry(value="10.0.0.0/24", type=ScopeType.CIDR)],
)


def make_tool(scope: EngagementScope = SCOPE) -> FfufTool:
    return FfufTool(scope=scope)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    schema = make_tool().get_schema()
    assert schema["name"] == "ffuf"
    assert "url" in schema["parameters"]["properties"]
    assert "url" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_input_basic() -> None:
    result = make_tool().validate_input({"url": "http://172.20.0.2/FUZZ"})
    assert result["url"] == "http://172.20.0.2/FUZZ"
    assert result["filter_status"] == "404"
    assert result["threads"] == 40


def test_validate_input_requires_url() -> None:
    with pytest.raises(ValueError, match="'url' is required"):
        make_tool().validate_input({})


def test_validate_input_auto_inserts_fuzz_when_missing() -> None:
    """Regression: bare URLs must have /FUZZ appended so ffuf can run.

    The scan agent passes base URLs like http://host into the fuzz fallback
    chain; the wrapper must not reject them.
    """
    result = make_tool().validate_input({"url": "http://172.20.0.2"})
    assert "FUZZ" in result["url"]
    assert result["url"] == "http://172.20.0.2/FUZZ"


def test_validate_input_auto_inserts_fuzz_strips_trailing_slash() -> None:
    result = make_tool().validate_input({"url": "http://172.20.0.2/"})
    assert result["url"] == "http://172.20.0.2/FUZZ"


def test_validate_input_auto_inserts_fuzz_on_path() -> None:
    result = make_tool().validate_input({"url": "http://172.20.0.2/admin"})
    assert "FUZZ" in result["url"]
    assert result["url"] == "http://172.20.0.2/admin/FUZZ"


def test_validate_input_preserves_explicit_fuzz_placement() -> None:
    """Parameter fuzzing URLs with FUZZ in the query string must be untouched."""
    result = make_tool().validate_input({"url": "http://172.20.0.2/search?q=FUZZ"})
    assert result["url"] == "http://172.20.0.2/search?q=FUZZ"


def test_validate_input_checks_scope() -> None:
    with pytest.raises(ValueError, match="outside the engagement scope"):
        make_tool(OUT_OF_SCOPE).validate_input({"url": "http://172.20.0.2/FUZZ"})


# ---------------------------------------------------------------------------
# Cookies — authenticated fuzzing
# ---------------------------------------------------------------------------


def test_validate_input_accepts_cookies() -> None:
    """Cookies provided to validate_input are normalized into the args dict."""
    result = make_tool().validate_input(
        {"url": "http://172.20.0.2/FUZZ", "cookies": "PHPSESSID=abc123; security=low"}
    )
    assert result["cookies"] == "PHPSESSID=abc123; security=low"


def test_validate_input_cookies_default_empty() -> None:
    """When no cookies are passed, the args dict carries an empty string."""
    result = make_tool().validate_input({"url": "http://172.20.0.2/FUZZ"})
    assert result["cookies"] == ""


async def test_execute_injects_cookie_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cookies must be passed to ffuf via -H "Cookie: ..." identically to katana."""
    captured: dict[str, list[str]] = {}

    async def _fake_run_subprocess(self: FfufTool, cmd: list[str]) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        return ("{}", "", 0)

    monkeypatch.setattr(FfufTool, "_run_subprocess", _fake_run_subprocess)

    args = make_tool().validate_input(
        {"url": "http://172.20.0.2/FUZZ", "cookies": "PHPSESSID=abc123; security=low"}
    )
    await make_tool().execute(args)

    cmd = captured["cmd"]
    assert "-H" in cmd
    header_idx = cmd.index("-H")
    assert cmd[header_idx + 1] == "Cookie: PHPSESSID=abc123; security=low"


async def test_execute_omits_cookie_header_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """No -H Cookie flag should appear when cookies is empty."""
    captured: dict[str, list[str]] = {}

    async def _fake_run_subprocess(self: FfufTool, cmd: list[str]) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        return ("{}", "", 0)

    monkeypatch.setattr(FfufTool, "_run_subprocess", _fake_run_subprocess)

    args = make_tool().validate_input({"url": "http://172.20.0.2/FUZZ"})
    await make_tool().execute(args)

    cmd = captured["cmd"]
    # No Cookie header should be present
    assert not any("Cookie:" in part for part in cmd)


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


def test_parse_output_no_json() -> None:
    out = make_tool().parse_output("some banner text with no JSON")
    assert out.success is False
    assert "No JSON" in out.error


def test_parse_output_null_results() -> None:
    """ffuf may return null instead of [] when no results match."""
    raw = '{"commandline": "ffuf ...", "results": null, "config": {}}'
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert out.results == []


def test_parse_output_ansi_stripped() -> None:
    """ANSI escape codes from Docker exec should be stripped before parsing."""
    raw = '\x1b[0m{"commandline": "ffuf", "results": [{"url": "http://172.20.0.2/test", "status": 200, "length": 100, "words": 10, "lines": 5}]}\x1b[0m'  # noqa: E501
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1
    assert out.results[0].url == "http://172.20.0.2/test"


def test_parse_output_mixed_banner_and_json() -> None:
    """Banner text before JSON should be ignored."""
    raw = 'ffuf v2.1.0\n:: Progress: [100/100]\n{"commandline": "ffuf", "results": [{"url": "http://172.20.0.2/a", "status": 200, "length": 50, "words": 5, "lines": 2}]}'  # noqa: E501
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1


# ---------------------------------------------------------------------------
# parse_output — real fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return make_tool().parse_output(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.tool_name == "ffuf"


def test_fixture_result_count(parsed) -> None:
    assert len(parsed.results) == 6


def test_fixture_command_line(parsed) -> None:
    assert "ffuf" in parsed.command_line
    assert "172.20.0.2" in parsed.command_line


def test_fixture_result_urls(parsed) -> None:
    urls = [r.url for r in parsed.results]
    assert "http://172.20.0.2/admin" in urls
    assert "http://172.20.0.2/api" in urls
    assert "http://172.20.0.2/assets" in urls
    assert "http://172.20.0.2/ftp" in urls
    assert "http://172.20.0.2/profile" in urls
    assert "http://172.20.0.2/robots.txt" in urls


def test_fixture_status_codes(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://172.20.0.2/admin"].status == 301
    assert by_url["http://172.20.0.2/api"].status == 200
    assert by_url["http://172.20.0.2/ftp"].status == 200
    assert by_url["http://172.20.0.2/profile"].status == 500
    assert by_url["http://172.20.0.2/robots.txt"].status == 200


def test_fixture_content_lengths(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://172.20.0.2/admin"].length == 169
    assert by_url["http://172.20.0.2/api"].length == 3748
    assert by_url["http://172.20.0.2/robots.txt"].length == 28


def test_fixture_redirect_locations(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://172.20.0.2/admin"].redirect_location == "http://172.20.0.2/admin/"
    assert by_url["http://172.20.0.2/assets"].redirect_location == "http://172.20.0.2/assets/"
    assert by_url["http://172.20.0.2/api"].redirect_location == ""


def test_fixture_content_types(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert "application/json" in by_url["http://172.20.0.2/api"].content_type
    assert "text/plain" in by_url["http://172.20.0.2/robots.txt"].content_type


def test_fixture_input_data(parsed) -> None:
    by_url = {r.url: r for r in parsed.results}
    assert by_url["http://172.20.0.2/admin"].input_data == {"FUZZ": "admin"}
    assert by_url["http://172.20.0.2/robots.txt"].input_data == {"FUZZ": "robots.txt"}


def test_fixture_host(parsed) -> None:
    for r in parsed.results:
        assert r.host == "172.20.0.2"
