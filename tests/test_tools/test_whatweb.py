"""Unit tests for the WhatWeb tool wrapper.

Two fixtures, and the difference between them is the whole point:

* ``whatweb_output.json`` — a hand-authored clean JSON array. Every test here
  passed against it for the life of this wrapper.
* ``whatweb_output_interleaved.txt`` — the bytes whatweb ACTUALLY writes,
  lifted from a recorded ``tool_invocations/`` record of a real DVWA run (the
  engagement's live ``PHPSESSID`` scrubbed before it was committed). The brief
  human-readable log shares stdout with the JSON log, so the blob is not valid
  JSON, ``json.loads`` raised, and 100% of a successful fingerprint —
  Apache 2.4.67, PHP 8.5.6 — was discarded on every run. The clean fixture
  could not have caught it: it tested the shape we assumed, not the shape the
  tool emits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.whatweb import WhatWebTool

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "whatweb_output.json"
INTERLEAVED_PATH = Path(__file__).parent.parent / "fixtures" / "whatweb_output_interleaved.txt"

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


# ---------------------------------------------------------------------------
# parse_output — the bytes whatweb really writes (D1)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_output() -> str:
    return INTERLEAVED_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def interleaved(real_output: str):
    return make_tool().parse_output(real_output)


def test_the_real_output_is_not_valid_json_as_a_whole(real_output: str) -> None:
    """The negative control: without this, the test below proves nothing.

    If whatweb ever stops interleaving, this fails and the fallback path
    becomes dead code that nobody noticed had stopped being exercised.
    """
    import json

    with pytest.raises(json.JSONDecodeError):
        json.loads(real_output)


def test_interleaved_output_parses(interleaved) -> None:
    assert interleaved.success is True
    assert len(interleaved.results) == 2


def test_interleaved_output_recovers_the_versioned_components(interleaved) -> None:
    """The half that matters: a version is what the CVE path matches against."""
    components = {(c.name, c.version) for c in interleaved.detected_components()}
    assert ("Apache", "2.4.67") in components
    assert ("PHP", "8.5.6") in components


def test_interleaved_output_keeps_per_url_attribution(interleaved) -> None:
    by_target = {r.target: r for r in interleaved.results}
    assert set(by_target) == {"http://clinkz-dvwa/", "http://clinkz-dvwa/login.php"}
    assert by_target["http://clinkz-dvwa/"].http_status == 302
    assert by_target["http://clinkz-dvwa/login.php"].http_status == 200
    assert by_target["http://clinkz-dvwa/"].server == "Apache/2.4.67 (Debian)"


def test_brief_lines_do_not_become_scan_results(interleaved) -> None:
    """A brief line is prose, not a result — it must not enter the inventory."""
    assert all(r.target.startswith("http") for r in interleaved.results)
    assert all(r.technologies for r in interleaved.results)


def test_clean_array_still_takes_the_whole_blob_path(parsed) -> None:
    """The fast path is unchanged for output that is valid JSON."""
    assert parsed.success is True
    assert len(parsed.results) == 3


def test_ndjson_shape_is_recovered_too() -> None:
    """One object per line, no array — the other way tools emit JSON logs."""
    raw = (
        '{"target":"http://a/","http_status":200,"plugins":{"nginx":{"version":["1.24"]}}}\n'
        '{"target":"http://b/","http_status":404,"plugins":{"Apache":{"version":["2.4"]}}}\n'
    )
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert [r.target for r in out.results] == ["http://a/", "http://b/"]


def test_a_brace_inside_a_quoted_value_does_not_split_an_object() -> None:
    """String state is tracked, so a plugin string carrying braces is safe."""
    raw = (
        "noise before\n"
        '{"target":"http://a/","http_status":200,'
        '"plugins":{"Title":{"string":["a } brace \\" and a quote"]}}}\n'
        "noise after\n"
    )
    out = make_tool().parse_output(raw)
    assert out.success is True
    assert len(out.results) == 1
    assert out.results[0].technologies == ["Title"]


def test_output_with_no_recoverable_object_still_reports_the_parse_error() -> None:
    out = make_tool().parse_output("http://x/ [200 OK] Apache[2.4.67], PHP[8.5.6]\n")
    assert out.success is False
    assert "JSON parse error" in out.error
