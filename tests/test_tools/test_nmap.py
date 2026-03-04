"""Unit tests for the nmap tool wrapper.

Tests parse_output() against a realistic fixture — no real nmap required.

Fixture: tests/fixtures/nmap_sample_output.xml
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.nmap import NmapTool

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "nmap_sample_output.xml"

SAMPLE_SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)

FIXTURE_SCOPE = EngagementScope(
    name="fixture-test",
    targets=[ScopeEntry(value="192.168.1.0/24", type=ScopeType.CIDR)],
)


def make_tool(scope: EngagementScope = SAMPLE_SCOPE) -> NmapTool:
    return NmapTool(scope=scope)


def load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    tool = make_tool()
    schema = tool.get_schema()
    assert schema["name"] == "nmap"
    assert "target" in schema["parameters"]["properties"]
    assert "target" in schema["parameters"]["required"]


# ---------------------------------------------------------------------------
# validate_input tests
# ---------------------------------------------------------------------------


def test_validate_input_checks_scope() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool.validate_input({"target": "8.8.8.8"})


def test_validate_input_accepts_in_scope() -> None:
    tool = make_tool()
    result = tool.validate_input({"target": "127.0.0.1"})
    assert result["target"] == "127.0.0.1"
    assert result["ports"] == "1-1000"  # default


def test_validate_input_rejects_out_of_cidr_scope() -> None:
    tool = make_tool(FIXTURE_SCOPE)
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool.validate_input({"target": "10.0.0.1"})


def test_validate_input_accepts_cidr_target() -> None:
    tool = make_tool(FIXTURE_SCOPE)
    result = tool.validate_input({"target": "192.168.1.100"})
    assert result["target"] == "192.168.1.100"


def test_validate_input_raises_on_missing_target() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="'target' is required"):
        tool.validate_input({})


# ---------------------------------------------------------------------------
# parse_output — edge cases
# ---------------------------------------------------------------------------


def test_parse_output_empty_string() -> None:
    tool = make_tool()
    output = tool.parse_output("")
    assert output.tool_name == "nmap"
    assert output.success is False
    assert output.hosts == []


def test_parse_output_whitespace_only() -> None:
    tool = make_tool()
    output = tool.parse_output("   \n  ")
    assert output.success is False


def test_parse_output_invalid_xml() -> None:
    tool = make_tool()
    output = tool.parse_output("<nmaprun><host>BROKEN")
    assert output.success is False
    assert "XML parse error" in output.error


# ---------------------------------------------------------------------------
# parse_output — fixture-based tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    """Parse the nmap fixture XML once for all fixture-based tests."""
    tool = make_tool(FIXTURE_SCOPE)
    xml = load_fixture()
    return tool.parse_output(xml)


def test_fixture_parse_succeeds(parsed) -> None:
    assert parsed.success is True
    assert parsed.error == ""


def test_fixture_host_count(parsed) -> None:
    assert len(parsed.hosts) == 1


def test_fixture_host_ip(parsed) -> None:
    assert parsed.hosts[0].ip == "192.168.1.100"


def test_fixture_host_is_alive(parsed) -> None:
    assert parsed.hosts[0].is_alive is True


def test_fixture_hostname_resolved(parsed) -> None:
    assert "webserver.example.com" in parsed.hosts[0].hostnames


def test_fixture_open_port_count(parsed) -> None:
    # Ports 22, 80, 443, 8080 — closed port 3306 must be excluded
    assert len(parsed.hosts[0].services) == 4


def test_fixture_open_ports_list(parsed) -> None:
    assert set(parsed.open_ports) == {22, 80, 443, 8080}


def test_fixture_port_22_ssh(parsed) -> None:
    host = parsed.hosts[0]
    ssh = next(s for s in host.services if s.port == 22)
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version.startswith("8.9")
    assert ssh.protocol.value == "tcp"
    assert "Ubuntu Linux" in ssh.extra_info


def test_fixture_port_80_nginx(parsed) -> None:
    host = parsed.hosts[0]
    http = next(s for s in host.services if s.port == 80)
    assert http.name == "http"
    assert http.product == "nginx"
    assert http.version == "1.24.0"


def test_fixture_port_443_nginx_ssl(parsed) -> None:
    host = parsed.hosts[0]
    https = next(s for s in host.services if s.port == 443)
    assert https.name == "ssl/http"
    assert https.product == "nginx"
    assert https.version == "1.24.0"


def test_fixture_port_8080_tomcat(parsed) -> None:
    host = parsed.hosts[0]
    tomcat = next(s for s in host.services if s.port == 8080)
    assert tomcat.product == "Apache Tomcat"
    assert tomcat.version == "9.0.70"


def test_fixture_closed_port_excluded(parsed) -> None:
    host = parsed.hosts[0]
    ports = [s.port for s in host.services]
    assert 3306 not in ports


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------


def test_fixture_os_family_linux(parsed) -> None:
    host = parsed.hosts[0]
    assert host.os == "Linux"


def test_fixture_os_version_highest_accuracy(parsed) -> None:
    # osmatch with accuracy=96 ("Linux 5.4 - 5.15") beats accuracy=94
    host = parsed.hosts[0]
    assert "Linux 5" in host.os_version


# ---------------------------------------------------------------------------
# NSE script output
# ---------------------------------------------------------------------------


def test_fixture_ssh_hostkey_script_captured(parsed) -> None:
    host = parsed.hosts[0]
    ssh = next(s for s in host.services if s.port == 22)
    assert "ssh-hostkey" in ssh.scripts
    assert "ECDSA" in ssh.scripts["ssh-hostkey"]


def test_fixture_ssh_auth_methods_captured(parsed) -> None:
    host = parsed.hosts[0]
    ssh = next(s for s in host.services if s.port == 22)
    assert "ssh-auth-methods" in ssh.scripts
    assert "publickey" in ssh.scripts["ssh-auth-methods"]


def test_fixture_http_title_port_80(parsed) -> None:
    host = parsed.hosts[0]
    http = next(s for s in host.services if s.port == 80)
    assert "http-title" in http.scripts
    assert "nginx" in http.scripts["http-title"]


def test_fixture_ssl_cert_script_captured(parsed) -> None:
    host = parsed.hosts[0]
    https = next(s for s in host.services if s.port == 443)
    assert "ssl-cert" in https.scripts
    assert "webserver.example.com" in https.scripts["ssl-cert"]


def test_fixture_tomcat_auth_finder_script(parsed) -> None:
    host = parsed.hosts[0]
    tomcat = next(s for s in host.services if s.port == 8080)
    assert "http-auth-finder" in tomcat.scripts
    assert "Tomcat Manager" in tomcat.scripts["http-auth-finder"]


def test_fixture_script_count_port_80(parsed) -> None:
    host = parsed.hosts[0]
    http = next(s for s in host.services if s.port == 80)
    # http-title, http-server-header, http-methods, http-robots.txt
    assert len(http.scripts) == 4
