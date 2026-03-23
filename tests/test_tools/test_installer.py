"""Unit tests for the tool installer wrapper."""

from __future__ import annotations

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.installer import ToolInstallerTool

SAMPLE_SCOPE = EngagementScope(
    name="test",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)


def make_tool() -> ToolInstallerTool:
    return ToolInstallerTool(scope=SAMPLE_SCOPE)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_has_required_fields() -> None:
    tool = make_tool()
    schema = tool.get_schema()
    assert schema["name"] == "tool_installer"
    assert "tool_name" in schema["parameters"]["properties"]
    assert "install_method" in schema["parameters"]["properties"]
    assert set(schema["parameters"]["required"]) == {"tool_name", "install_method"}


def test_capabilities() -> None:
    tool = make_tool()
    assert "tool_installation" in tool.capabilities
    assert "tool_setup" in tool.capabilities
    assert tool.category == "utility"


# ---------------------------------------------------------------------------
# validate_input
# ---------------------------------------------------------------------------


def test_validate_apt_package() -> None:
    tool = make_tool()
    result = tool.validate_input({"tool_name": "gobuster", "install_method": "apt"})
    assert result["tool_name"] == "gobuster"
    assert result["install_method"] == "apt"


def test_validate_pip_package() -> None:
    tool = make_tool()
    result = tool.validate_input({"tool_name": "dirsearch", "install_method": "pip"})
    assert result["install_method"] == "pip"


def test_validate_go_install() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "tool_name": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
            "install_method": "go",
        }
    )
    assert result["install_method"] == "go"


def test_validate_git_clone() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "tool_name": "https://github.com/some/tool",
            "install_method": "git",
        }
    )
    assert result["install_method"] == "git"


def test_validate_download() -> None:
    tool = make_tool()
    result = tool.validate_input(
        {
            "tool_name": "https://releases.example.com/tool-linux-amd64",
            "install_method": "download",
        }
    )
    assert result["install_method"] == "download"


def test_validate_empty_tool_name_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="'tool_name' is required"):
        tool.validate_input({"tool_name": "", "install_method": "apt"})


def test_validate_invalid_method_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="Invalid install_method"):
        tool.validate_input({"tool_name": "nmap", "install_method": "yum"})


def test_validate_shell_injection_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="dangerous characters"):
        tool.validate_input({"tool_name": "nmap; rm -rf /", "install_method": "apt"})


def test_validate_backtick_injection_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="dangerous characters"):
        tool.validate_input({"tool_name": "nmap`whoami`", "install_method": "apt"})


def test_validate_pipe_injection_rejects() -> None:
    tool = make_tool()
    with pytest.raises(ValueError, match="dangerous characters"):
        tool.validate_input({"tool_name": "nmap | cat /etc/passwd", "install_method": "apt"})


# ---------------------------------------------------------------------------
# parse_output
# ---------------------------------------------------------------------------


def test_parse_output_success() -> None:
    tool = make_tool()
    raw = "$ apt-get install -y gobuster\nDone.\nSUCCESS: gobuster installed via apt"
    output = tool.parse_output(raw)
    assert output.success is True
    assert output.install_log == raw


def test_parse_output_failure() -> None:
    tool = make_tool()
    raw = "$ apt-get install -y nonexistent\nE: Unable to locate package\nEXIT CODE: 1"
    output = tool.parse_output(raw)
    assert output.success is False
    assert "EXIT CODE" in output.error


def test_parse_output_empty() -> None:
    tool = make_tool()
    output = tool.parse_output("")
    assert output.success is False
