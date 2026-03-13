"""Tool Installer — lets agents install tools they discover at runtime.

Safety: ALL installations happen inside the Docker container, never on
the host. If TOOL_EXEC_MODE is not 'docker', the tool refuses to run.
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput

logger = logging.getLogger(__name__)

# Allowed install methods and their command templates.
# {tool} is replaced with the tool_name argument.
_INSTALL_COMMANDS: dict[str, list[list[str]]] = {
    "apt": [
        ["apt-get", "update", "-qq"],
        ["apt-get", "install", "-y", "-qq", "{tool}"],
    ],
    "pip": [
        ["pip", "install", "--quiet", "{tool}"],
    ],
    "go": [
        ["go", "install", "{tool}@latest"],
    ],
    "git": [
        ["git", "clone", "--depth=1", "{tool}", "/opt/{tool_basename}"],
    ],
    "download": [
        ["wget", "-q", "-O", "/usr/local/bin/{tool_basename}", "{tool}"],
        ["chmod", "+x", "/usr/local/bin/{tool_basename}"],
    ],
}


class ToolInstallerOutput(ToolOutput):
    """Structured output from a tool installation."""

    install_method: str = ""
    installed_tool: str = ""
    install_log: str = ""


class ToolInstallerTool(ToolBase):
    """Install tools inside the Docker container at runtime.

    Agents use this when the ToolResolver reports a needed capability
    is unavailable. The tool is installed inside the security-tools
    Docker container and then registered with the ToolResolver.
    """

    capabilities = ["tool_installation", "tool_setup"]
    category = "utility"

    @property
    def name(self) -> str:
        return "tool_installer"

    @property
    def description(self) -> str:
        return "Install a security tool inside the Docker container."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": (
                            "Name or URL of the tool to install. "
                            "For apt: package name. For pip: package name. "
                            "For go: full module path. For git: repo URL. "
                            "For download: direct URL to binary."
                        ),
                    },
                    "install_method": {
                        "type": "string",
                        "enum": ["apt", "pip", "go", "git", "download"],
                        "description": "Installation method to use.",
                    },
                },
                "required": ["tool_name", "install_method"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        tool_name = args.get("tool_name", "").strip()
        if not tool_name:
            raise ValueError("'tool_name' is required for tool_installer")

        install_method = args.get("install_method", "").strip().lower()
        if install_method not in _INSTALL_COMMANDS:
            raise ValueError(
                f"Invalid install_method: '{install_method}'. "
                f"Must be one of: {', '.join(_INSTALL_COMMANDS.keys())}"
            )

        # Reject shell metacharacters to prevent command injection
        dangerous_chars = set(";|&$`\\'\"\n\r")
        if any(c in tool_name for c in dangerous_chars):
            raise ValueError(
                f"tool_name contains dangerous characters: {tool_name!r}"
            )

        return {"tool_name": tool_name, "install_method": install_method}

    async def execute(self, args: dict[str, Any]) -> str:
        """Install the tool inside Docker and return combined output."""
        from clinkz.config import settings

        if settings.tool_exec_mode != "docker":
            return (
                "ERROR: Tool installation is only allowed inside the Docker "
                "container. Set TOOL_EXEC_MODE=docker to enable."
            )

        tool_name = args["tool_name"]
        install_method = args["install_method"]
        tool_basename = tool_name.rstrip("/").rsplit("/", 1)[-1]

        templates = _INSTALL_COMMANDS[install_method]
        output_parts: list[str] = []

        for template in templates:
            cmd = [
                part.replace("{tool}", tool_name).replace("{tool_basename}", tool_basename)
                for part in template
            ]
            stdout, stderr, rc = await self._run_subprocess(cmd)
            output_parts.append(f"$ {' '.join(cmd)}\n{stdout}")
            if stderr:
                output_parts.append(f"STDERR: {stderr}")
            if rc != 0:
                output_parts.append(f"EXIT CODE: {rc}")
                return "\n".join(output_parts)

        output_parts.append(f"SUCCESS: {tool_name} installed via {install_method}")
        return "\n".join(output_parts)

    def parse_output(self, raw_output: str) -> ToolInstallerOutput:
        """Parse installation output."""
        success = "SUCCESS:" in raw_output
        error = "" if success else raw_output.split("\n")[-1] if raw_output else "Empty output"

        return ToolInstallerOutput(
            tool_name=self.name,
            success=success,
            raw_output=raw_output,
            error=error,
            install_log=raw_output,
        )
