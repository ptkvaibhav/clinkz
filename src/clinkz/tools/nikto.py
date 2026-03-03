"""Nikto tool wrapper — web server vulnerability scanner.

Sample fixture: tests/fixtures/nikto_output.xml
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class NiktoFinding(BaseModel):
    """Single Nikto finding."""

    id: str = ""
    description: str
    uri: str = ""
    method: str = ""


class NiktoOutput(ToolOutput):
    """Structured output from a Nikto scan."""

    findings: list[NiktoFinding] = []


class NiktoTool(ToolBase):
    """Nikto web server scanner.

    Runs: nikto -h <target> -Format xml -output /dev/stdout

    TODO: Parse Nikto XML output into NiktoFinding models.
    """

    @property
    def name(self) -> str:
        return "nikto"

    @property
    def description(self) -> str:
        return (
            "Scan a web server for common vulnerabilities, misconfigurations, and dangerous files."
        )

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host."},
                    "port": {
                        "type": "integer",
                        "description": "Port to scan (default: 80 or 443 based on URL).",
                        "default": 80,
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Force SSL/HTTPS.",
                        "default": False,
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for nikto")
        self._check_scope(target)
        return {
            "target": target,
            "port": int(args.get("port", 80)),
            "ssl": bool(args.get("ssl", False)),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "nikto",
            "-h",
            args["target"],
            "-p",
            str(args["port"]),
            "-Format",
            "xml",
            "-output",
            "/dev/stdout",
            "-nointeractive",
        ]
        if args.get("ssl"):
            cmd.append("-ssl")
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> NiktoOutput:
        # TODO: parse Nikto XML with xml.etree.ElementTree
        return NiktoOutput(tool_name=self.name, success=bool(raw_output), raw_output=raw_output)
