"""Nmap tool wrapper — port scanning and service fingerprinting.

Sample fixture: tests/fixtures/nmap_output.xml
"""

from __future__ import annotations

from typing import Any

from clinkz.models.target import Host
from clinkz.tools.base import ToolBase, ToolOutput


class NmapOutput(ToolOutput):
    """Structured output from an nmap scan."""

    hosts: list[Host] = []
    open_ports: list[int] = []


class NmapTool(ToolBase):
    """Nmap port scanner and service fingerprinter.

    Runs: nmap -sV -sC -oX - <target> -p <ports>

    TODO: Parse nmap XML output into Host / Service models.
    """

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Scan a target for open ports and identify running services."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g., '1-1000', '80,443,8080', '-' for all).",  # noqa: E501
                        "default": "1-1000",
                    },
                    "flags": {
                        "type": "string",
                        "description": "Additional nmap flags (e.g., '-sU' for UDP, '--script vuln').",  # noqa: E501
                        "default": "",
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for nmap")
        self._check_scope(target)
        return {
            "target": target,
            "ports": args.get("ports", "1-1000"),
            "flags": args.get("flags", ""),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "-oX",
            "-",  # XML output to stdout
            "-p",
            args["ports"],
        ]
        if args.get("flags"):
            cmd.extend(args["flags"].split())
        cmd.append(args["target"])
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> NmapOutput:
        # TODO: parse nmap XML with xml.etree.ElementTree into Host / Service models
        return NmapOutput(tool_name=self.name, success=bool(raw_output), raw_output=raw_output)
