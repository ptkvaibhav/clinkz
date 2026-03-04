"""Nikto tool wrapper — web server vulnerability scanner.

Sample fixture: tests/fixtures/nikto_output.xml
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
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

    Runs: nikto -h <target> -p <port> -Format xml -output /dev/stdout -nointeractive
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
        """Parse Nikto XML output into NiktoFinding models.

        Iterates over all ``<item>`` elements nested inside
        ``<niktoscandetails>`` and extracts id, description, uri, and method.
        Items without a description are skipped.

        Args:
            raw_output: Raw XML string from nikto -Format xml.

        Returns:
            NiktoOutput with one NiktoFinding per reported vulnerability.
        """
        if not raw_output or not raw_output.strip():
            return NiktoOutput(tool_name=self.name, success=False, raw_output=raw_output)

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as exc:
            return NiktoOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"XML parse error: {exc}",
            )

        findings: list[NiktoFinding] = []

        for item_el in root.findall(".//niktoscandetails/item"):
            item_id = item_el.get("id", "")
            method = item_el.get("method", "GET")

            desc_el = item_el.find("description")
            description = (desc_el.text or "").strip() if desc_el is not None else ""
            if not description:
                continue

            uri_el = item_el.find("uri")
            uri = (uri_el.text or "").strip() if uri_el is not None else ""

            findings.append(
                NiktoFinding(id=item_id, description=description, uri=uri, method=method)
            )

        return NiktoOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            findings=findings,
        )
