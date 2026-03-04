"""Nuclei tool wrapper — template-based vulnerability scanner.

Sample fixture: tests/fixtures/nuclei_output.jsonl
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class NucleiFinding(BaseModel):
    """Single nuclei template match."""

    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str = ""
    description: str = ""
    reference: list[str] = []


class NucleiOutput(ToolOutput):
    """Structured output from a nuclei scan."""

    findings: list[NucleiFinding] = []


class NucleiTool(ToolBase):
    """Nuclei vulnerability scanner.

    Runs: nuclei -u <target> -severity <severity> -json

    TODO: Parse nuclei JSONL output into NucleiFinding models.
    """

    capabilities = ["vulnerability_scanning", "cve_detection", "template_based_scanning"]
    category = "exploit"

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def description(self) -> str:
        return "Run nuclei vulnerability templates against a target URL or host."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or host."},
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severity filter (e.g., 'critical,high,medium').",  # noqa: E501
                        "default": "critical,high,medium",
                    },
                    "tags": {
                        "type": "string",
                        "description": "Comma-separated template tags to run (e.g., 'cve,sqli,xss').",  # noqa: E501
                        "default": "",
                    },
                    "templates": {
                        "type": "string",
                        "description": "Path to specific templates or template directory.",
                        "default": "",
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for nuclei")
        self._check_scope(target)
        return {
            "target": target,
            "severity": args.get("severity", "critical,high,medium"),
            "tags": args.get("tags", ""),
            "templates": args.get("templates", ""),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "nuclei",
            "-u",
            args["target"],
            "-severity",
            args["severity"],
            "-json",
            "-silent",
        ]
        if args.get("tags"):
            cmd.extend(["-tags", args["tags"]])
        if args.get("templates"):
            cmd.extend(["-t", args["templates"]])
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> NucleiOutput:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(
                    NucleiFinding(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "unknown"),
                        url=data.get("host", ""),
                        matched_at=data.get("matched-at", ""),
                        description=data.get("info", {}).get("description", ""),
                        reference=data.get("info", {}).get("reference", []),
                    )
                )
            except json.JSONDecodeError:
                continue
        return NucleiOutput(
            tool_name=self.name, success=True, raw_output=raw_output, findings=findings
        )
