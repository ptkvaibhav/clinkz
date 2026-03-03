"""wafw00f tool wrapper — WAF (Web Application Firewall) detection.

Sample fixture: tests/fixtures/wafw00f_output.txt
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class WafDetectionResult(BaseModel):
    """WAF detection result for a single target."""

    target: str
    waf_detected: bool = False
    waf_name: str = ""


class Wafw00fOutput(ToolOutput):
    """Structured output from wafw00f."""

    results: list[WafDetectionResult] = []


class Wafw00fTool(ToolBase):
    """wafw00f WAF detection tool.

    Runs: wafw00f -o - <target>

    TODO: Parse wafw00f output to detect WAF name.
    """

    @property
    def name(self) -> str:
        return "wafw00f"

    @property
    def description(self) -> str:
        return "Detect if a Web Application Firewall (WAF) is protecting the target."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL to check for WAF."},
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for wafw00f")
        self._check_scope(target)
        return {"target": target}

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = ["wafw00f", args["target"]]
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> Wafw00fOutput:
        waf_detected = "is behind" in raw_output.lower()
        waf_name = ""
        for line in raw_output.splitlines():
            if "is behind" in line.lower():
                parts = line.split("is behind")
                if len(parts) > 1:
                    waf_name = parts[1].strip().strip("WAF").strip()
        return Wafw00fOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=[WafDetectionResult(target="", waf_detected=waf_detected, waf_name=waf_name)],
        )
