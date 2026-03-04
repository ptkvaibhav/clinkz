"""wafw00f tool wrapper — WAF (Web Application Firewall) detection.

Sample fixture: tests/fixtures/wafw00f_output.txt
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class WafDetectionResult(BaseModel):
    """WAF detection result for a single target URL."""

    target: str
    waf_detected: bool = False
    waf_name: str = ""
    manufacturer: str = ""


class Wafw00fOutput(ToolOutput):
    """Structured output from wafw00f."""

    results: list[WafDetectionResult] = []


# Patterns for wafw00f text output
_RE_CHECKING = re.compile(r"\[\*\] Checking (.+)")
_RE_DETECTED = re.compile(
    r"\[\+\] The site (.+?) is behind (.+?) WAF\.?$",
    re.IGNORECASE,
)
_RE_NO_WAF = re.compile(r"\[-\].*no waf detected", re.IGNORECASE)
_RE_MANUFACTURER = re.compile(r"^(.+?)\s*\(([^)]+)\)$")


class Wafw00fTool(ToolBase):
    """wafw00f WAF detection tool.

    Runs: wafw00f <target>
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
        """Parse wafw00f text output into WafDetectionResult models.

        Handles three line patterns:
        - ``[*] Checking <URL>``   — records the current target
        - ``[+] The site <URL> is behind <WAF> [(<Manufacturer>)] WAF.``
        - ``[-] No WAF detected …`` — no WAF for the current target

        Args:
            raw_output: Raw stdout from wafw00f.

        Returns:
            Wafw00fOutput with one WafDetectionResult per scanned target.
        """
        if not raw_output or not raw_output.strip():
            return Wafw00fOutput(tool_name=self.name, success=False, raw_output=raw_output)

        results: list[WafDetectionResult] = []
        seen: set[str] = set()
        current_target = ""

        for line in raw_output.splitlines():
            line = line.strip()

            m = _RE_CHECKING.match(line)
            if m:
                current_target = m.group(1).strip()
                continue

            m = _RE_DETECTED.match(line)
            if m:
                target = m.group(1).strip()
                waf_part = m.group(2).strip()
                waf_name, manufacturer = _split_waf_manufacturer(waf_part)
                if target not in seen:
                    seen.add(target)
                    results.append(
                        WafDetectionResult(
                            target=target,
                            waf_detected=True,
                            waf_name=waf_name,
                            manufacturer=manufacturer,
                        )
                    )
                continue

            if _RE_NO_WAF.match(line) and current_target and current_target not in seen:
                seen.add(current_target)
                results.append(WafDetectionResult(target=current_target, waf_detected=False))

        return Wafw00fOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
        )


def _split_waf_manufacturer(waf_part: str) -> tuple[str, str]:
    """Split 'Cloudflare (Cloudflare Inc.)' into (name, manufacturer)."""
    m = _RE_MANUFACTURER.match(waf_part)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return waf_part, ""
