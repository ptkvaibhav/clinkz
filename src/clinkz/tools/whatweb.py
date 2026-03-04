"""WhatWeb tool wrapper — web technology fingerprinting.

Sample fixture: tests/fixtures/whatweb_output.json
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class WhatWebScanResult(BaseModel):
    """Fingerprint result for a single URL."""

    target: str
    http_status: int = 0
    technologies: list[str] = []  # plugin names detected
    versions: dict[str, str] = {}  # plugin name -> first version string
    server: str = ""  # value of the HTTPServer plugin


class WhatWebOutput(ToolOutput):
    """Structured output from WhatWeb."""

    results: list[WhatWebScanResult] = []
    technologies: dict[str, list[str]] = {}  # url -> list of tech names


class WhatWebTool(ToolBase):
    """WhatWeb technology fingerprinter.

    Runs: whatweb --aggression=<n> --log-json=- <target>
    """

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def description(self) -> str:
        return "Identify web technologies, CMS, frameworks, and server software."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to fingerprint."},
                    "aggression": {
                        "type": "integer",
                        "description": "Aggression level 1-4 (1=passive, 3=moderate).",
                        "default": 1,
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for whatweb")
        self._check_scope(target)
        aggression = int(args.get("aggression", 1))
        if not 1 <= aggression <= 4:
            raise ValueError("aggression must be between 1 and 4")
        return {"target": target, "aggression": aggression}

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "whatweb",
            f"--aggression={args['aggression']}",
            "--log-json=-",
            args["target"],
        ]
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> WhatWebOutput:
        """Parse WhatWeb JSON log output into WhatWebScanResult models.

        WhatWeb outputs a JSON array via --log-json=-, where each element
        represents one scanned URL and contains a ``plugins`` dict mapping
        plugin name to detected strings/versions.

        Args:
            raw_output: Raw JSON string from whatweb --log-json=-.

        Returns:
            WhatWebOutput with per-URL technology fingerprints.
        """
        if not raw_output or not raw_output.strip():
            return WhatWebOutput(tool_name=self.name, success=False, raw_output=raw_output)

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            return WhatWebOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"JSON parse error: {exc}",
            )

        # Normalise: accept both a JSON array and a single object
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return WhatWebOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error="Unexpected JSON structure — expected array of scan results",
            )

        results: list[WhatWebScanResult] = []
        technologies_map: dict[str, list[str]] = {}

        for entry in data:
            if not isinstance(entry, dict):
                continue
            target = entry.get("target", "")
            http_status = int(entry.get("http_status", 0))
            plugins: dict[str, Any] = entry.get("plugins", {})

            tech_names: list[str] = []
            versions: dict[str, str] = {}
            server = ""

            for plugin_name, plugin_data in plugins.items():
                tech_names.append(plugin_name)
                if isinstance(plugin_data, dict):
                    version_list = plugin_data.get("version", [])
                    if version_list:
                        versions[plugin_name] = version_list[0]
                    if plugin_name == "HTTPServer":
                        strings = plugin_data.get("string", [])
                        if strings:
                            server = strings[0]

            results.append(
                WhatWebScanResult(
                    target=target,
                    http_status=http_status,
                    technologies=tech_names,
                    versions=versions,
                    server=server,
                )
            )
            technologies_map[target] = tech_names

        return WhatWebOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
            technologies=technologies_map,
        )
