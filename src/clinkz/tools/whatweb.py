"""WhatWeb tool wrapper — web technology fingerprinting.

Sample fixture: tests/fixtures/whatweb_output.json
"""

from __future__ import annotations

from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput


class WhatWebOutput(ToolOutput):
    """Structured output from WhatWeb."""

    technologies: dict[str, list[str]] = {}  # url -> list of tech names


class WhatWebTool(ToolBase):
    """WhatWeb technology fingerprinter.

    Runs: whatweb --log-json=- <target>

    TODO: Parse WhatWeb JSON output into technology dicts.
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
        # TODO: parse WhatWeb JSON log format
        return WhatWebOutput(tool_name=self.name, success=bool(raw_output), raw_output=raw_output)
