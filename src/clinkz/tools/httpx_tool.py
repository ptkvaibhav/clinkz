"""httpx tool wrapper — fast HTTP probing and fingerprinting.

Sample fixture: tests/fixtures/httpx_output.jsonl
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class HttpxResult(BaseModel):
    """Single httpx probe result."""

    url: str
    status_code: int = 0
    title: str = ""
    tech: list[str] = []
    content_length: int = 0
    webserver: str = ""


class HttpxOutput(ToolOutput):
    """Structured output from httpx."""

    results: list[HttpxResult] = []


class HttpxTool(ToolBase):
    """httpx HTTP service prober.

    Runs: httpx -u <url> -json -title -tech-detect -status-code

    TODO: Parse JSONL output into HttpxResult models.
    """

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def description(self) -> str:
        return "Probe HTTP/HTTPS services, detect status codes, titles, and technologies."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of URLs or hosts to probe.",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects.",
                        "default": True,
                    },
                },
                "required": ["targets"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        targets = args.get("targets", [])
        if not targets:
            raise ValueError("'targets' list is required for httpx")
        for t in targets:
            self._check_scope(t)
        return {"targets": targets, "follow_redirects": bool(args.get("follow_redirects", True))}

    async def execute(self, args: dict[str, Any]) -> str:
        import pathlib
        import tempfile

        targets_str = "\n".join(args["targets"])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(targets_str)
            tmp = f.name

        cmd = [
            "httpx",
            "-l",
            tmp,
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
            "-silent",
        ]
        if args.get("follow_redirects"):
            cmd.append("-follow-redirects")

        stdout, stderr, _ = await self._run_subprocess(cmd)
        pathlib.Path(tmp).unlink(missing_ok=True)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> HttpxOutput:
        """Parse httpx JSON-lines output into HttpxResult models.

        Handles the real httpx JSON field names (status-code, content-length
        with hyphens; technologies as the primary tech list key).
        Invalid lines are silently skipped.

        Args:
            raw_output: Raw JSONL stdout from httpx -json -silent.

        Returns:
            HttpxOutput with one HttpxResult per successfully probed URL.
        """
        if not raw_output or not raw_output.strip():
            return HttpxOutput(tool_name=self.name, success=False, raw_output=raw_output)
        results = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append(
                HttpxResult(
                    url=data.get("url", ""),
                    status_code=data.get("status-code", data.get("status_code", 0)),
                    title=data.get("title", ""),
                    tech=data.get("technologies", data.get("tech", [])),
                    content_length=data.get("content-length", data.get("content_length", 0)),
                    webserver=data.get("webserver", ""),
                )
            )
        return HttpxOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
        )
