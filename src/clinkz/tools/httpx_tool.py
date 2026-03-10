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

    capabilities = ["http_probing", "technology_detection", "service_fingerprinting", "alive_check"]
    category = "recon"

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
                    "target": {
                        "type": "string",
                        "description": "Required. URL or IP to probe (single target).",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of URLs or IPs to probe (alternative to 'target').",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects.",
                        "default": True,
                    },
                },
                "required": ["target"],
            },
        }

    def _normalize_targets(self, args: dict[str, Any]) -> list[str]:
        """Accept both 'target' (string) and 'targets' (list) params."""
        targets = args.get("targets") or []
        target = args.get("target")
        if target:
            if isinstance(target, str):
                targets = [target] + list(targets)
            else:
                targets = list(target) + list(targets)
        # deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        targets = self._normalize_targets(args)
        if not targets:
            raise ValueError("'target' or 'targets' is required for httpx")
        for t in targets:
            self._check_scope(t)
        return {"targets": targets, "follow_redirects": bool(args.get("follow_redirects", True))}

    async def execute(self, args: dict[str, Any]) -> str:
        from clinkz.config import settings

        targets_str = "\n".join(args["targets"])

        cmd = [
            "httpx",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
            "-silent",
        ]
        if args.get("follow_redirects"):
            cmd.append("-follow-redirects")

        if settings.tool_exec_mode == "docker":
            # In docker mode, pipe targets via stdin instead of a temp file
            # (temp files on the host are not accessible inside the container).
            stdout, stderr, _ = await self._run_subprocess_stdin(cmd, targets_str)
        else:
            import pathlib
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(targets_str)
                tmp = f.name
            cmd.extend(["-l", tmp])
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
