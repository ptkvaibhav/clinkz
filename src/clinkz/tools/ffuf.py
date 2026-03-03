"""ffuf tool wrapper — fast web fuzzer for directory and parameter discovery.

Sample fixture: tests/fixtures/ffuf_output.json
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput


class FfufResult(BaseModel):
    """Single ffuf hit."""

    url: str
    status: int
    length: int
    words: int
    lines: int


class FfufOutput(ToolOutput):
    """Structured output from ffuf."""

    results: list[FfufResult] = []


class FfufTool(ToolBase):
    """ffuf directory and parameter fuzzer.

    Runs: ffuf -u <url>/FUZZ -w <wordlist> -of json -o /dev/stdout

    TODO: Parse ffuf JSON output into FfufResult models.
    """

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def description(self) -> str:
        return "Fuzz a URL for hidden directories, files, or parameters using a wordlist."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with FUZZ placeholder (e.g., 'https://example.com/FUZZ').",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file.",
                        "default": "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    },
                    "filter_status": {
                        "type": "string",
                        "description": "HTTP status codes to filter out (e.g., '404,403').",
                        "default": "404",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads.",
                        "default": 40,
                    },
                },
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        url = args.get("url", "").strip()
        if not url:
            raise ValueError("'url' is required for ffuf")
        if "FUZZ" not in url:
            raise ValueError("'url' must contain the FUZZ placeholder")
        # Extract base URL for scope check
        from urllib.parse import urlparse

        base = urlparse(url).netloc
        self._check_scope(base)
        return {
            "url": url,
            "wordlist": args.get(
                "wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt"
            ),
            "filter_status": args.get("filter_status", "404"),
            "threads": int(args.get("threads", 40)),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "ffuf",
            "-u",
            args["url"],
            "-w",
            args["wordlist"],
            "-of",
            "json",
            "-o",
            "/dev/stdout",
            "-fc",
            args["filter_status"],
            "-t",
            str(args["threads"]),
            "-s",  # silent mode
        ]
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> FfufOutput:
        try:
            data = json.loads(raw_output)
            results = [
                FfufResult(
                    url=r.get("url", ""),
                    status=r.get("status", 0),
                    length=r.get("length", 0),
                    words=r.get("words", 0),
                    lines=r.get("lines", 0),
                )
                for r in data.get("results", [])
            ]
        except json.JSONDecodeError:
            results = []
        return FfufOutput(tool_name=self.name, success=True, raw_output=raw_output, results=results)
