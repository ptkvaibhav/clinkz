"""ffuf tool wrapper — fast web fuzzer for directory and parameter discovery.

Sample fixture: tests/fixtures/real_ffuf.json
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput

# Regex to strip ANSI escape sequences (common in Docker exec output)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class FfufResult(BaseModel):
    """Single ffuf hit."""

    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    redirect_location: str = ""
    host: str = ""
    input_data: dict[str, str] = {}
    duration_ns: int = 0


class FfufOutput(ToolOutput):
    """Structured output from ffuf."""

    results: list[FfufResult] = []
    command_line: str = ""


class FfufTool(ToolBase):
    """ffuf directory and parameter fuzzer.

    Runs: ffuf -u <url>/FUZZ -w <wordlist> -of json -o /dev/stdout
    """

    capabilities = ["directory_fuzzing", "parameter_fuzzing", "endpoint_discovery"]
    category = "scan"

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
        # Auto-insert FUZZ placeholder for directory fuzzing when caller passes
        # a bare URL. Parameter fuzzing requires the caller to place FUZZ
        # explicitly (e.g. "?q=FUZZ"), so only append when FUZZ is absent.
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        # Extract base URL for scope check
        from urllib.parse import urlparse

        base = urlparse(url).netloc
        self._check_scope(base)
        wordlist = args.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        # If the LLM provides a bare filename (no path separator), resolve it
        # to the standard seclists directory inside the Docker container.
        if wordlist and "/" not in wordlist and "\\" not in wordlist:
            wordlist = f"/usr/share/seclists/Discovery/Web-Content/{wordlist}"
        return {
            "url": url,
            "wordlist": wordlist,
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
        """Parse ffuf JSON output into structured results.

        Handles ANSI escape codes from Docker exec and extracts JSON from
        mixed output (banner text + JSON).
        """
        if not raw_output or not raw_output.strip():
            return FfufOutput(tool_name=self.name, success=False, raw_output=raw_output)

        # Strip ANSI escape codes (common in Docker exec output)
        cleaned = _ANSI_RE.sub("", raw_output)

        # Extract JSON object from potentially mixed output — find the
        # outermost { ... } block (ffuf outputs a single JSON object)
        json_str = cleaned
        start = cleaned.find("{")
        if start == -1:
            return FfufOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error="No JSON object found in ffuf output",
            )
        # Find matching closing brace by scanning from the end
        end = cleaned.rfind("}")
        if end == -1 or end <= start:
            return FfufOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error="Malformed JSON in ffuf output",
            )
        json_str = cleaned[start : end + 1]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            return FfufOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"JSON parse error: {exc}",
            )

        # ffuf wraps results in a top-level object with "results" array
        raw_results = data.get("results") or []
        command_line = data.get("commandline", "")

        results = [
            FfufResult(
                url=r.get("url", ""),
                status=r.get("status", 0),
                length=r.get("length", 0),
                words=r.get("words", 0),
                lines=r.get("lines", 0),
                content_type=r.get("content-type", ""),
                redirect_location=r.get("redirectlocation", ""),
                host=r.get("host", ""),
                input_data=r.get("input", {}),
                duration_ns=r.get("duration", 0),
            )
            for r in raw_results
            if isinstance(r, dict)
        ]

        return FfufOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
            command_line=command_line,
        )
