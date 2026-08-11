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

    def discovered_urls(self) -> list[str]:
        """The URLs ffuf resolved, one per surviving hit.

        ffuf reports a hit as a fully-resolved URL (the wordlist entry already
        substituted into the ``FUZZ`` placeholder), so the result rows are the
        discovery items directly — there is no separate ``paths`` collection to
        read, which is precisely what the old duck-typed seam assumed.
        """
        return [r.url for r in self.results if r.url]


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
                    "cookies": {
                        "type": "string",
                        "description": (
                            "Session cookies for authenticated fuzzing. "
                            "Format: 'PHPSESSID=abc123; security=low'."
                        ),
                        "default": "",
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
            "cookies": str(args.get("cookies", "")).strip(),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        """Run ffuf, paced by the engagement's rate policy when one is in force.

        ffuf generates its own traffic inside a subprocess, so the engagement's
        HTTP chokepoint never sees those requests and cannot pace them. This is
        the tool most capable of flooding a live application — tens of thousands
        of requests across 40 threads — so its own ``-rate`` and ``-t`` flags are
        driven from the governor's policy instead.

        With no governor installed the flags are untouched and behaviour is
        unchanged, which keeps the benchmark suites at full speed.
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        threads = int(args["threads"])
        rate_flags: list[str] = []
        if governor is not None:
            policy = governor.policy
            # ffuf's -rate is requests/second across all threads; 0 means
            # unlimited, so round up to at least 1 rather than silently
            # uncapping a fractional policy.
            rate_flags = ["-rate", str(max(1, int(policy.max_requests_per_second)))]
            threads = min(threads, policy.max_concurrent_requests)

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
            str(threads),
            *rate_flags,
            "-s",  # silent mode
        ]
        if args.get("cookies"):
            cmd.extend(["-H", f"Cookie: {args['cookies']}"])
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
