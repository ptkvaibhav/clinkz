"""HTTP Client tool — lets agents send arbitrary HTTP requests.

Enables manual exploitation workflows: crafting POST requests with
credentials, injecting payloads into parameters, testing authentication, etc.

When TOOL_EXEC_MODE=docker, executes curl inside the Docker container so that
requests originate from the container network. Otherwise uses aiohttp on the host.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlparse

from clinkz.tools.base import ToolBase, ToolOutput


class HTTPClientOutput(ToolOutput):
    """Structured output from an HTTP request."""

    status_code: int = 0
    response_headers: dict[str, str] = {}
    response_body: str = ""
    redirect_chain: list[str] = []
    response_time_ms: float = 0.0


def _cookie_jar_path(engagement_id: str) -> str:
    """Return the shared cookie jar file path for an engagement.

    All curl calls within the same engagement share this file, so cookies
    obtained during authentication persist across agents and tool invocations.

    Args:
        engagement_id: UUID of the active engagement.

    Returns:
        Absolute path string (``/tmp/clinkz_{engagement_id}_cookies.txt``).
    """
    return f"/tmp/clinkz_{engagement_id}_cookies.txt"


def get_session_cookies(engagement_id: str) -> dict[str, str]:
    """Read the Netscape-format cookie jar and return cookies as a dict.

    Args:
        engagement_id: UUID of the active engagement.

    Returns:
        Dict of cookie_name → cookie_value.  Empty dict if the jar
        does not exist or is empty.
    """
    import os

    jar_path = _cookie_jar_path(engagement_id)
    cookies: dict[str, str] = {}

    if not os.path.isfile(jar_path):
        return cookies

    try:
        with open(jar_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    # Netscape cookie format: domain, flag, path, secure, exp, name, value
                    cookies[parts[5]] = parts[6]
    except OSError:
        pass

    return cookies


class HTTPClientTool(ToolBase):
    """Send arbitrary HTTP requests for manual testing and exploitation.

    In Docker mode, uses curl via ``docker exec`` so requests come from the
    container network. In local mode, uses aiohttp on the host.

    Args:
        engagement_id: If provided, a per-engagement cookie jar is used so
            session cookies persist across all requests in the engagement.
    """

    capabilities = [
        "http_request",
        "request_crafting",
        "authentication_testing",
        "manual_exploitation",
    ]
    category = "utility"

    def __init__(
        self,
        scope: Any = None,
        timeout: int = 300,
        engagement_id: str | None = None,
    ) -> None:
        if scope is None:
            from clinkz.models.scope import EngagementScope

            scope = EngagementScope(name="default", targets=[])
        super().__init__(scope=scope, timeout=timeout)
        self._engagement_id = engagement_id

    @property
    def name(self) -> str:
        return "http_client"

    @property
    def description(self) -> str:
        return "Send an arbitrary HTTP request to a target URL."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).",
                        "default": "GET",
                    },
                    "url": {
                        "type": "string",
                        "description": "Full URL to send the request to.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom HTTP headers as key-value pairs.",
                        "default": {},
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body (for POST/PUT/PATCH).",
                        "default": "",
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Cookies as key-value pairs.",
                        "default": {},
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Whether to follow HTTP redirects.",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        url = args.get("url", "").strip()
        if not url:
            raise ValueError("'url' is required for http_client")

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"Invalid URL: {url}")

        self._check_scope(url)

        method = args.get("method", "GET").upper()
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {method}")

        return {
            "method": method,
            "url": url,
            "headers": args.get("headers") or {},
            "body": args.get("body", ""),
            "cookies": args.get("cookies") or {},
            "follow_redirects": bool(args.get("follow_redirects", False)),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        """Execute the HTTP request and return raw response info."""
        from clinkz.config import settings

        if settings.tool_exec_mode == "docker":
            return await self._execute_curl(args)
        return await self._execute_aiohttp(args)

    # ------------------------------------------------------------------
    # Docker mode: curl inside container
    # ------------------------------------------------------------------

    async def _execute_curl(self, args: dict[str, Any]) -> str:
        """Build and run a curl command inside the Docker container."""
        method = args["method"]
        url = args["url"]
        headers: dict[str, str] = args.get("headers") or {}
        body: str = args.get("body", "")
        cookies: dict[str, str] = args.get("cookies") or {}
        follow_redirects: bool = args.get("follow_redirects", False)

        # Per-engagement cookie jar so sessions persist across all requests
        cookie_jar = (
            _cookie_jar_path(self._engagement_id)
            if self._engagement_id
            else "/tmp/clinkz_cookies.txt"
        )

        # Build curl command
        cmd: list[str] = [
            "curl",
            "-s",  # silent (no progress bar)
            "-S",  # show errors
            "-D",
            "-",  # dump response headers to stdout
            "-X",
            method,
            "-w",
            "\n__CURL_TIMING__%{time_total}\n",  # timing info at end
        ]

        if follow_redirects:
            cmd.append("-L")

        # Headers
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Request body
        if body:
            cmd.extend(["-d", body])

        # Cookie jar for persistence across redirect chain
        cmd.extend(["-c", cookie_jar])

        # Cookies — if dict provided, send as header; otherwise read from jar
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cmd.extend(["-b", cookie_str])
        else:
            cmd.extend(["-b", cookie_jar])

        cmd.append(url)

        start = time.monotonic()
        try:
            stdout, stderr, returncode = await self._run_subprocess(cmd)
            elapsed_ms = (time.monotonic() - start) * 1000

            if returncode != 0 and not stdout.strip():
                return json.dumps(
                    {
                        "status_code": 0,
                        "response_headers": {},
                        "response_body": "",
                        "redirect_chain": [],
                        "response_time_ms": round(elapsed_ms, 2),
                        "error": f"curl exited with code {returncode}: {stderr.strip()}",
                    }
                )

            return self._parse_curl_output(stdout, elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return json.dumps(
                {
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "redirect_chain": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "error": str(exc),
                }
            )

    def _parse_curl_output(self, raw: str, elapsed_ms: float) -> str:
        """Parse curl ``-D -`` output into structured JSON.

        The output format from ``curl -D - -w '\\n__CURL_TIMING__%%{time_total}'``
        is:
            HTTP/1.1 200 OK\\r\\n
            Header: value\\r\\n
            ...\\r\\n
            \\r\\n
            <body>
            __CURL_TIMING__0.123
        """
        # Extract timing from the end
        timing_match = re.search(r"__CURL_TIMING__([\d.]+)\s*$", raw)
        if timing_match:
            curl_time_s = float(timing_match.group(1))
            elapsed_ms = curl_time_s * 1000
            raw = raw[: timing_match.start()]

        # With -L (follow redirects), there may be multiple HTTP response blocks.
        # Split on HTTP status lines to find intermediate redirects and final response.
        # Pattern: "HTTP/<version> <status>" at start of a line
        http_blocks = re.split(r"(?=^HTTP/[\d.]+ \d+)", raw, flags=re.MULTILINE)
        http_blocks = [b for b in http_blocks if b.strip()]

        redirect_chain: list[str] = []
        status_code = 0
        resp_headers: dict[str, str] = {}
        resp_body = ""

        for i, block in enumerate(http_blocks):
            # Parse status line
            status_match = re.match(r"HTTP/[\d.]+ (\d+)", block)
            if not status_match:
                # This block is just body continuation
                resp_body += block
                continue

            code = int(status_match.group(1))

            # Split headers from body at the blank line
            header_body_split = re.split(r"\r?\n\r?\n", block, maxsplit=1)
            header_section = header_body_split[0]
            body_section = header_body_split[1] if len(header_body_split) > 1 else ""

            if i < len(http_blocks) - 1:
                # Intermediate response (redirect)
                # Extract Location header for redirect chain
                loc_match = re.search(
                    r"^Location:\s*(.+)$", header_section, re.IGNORECASE | re.MULTILINE
                )
                if loc_match:
                    redirect_chain.append(loc_match.group(1).strip())
            else:
                # Final response
                status_code = code
                resp_body = body_section

                # Parse headers (append duplicates with `, `)
                for line in header_section.split("\n"):
                    line = line.strip().rstrip("\r")
                    if ":" in line and not line.startswith("HTTP/"):
                        key, _, value = line.partition(":")
                        k, v = key.strip(), value.strip()
                        if k in resp_headers:
                            resp_headers[k] += f", {v}"
                        else:
                            resp_headers[k] = v

        raw_display = f"HTTP {status_code}\n"
        for k, v in resp_headers.items():
            raw_display += f"{k}: {v}\n"
        raw_display += f"\n{resp_body}"

        return json.dumps(
            {
                "status_code": status_code,
                "response_headers": resp_headers,
                "response_body": resp_body,
                "redirect_chain": redirect_chain,
                "response_time_ms": round(elapsed_ms, 2),
                "raw": raw_display,
            }
        )

    # ------------------------------------------------------------------
    # Local mode: aiohttp on the host
    # ------------------------------------------------------------------

    async def _execute_aiohttp(self, args: dict[str, Any]) -> str:
        """Execute the HTTP request using aiohttp (host-based)."""
        import aiohttp

        method = args["method"]
        url = args["url"]
        headers = args.get("headers") or {}
        body = args.get("body", "")
        cookies = args.get("cookies") or {}
        follow_redirects = args.get("follow_redirects", False)

        redirect_chain: list[str] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        start = time.monotonic()
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ) as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    cookies=cookies if cookies else None,
                    allow_redirects=follow_redirects,
                    ssl=False,
                ) as resp:
                    elapsed_ms = (time.monotonic() - start) * 1000

                    # Collect redirect history
                    if resp.history:
                        redirect_chain = [str(r.url) for r in resp.history]

                    resp_headers = {k: v for k, v in resp.headers.items()}
                    resp_body = await resp.text(errors="replace")

                    raw = (
                        f"HTTP/{resp.version.major}.{resp.version.minor} "
                        f"{resp.status} {resp.reason}\n"
                    )
                    for k, v in resp_headers.items():
                        raw += f"{k}: {v}\n"
                    raw += f"\n{resp_body}"

                    return json.dumps(
                        {
                            "status_code": resp.status,
                            "response_headers": resp_headers,
                            "response_body": resp_body,
                            "redirect_chain": redirect_chain,
                            "response_time_ms": round(elapsed_ms, 2),
                            "raw": raw,
                        }
                    )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return json.dumps(
                {
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "redirect_chain": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "error": str(exc),
                }
            )

    def parse_output(self, raw_output: str) -> HTTPClientOutput:
        """Parse the JSON response from execute() into structured output."""
        if not raw_output or not raw_output.strip():
            return HTTPClientOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output or "",
                error="Empty response",
            )

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            return HTTPClientOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"JSON parse error: {exc}",
            )

        error = data.get("error", "")
        return HTTPClientOutput(
            tool_name=self.name,
            success=not error,
            raw_output=data.get("raw", raw_output),
            error=error,
            status_code=data.get("status_code", 0),
            response_headers=data.get("response_headers", {}),
            response_body=data.get("response_body", ""),
            redirect_chain=data.get("redirect_chain", []),
            response_time_ms=data.get("response_time_ms", 0.0),
        )
