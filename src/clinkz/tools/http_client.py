"""HTTP Client tool — lets agents send arbitrary HTTP requests.

Enables manual exploitation workflows: crafting POST requests with
credentials, injecting payloads into parameters, testing authentication, etc.

Runs from the host (no Docker exec) using aiohttp.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from clinkz.tools.base import ToolBase, ToolOutput


class HTTPClientOutput(ToolOutput):
    """Structured output from an HTTP request."""

    status_code: int = 0
    response_headers: dict[str, str] = {}
    response_body: str = ""
    redirect_chain: list[str] = []
    response_time_ms: float = 0.0


class HTTPClientTool(ToolBase):
    """Send arbitrary HTTP requests for manual testing and exploitation.

    Unlike other tools, this runs directly from the host using aiohttp
    (NOT via Docker exec) so agents can interact with targets in real time.
    """

    capabilities = [
        "http_request",
        "request_crafting",
        "authentication_testing",
        "manual_exploitation",
    ]
    category = "utility"

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
                        "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).",
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
                # Set cookies
                for name, value in cookies.items():
                    session.cookie_jar.update_cookies({name: value})

                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    allow_redirects=follow_redirects,
                    ssl=False,
                ) as resp:
                    elapsed_ms = (time.monotonic() - start) * 1000

                    # Collect redirect history
                    if resp.history:
                        redirect_chain = [str(r.url) for r in resp.history]

                    resp_headers = {k: v for k, v in resp.headers.items()}
                    resp_body = await resp.text(errors="replace")

                    # Build a raw output string for debugging
                    raw = (
                        f"HTTP/{resp.version.major}.{resp.version.minor} "
                        f"{resp.status} {resp.reason}\n"
                    )
                    for k, v in resp_headers.items():
                        raw += f"{k}: {v}\n"
                    raw += f"\n{resp_body}"

                    # Encode structured data as a parseable format
                    import json

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
        except aiohttp.ClientError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            import json

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
        import json

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
