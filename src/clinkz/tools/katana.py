"""Katana tool wrapper — fast web crawler.

Sample fixture: tests/fixtures/katana_output.txt
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse, urlunparse

from clinkz.tools.base import ToolBase, ToolOutput

# URL substrings that terminate the session we crawl with. When crawling
# authenticated (cookies present), katana follows in-app links — including
# the logout link on every page — and DVWA-style apps destroy the
# server-side session the moment logout.php is requested. That silently
# de-authenticates every downstream agent that reuses the same cookie, so
# the exploit phase analyses login pages and emits zero findings. We feed
# these to katana's ``-crawl-out-scope`` so the crawler never *requests*
# them; discovery of other endpoints is unaffected.
_SESSION_DESTROYING_URL_PATTERNS = ["logout", "signout", "sign-out", "sign_out"]


class KatanaOutput(ToolOutput):
    """Structured output from katana crawler."""

    urls: list[str] = []


class KatanaTool(ToolBase):
    """Katana web crawler.

    Runs: katana -u <url> -jc -silent
    """

    capabilities = ["web_crawling", "endpoint_discovery", "url_enumeration"]
    category = "scan"

    @property
    def name(self) -> str:
        return "katana"

    @property
    def description(self) -> str:
        return "Crawl a web application to discover URLs, endpoints, and JavaScript-loaded links."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Starting URL to crawl."},
                    "depth": {
                        "type": "integer",
                        "description": "Crawl depth (default: 3).",
                        "default": 3,
                    },
                    "js_crawl": {
                        "type": "boolean",
                        "description": "Parse JavaScript files for additional endpoints.",
                        "default": True,
                    },
                    "cookies": {
                        "type": "string",
                        "description": (
                            "Session cookies for authenticated crawling. "
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
            raise ValueError("'url' is required for katana")
        self._check_scope(url)
        return {
            "url": url,
            "depth": int(args.get("depth", 3)),
            "js_crawl": bool(args.get("js_crawl", True)),
            "cookies": str(args.get("cookies", "")).strip(),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        url = await self._normalize_seed_url(args["url"])
        cmd = ["katana", "-u", url, "-depth", str(args["depth"]), "-silent"]
        if args.get("js_crawl"):
            cmd.append("-jc")
        if args.get("cookies"):
            cmd.extend(["-H", f"Cookie: {args['cookies']}"])
            # Authenticated crawl: keep the crawler away from logout/sign-out
            # links so it cannot destroy the session it is borrowing. Only
            # applied when cookies are present, since that is the only case
            # where requesting these endpoints has a destructive side effect.
            for pattern in _SESSION_DESTROYING_URL_PATTERNS:
                cmd.extend(["-crawl-out-scope", pattern])
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    async def _normalize_seed_url(self, url: str) -> str:
        """Rewrite single-label hostnames to their resolved IP.

        katana v1.5.0's URL validator rejects single-label hostnames
        (e.g. ``http://clinkz-dvwa/``) with ``not a url. skipping`` and
        exits silently with no output. Docker-network container aliases
        are the common trigger. Resolve via ``getent hosts`` inside the
        tools container (when ``TOOL_EXEC_MODE=docker``) or on the host
        (when local) and substitute the IP back into the URL. Hosts that
        already contain a dot or are IP addresses pass through untouched.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host or "." in host or ":" in host:
            return url

        ip = await self._resolve_host_ip(host)
        if ip is None:
            return url

        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        new_netloc = f"{ip}{port_suffix}"
        return urlunparse(parsed._replace(netloc=new_netloc))

    async def _resolve_host_ip(self, host: str) -> str | None:
        """Resolve *host* to an IPv4 address via ``getent hosts``."""
        from clinkz.config import settings

        if settings.tool_exec_mode == "docker":
            cmd = ["docker", "exec", settings.docker_container, "getent", "hosts", host]
        else:
            cmd = ["getent", "hosts", host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (FileNotFoundError, TimeoutError, OSError):
            return None

        if proc.returncode != 0:
            return None
        first_line = stdout_bytes.decode(errors="replace").splitlines()[:1]
        if not first_line:
            return None
        parts = first_line[0].split()
        return parts[0] if parts else None

    def parse_output(self, raw_output: str) -> KatanaOutput:
        urls = [line.strip() for line in raw_output.splitlines() if line.strip().startswith("http")]
        return KatanaOutput(tool_name=self.name, success=True, raw_output=raw_output, urls=urls)
