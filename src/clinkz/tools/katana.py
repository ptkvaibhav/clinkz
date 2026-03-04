"""Katana tool wrapper — fast web crawler.

Sample fixture: tests/fixtures/katana_output.txt
"""

from __future__ import annotations

from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput


class KatanaOutput(ToolOutput):
    """Structured output from katana crawler."""

    urls: list[str] = []


class KatanaTool(ToolBase):
    """Katana web crawler.

    Runs: katana -u <url> -jc -silent

    TODO: Parse discovered URLs and filter interesting endpoints.
    """

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
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = ["katana", "-u", args["url"], "-depth", str(args["depth"]), "-silent"]
        if args.get("js_crawl"):
            cmd.append("-jc")
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> KatanaOutput:
        urls = [line.strip() for line in raw_output.splitlines() if line.strip().startswith("http")]
        return KatanaOutput(tool_name=self.name, success=True, raw_output=raw_output, urls=urls)
