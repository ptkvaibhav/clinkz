"""Subfinder tool wrapper — passive subdomain enumeration.

Sample fixture: tests/fixtures/subfinder_output.txt
"""

from __future__ import annotations

from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput


class SubfinderOutput(ToolOutput):
    """Structured output from subfinder."""

    subdomains: list[str] = []


class SubfinderTool(ToolBase):
    """Subfinder passive subdomain enumerator.

    Runs: subfinder -d <domain> -silent -o -

    TODO: Parse subfinder output (one subdomain per line).
    """

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def description(self) -> str:
        return "Enumerate subdomains for a domain using passive sources."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Root domain to enumerate subdomains for (e.g., 'example.com').",  # noqa: E501
                    },
                    "all_sources": {
                        "type": "boolean",
                        "description": "Use all available passive sources (slower but more thorough).",  # noqa: E501
                        "default": False,
                    },
                },
                "required": ["domain"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        domain = args.get("domain", "").strip()
        if not domain:
            raise ValueError("'domain' is required for subfinder")
        self._check_scope(domain)
        return {"domain": domain, "all_sources": bool(args.get("all_sources", False))}

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = ["subfinder", "-d", args["domain"], "-silent"]
        if args.get("all_sources"):
            cmd.append("-all")
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> SubfinderOutput:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return SubfinderOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            subdomains=subdomains,
        )
