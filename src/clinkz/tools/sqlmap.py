"""sqlmap tool wrapper — SQL injection detection and exploitation.

Sample fixture: tests/fixtures/sqlmap_output.txt

WARNING: sqlmap can be destructive if --dump or --os-shell flags are used.
Only use read-only detection flags in automated mode.
"""

from __future__ import annotations

from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput


class SqlmapOutput(ToolOutput):
    """Structured output from sqlmap."""

    vulnerable: bool = False
    injection_types: list[str] = []
    dbms: str = ""
    payloads: list[str] = []


class SqlmapTool(ToolBase):
    """sqlmap SQL injection tester.

    Runs: sqlmap -u <url> --batch --level=2 --risk=1 --output-dir=<tmp>

    Safety rules:
    - Never use --dump, --all, --os-shell, --os-cmd in automated mode
    - Level ≤ 3, Risk ≤ 2 to avoid destructive payloads
    - Always use --batch for non-interactive mode

    TODO: Parse sqlmap output to detect vulnerable parameters and injection types.
    """

    @property
    def name(self) -> str:
        return "sqlmap"

    @property
    def description(self) -> str:
        return "Test a URL for SQL injection vulnerabilities."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with parameters (e.g., 'https://example.com/search?q=test').",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data to test (e.g., 'username=admin&password=test').",
                        "default": "",
                    },
                    "level": {
                        "type": "integer",
                        "description": "Test level 1-5 (default: 2, max recommended: 3).",
                        "default": 2,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk level 1-3 (default: 1, max recommended: 2).",
                        "default": 1,
                    },
                },
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        url = args.get("url", "").strip()
        if not url:
            raise ValueError("'url' is required for sqlmap")
        from urllib.parse import urlparse

        self._check_scope(urlparse(url).netloc)
        level = min(int(args.get("level", 2)), 3)  # cap at 3 for safety
        risk = min(int(args.get("risk", 1)), 2)  # cap at 2 for safety
        return {"url": url, "data": args.get("data", ""), "level": level, "risk": risk}

    async def execute(self, args: dict[str, Any]) -> str:
        import tempfile

        tmp_dir = tempfile.mkdtemp(prefix="sqlmap_")
        cmd = [
            "sqlmap",
            "-u",
            args["url"],
            "--batch",
            f"--level={args['level']}",
            f"--risk={args['risk']}",
            f"--output-dir={tmp_dir}",
            "--flush-session",
        ]
        if args.get("data"):
            cmd.extend(["--data", args["data"]])
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> SqlmapOutput:
        vulnerable = "is vulnerable" in raw_output.lower() or "parameter" in raw_output.lower()
        return SqlmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            vulnerable=vulnerable,
        )
