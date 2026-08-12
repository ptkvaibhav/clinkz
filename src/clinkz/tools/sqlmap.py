"""sqlmap tool wrapper — SQL injection detection and exploitation.

Sample fixture: tests/fixtures/sqlmap_output.txt

WARNING: sqlmap can be destructive if --dump or --os-shell flags are used.
Only use read-only detection flags in automated mode.
"""

from __future__ import annotations

import re
from typing import Any

from clinkz.tools.base import ToolBase, ToolOutput

#: Sentences sqlmap prints when it has CONCLUDED a parameter is injectable.
#: Deliberately narrow: every one of these appears only after sqlmap has decided,
#: never in the progress chatter it emits while testing.
_INJECTABLE_MARKERS: tuple[str, ...] = (
    "identified the following injection point",
    "is vulnerable",
    "appears to be injectable",
    "injection point(s) with a total",
)

#: Sentences sqlmap prints when it has concluded the opposite. Checked FIRST and
#: allowed to win: sqlmap's negative conclusion is unambiguous, and a run can
#: contain a heuristic "appears to be injectable" note that its own final verdict
#: then retracts.
_NOT_INJECTABLE_MARKERS: tuple[str, ...] = (
    "all tested parameters do not appear to be injectable",
    "all tested parameters appear to be not injectable",
)

#: ``back-end DBMS: MySQL >= 5.0.12`` → ``MySQL >= 5.0.12``.
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)


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
    """

    capabilities = ["sql_injection_testing", "sqli_detection", "database_fingerprinting"]
    category = "exploit"

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
                    "cookie": {
                        "type": "string",
                        "description": "Cookie string for authenticated testing.",
                        "default": "",
                    },
                    "header": {
                        "type": "string",
                        "description": (
                            "Extra HTTP header for authenticated testing, e.g. "
                            "'Authorization: Bearer <jwt>'. Multiple headers may "
                            "be newline-separated."
                        ),
                        "default": "",
                    },
                    "forms": {
                        "type": "boolean",
                        "description": "Automatically detect and test forms on the target page.",
                        "default": False,
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

        # Cookie can arrive as a dict from LLM (e.g., {"PHPSESSID": "abc"})
        # — convert to "key=value; key=value" string for the CLI flag.
        cookie_raw = args.get("cookie", "")
        if isinstance(cookie_raw, dict):
            cookie = "; ".join(f"{k}={v}" for k, v in cookie_raw.items())
        else:
            cookie = str(cookie_raw)

        # Header(s) — a dict ({"Authorization": "Bearer x"}) becomes
        # newline-separated "Key: value" lines for sqlmap's --headers flag.
        header_raw = args.get("header", "")
        if isinstance(header_raw, dict):
            header = "\n".join(f"{k}: {v}" for k, v in header_raw.items())
        else:
            header = str(header_raw)

        return {
            "url": url,
            "data": str(args.get("data", "")),
            "level": level,
            "risk": risk,
            "cookie": cookie,
            "header": header,
            "forms": bool(args.get("forms", False)),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        import shutil
        import tempfile

        tmp_dir = tempfile.mkdtemp(prefix="sqlmap_")
        try:
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
            if args.get("cookie"):
                cmd.extend(["--cookie", args["cookie"]])
            if args.get("header"):
                header = args["header"]
                # --header takes a single header; --headers takes multiple
                # (newline-separated). Pick by content.
                if "\n" in header:
                    cmd.extend(["--headers", header])
                else:
                    cmd.extend(["--header", header])
            if args.get("forms"):
                cmd.append("--forms")
            stdout, stderr, _ = await self._run_subprocess(cmd)
            return stdout or stderr
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def parse_output(self, raw_output: str) -> SqlmapOutput:
        """Parse sqlmap's console output into its verdict and the evidence for it.

        The predecessor was::

            vulnerable = "is vulnerable" in lower or "parameter" in lower

        The second clause matches ``testing for SQL injection on GET parameter
        'id'``, which sqlmap prints on EVERY run before it knows anything — so
        ``vulnerable`` was ``True`` whenever sqlmap executed at all, whatever it
        found. That is worse than the dead seam it replaced: a seam that always
        returns ``False`` costs coverage, while a verdict that is always ``True``
        manufactures leads on every parameter this engine's own oracle declined.

        The verdict now keys on sqlmap's own conclusion markers, and the negative
        marker wins: sqlmap prints ``all tested parameters do not appear to be
        injectable`` when it is finished and found nothing, and that sentence
        contains none of the positive markers but is unambiguous about the
        answer.

        ``injection_types``, ``dbms`` and ``payloads`` have been on the model
        since it was written and were never populated by anything. They are
        parsed here because they are the whole reason a lead built from this is
        useful: an operator needs the technique and the payload to re-derive the
        result, and "sqlmap said yes" is not re-derivable.

        Args:
            raw_output: sqlmap's stdout (``--batch`` console output).

        Returns:
            :class:`SqlmapOutput` whose ``vulnerable`` reflects sqlmap's stated
            conclusion, never merely the fact that it ran.
        """
        text = raw_output or ""
        lowered = text.lower()

        if not text.strip():
            return SqlmapOutput(tool_name=self.name, success=False, raw_output=text)

        if any(marker in lowered for marker in _NOT_INJECTABLE_MARKERS):
            vulnerable = False
        else:
            vulnerable = any(marker in lowered for marker in _INJECTABLE_MARKERS)

        injection_types: list[str] = []
        payloads: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("type:"):
                value = stripped.split(":", 1)[1].strip()
                if value and value not in injection_types:
                    injection_types.append(value)
            elif stripped.lower().startswith("payload:"):
                value = stripped.split(":", 1)[1].strip()
                if value and value not in payloads:
                    payloads.append(value)

        dbms = ""
        match = _DBMS_RE.search(text)
        if match:
            dbms = match.group(1).strip()

        return SqlmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=text,
            vulnerable=vulnerable,
            injection_types=injection_types,
            dbms=dbms,
            payloads=payloads,
        )
