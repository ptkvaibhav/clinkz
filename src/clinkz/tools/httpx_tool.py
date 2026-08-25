"""httpx tool wrapper — fast HTTP probing and fingerprinting.

Sample fixture: tests/fixtures/httpx_output.jsonl
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from clinkz.models.recon import VersionProvenance
from clinkz.tools.base import DetectedComponent, ToolBase, ToolOutput
from clinkz.tools.component_names import split_name_version


class HttpxResult(BaseModel):
    """Single httpx probe result."""

    url: str
    status_code: int = 0
    title: str = ""
    tech: list[str] = []
    content_length: int = 0
    webserver: str = ""


class HttpxOutput(ToolOutput):
    """Structured output from httpx."""

    results: list[HttpxResult] = []

    def discovered_urls(self) -> list[str]:
        """The URLs httpx confirmed were live."""
        return [r.url for r in self.results if r.url]

    def detected_components(self) -> list[DetectedComponent]:
        """Technologies httpx's ``-tech-detect`` named, plus the server banner.

        httpx reports a technology as one string with the version already inside
        it (``nginx:1.24.0``, ``Express 4.17.1``), so the name/version split is
        done here — at the wrapper that knows the tool's own format — rather than
        by every consumer guessing at it.

        Provenance is ``BANNER``: both channels here — ``-tech-detect`` and the
        ``Server`` header — are strings the target emitted.
        """
        seen: set[tuple[str, str]] = set()
        components: list[DetectedComponent] = []
        for result in self.results:
            for raw in [*result.tech, result.webserver]:
                name, version = split_name_version(raw)
                if not name:
                    continue
                key = (name.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                components.append(
                    DetectedComponent(
                        name=name,
                        version=version,
                        source="httpx:tech",
                        provenance=VersionProvenance.BANNER,
                    )
                )
        return components


class HttpxTool(ToolBase):
    """httpx HTTP service prober.

    Runs: httpx -u <url> -json -title -tech-detect -status-code
    """

    # ``web_fingerprinting`` is declared because ``TOOL_CHAINS`` names httpx as
    # whatweb's fallback for it — and a chain entry the tool does not declare is
    # a fallback that cannot fire. ``find_tool("web_fingerprinting")`` reads the
    # capability map, so before this line the chain read
    # ``["whatweb", "wappalyzer", "httpx"]`` and could resolve exactly one of
    # them: with whatweb absent the capability failed outright rather than
    # falling back to the tool declared to cover it.
    capabilities = [
        "http_probing",
        "web_fingerprinting",
        "technology_detection",
        "service_fingerprinting",
        "alive_check",
    ]
    category = "recon"

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def description(self) -> str:
        return "Probe HTTP/HTTPS services, detect status codes, titles, and technologies."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Required. URL or IP to probe (single target).",
                    },
                    "url": {
                        "type": "string",
                        "description": "Alias for 'target'. URL or IP to probe.",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of URLs or IPs to probe (alternative to 'target').",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects.",
                        "default": True,
                    },
                },
                "required": ["target"],
            },
        }

    def _normalize_targets(self, args: dict[str, Any]) -> list[str]:
        """Accept 'target', 'url', and 'targets' (list) params.

        The LLM sometimes uses 'url' instead of 'target', so we accept both.
        """
        targets = args.get("targets") or []
        target = args.get("target") or args.get("url")
        if target:
            if isinstance(target, str):
                targets = [target] + list(targets)
            else:
                targets = list(target) + list(targets)
        # deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        targets = self._normalize_targets(args)
        if not targets:
            raise ValueError("'target' or 'targets' is required for httpx")
        for t in targets:
            self._check_scope(t)
        return {"targets": targets, "follow_redirects": bool(args.get("follow_redirects", True))}

    async def execute(self, args: dict[str, Any]) -> str:
        from clinkz.config import settings

        targets_str = "\n".join(args["targets"])

        cmd = [
            "httpx",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
            "-silent",
        ]
        if args.get("follow_redirects"):
            cmd.append("-follow-redirects")

        if settings.tool_exec_mode == "docker":
            # In docker mode, pipe targets via stdin instead of a temp file
            # (temp files on the host are not accessible inside the container).
            stdout, stderr, _ = await self._run_subprocess_stdin(cmd, targets_str)
        else:
            import pathlib
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(targets_str)
                tmp = f.name
            cmd.extend(["-l", tmp])
            stdout, stderr, _ = await self._run_subprocess(cmd)
            pathlib.Path(tmp).unlink(missing_ok=True)

        return stdout or stderr

    def parse_output(self, raw_output: str) -> HttpxOutput:
        """Parse httpx JSON-lines output into HttpxResult models.

        Handles the real httpx JSON field names (status-code, content-length
        with hyphens; technologies as the primary tech list key).
        Invalid lines are silently skipped.

        Args:
            raw_output: Raw JSONL stdout from httpx -json -silent.

        Returns:
            HttpxOutput with one HttpxResult per successfully probed URL.
        """
        if not raw_output or not raw_output.strip():
            return HttpxOutput(tool_name=self.name, success=False, raw_output=raw_output)
        results = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append(
                HttpxResult(
                    url=data.get("url", ""),
                    status_code=data.get("status-code", data.get("status_code", 0)),
                    title=data.get("title", ""),
                    tech=data.get("technologies", data.get("tech", [])),
                    content_length=data.get("content-length", data.get("content_length", 0)),
                    webserver=data.get("webserver", ""),
                )
            )
        return HttpxOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
        )
