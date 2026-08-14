"""WhatWeb tool wrapper — web technology fingerprinting.

Sample fixture: tests/fixtures/whatweb_output.json
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import DetectedComponent, ToolBase, ToolOutput


class WhatWebScanResult(BaseModel):
    """Fingerprint result for a single URL."""

    target: str
    http_status: int = 0
    technologies: list[str] = []  # plugin names detected
    versions: dict[str, str] = {}  # plugin name -> first version string
    server: str = ""  # value of the HTTPServer plugin


class WhatWebOutput(ToolOutput):
    """Structured output from WhatWeb."""

    results: list[WhatWebScanResult] = []
    technologies: dict[str, list[str]] = {}  # url -> list of tech names

    def detected_components(self) -> list[DetectedComponent]:
        """Every plugin hit, carrying its version where WhatWeb reported one.

        ``versions`` has been parsed since this wrapper was written and consumed
        by nothing: the recon seam read technology NAMES only, so a version
        WhatWeb had already told us sat in the model unread and no engagement
        could test a dependency against a known CVE. The version is part of the
        observation, so it is part of what the producer declares.
        """
        seen: set[tuple[str, str]] = set()
        components: list[DetectedComponent] = []
        for result in self.results:
            for tech in result.technologies:
                name = (tech or "").strip()
                if not name:
                    continue
                version = (result.versions.get(name) or "").strip()
                key = (name.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                components.append(
                    DetectedComponent(name=name, version=version, source="whatweb:plugin")
                )
        return components


#: Cap on JSON objects recovered from one interleaved blob. The plugin payloads
#: are built from response headers the TARGET chose, so the scanner's input is
#: attacker-influenced and gets a bound like every other parser here. Far above
#: any real scan: whatweb emits one object per URL it visited.
_MAX_SCAN_OBJECTS = 2000


def _top_level_json_objects(text: str, limit: int = _MAX_SCAN_OBJECTS) -> list[str]:
    """Extract balanced top-level ``{...}`` spans, ignoring everything between.

    ``--log-json=-`` does not give stdout to the JSON log alone: whatweb keeps
    writing its human-readable *brief* output to the same stream, and the two
    interleave. The real shape is an array whose elements are separated by
    ``,`` lines with the brief lines spliced in before the closing bracket::

        [
        {"target":"http://host/","http_status":302,...}
        ,
        {"target":"http://host/login.php","http_status":200,...}
        http://host/ [302 Found] Apache[2.4.67], Cookies[...], ...
        http://host/login.php [200 OK] Apache[2.4.67], DVWA, ...
        ]

    ``json.loads`` on that blob raises, so every DVWA run discarded 100% of a
    successful fingerprint — Apache 2.4.67 and PHP 8.5.6 among it — and the
    whole published-CVE path ran on an empty component inventory. The ledger
    caught it (``whatweb`` invocations=1, contributed=0) exactly as designed.

    Scanning for balanced objects rather than repairing the array handles the
    interleaved form, a clean array, NDJSON and a bare object with one rule.
    String state and backslash escapes are tracked so a brace inside a quoted
    value (a ``Title`` plugin string, say) cannot end an object early.

    Args:
        text: Raw stdout, ANSI already stripped.
        limit: Maximum objects to recover.

    Returns:
        The raw substrings, in order. Never raises — callers decide what an
        empty list means.
    """
    spans: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth == 0:
                continue  # stray brace in the brief output — not ours
            depth -= 1
            if depth == 0 and start >= 0:
                spans.append(text[start : index + 1])
                start = -1
                if len(spans) >= limit:
                    break
    return spans


class WhatWebTool(ToolBase):
    """WhatWeb technology fingerprinter.

    Runs: whatweb --aggression=<n> --log-json=- <target>
    """

    capabilities = [
        "technology_fingerprinting",
        "web_fingerprinting",
        "cms_detection",
        "web_technology_detection",
    ]
    category = "recon"

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def description(self) -> str:
        return "Identify web technologies, CMS, frameworks, and server software."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to fingerprint."},
                    "aggression": {
                        "type": "integer",
                        "description": "Aggression level 1-4 (1=passive, 3=moderate).",
                        "default": 1,
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip() or args.get("url", "").strip()
        if not target:
            raise ValueError("'target' is required for whatweb")
        self._check_scope(target)
        aggression = int(args.get("aggression", 1))
        if not 1 <= aggression <= 4:
            raise ValueError("aggression must be between 1 and 4")
        return {"target": target, "aggression": aggression}

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "whatweb",
            f"--aggression={args['aggression']}",
            "--color=never",
            "--log-json=-",
            args["target"],
        ]
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> WhatWebOutput:
        """Parse WhatWeb JSON log output into WhatWebScanResult models.

        WhatWeb outputs a JSON array via ``--log-json=-``, where each element
        represents one scanned URL and contains a ``plugins`` dict mapping
        plugin name to detected strings/versions — but it writes its brief
        human-readable log to the same stream, so the two INTERLEAVE and the
        blob as a whole is not valid JSON. Whole-blob parsing is therefore only
        the fast path; when it fails, the balanced-object scanner in
        :func:`_top_level_json_objects` recovers each element on its own. See
        that function for the shape and for what the assumption cost.

        Args:
            raw_output: Raw stdout from whatweb --log-json=-.

        Returns:
            WhatWebOutput with per-URL technology fingerprints.
        """
        if not raw_output or not raw_output.strip():
            return WhatWebOutput(tool_name=self.name, success=False, raw_output=raw_output)

        # Strip ANSI escape codes that WhatWeb emits when run inside Docker
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", raw_output)

        data: Any
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as whole_blob_error:
            data = []
            for span in _top_level_json_objects(cleaned):
                try:
                    entry = json.loads(span)
                except json.JSONDecodeError:
                    continue
                # A log element always carries ``plugins``, and that is the key
                # this parser consumes. Requiring it discriminates a scan result
                # from a brace-bearing brief line that happens to parse.
                if isinstance(entry, dict) and isinstance(entry.get("plugins"), dict):
                    data.append(entry)
            if not data:
                return WhatWebOutput(
                    tool_name=self.name,
                    success=False,
                    raw_output=raw_output,
                    error=f"JSON parse error: {whole_blob_error}",
                )

        # Normalise: accept both a JSON array and a single object
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return WhatWebOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error="Unexpected JSON structure — expected array of scan results",
            )

        results: list[WhatWebScanResult] = []
        technologies_map: dict[str, list[str]] = {}

        for entry in data:
            if not isinstance(entry, dict):
                continue
            target = entry.get("target", "")
            http_status = int(entry.get("http_status", 0))
            plugins: dict[str, Any] = entry.get("plugins", {})

            tech_names: list[str] = []
            versions: dict[str, str] = {}
            server = ""

            for plugin_name, plugin_data in plugins.items():
                tech_names.append(plugin_name)
                if isinstance(plugin_data, dict):
                    version_list = plugin_data.get("version", [])
                    if version_list:
                        versions[plugin_name] = version_list[0]
                    if plugin_name == "HTTPServer":
                        strings = plugin_data.get("string", [])
                        if strings:
                            server = strings[0]

            results.append(
                WhatWebScanResult(
                    target=target,
                    http_status=http_status,
                    technologies=tech_names,
                    versions=versions,
                    server=server,
                )
            )
            technologies_map[target] = tech_names

        return WhatWebOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=results,
            technologies=technologies_map,
        )
