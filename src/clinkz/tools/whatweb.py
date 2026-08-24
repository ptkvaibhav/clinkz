"""WhatWeb tool wrapper — web technology fingerprinting.

Sample fixture: tests/fixtures/whatweb_output.json
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from clinkz.tools.base import DetectedComponent, ToolBase, ToolOutput
from clinkz.tools.component_names import split_name_version

#: WhatWeb plugin names that describe the OBSERVATION rather than name a piece
#: of software, mapped to why. Every plugin hit used to become a
#: ``DetectedComponent``, so a DVWA run inventoried 14 "components" of which 11
#: were these: ``Country``, ``IP``, ``Title``, ``HttpOnly``, ``PasswordField``.
#: ``DetectedComponent`` is documented as "one **software** component", so the
#: wrapper was breaking its own model's contract, and the result reached the
#: client-facing inventory — a report that calls ``Country`` a component is
#: wrong in a way a reader notices immediately.
#:
#: Default-**allow**: a plugin absent from this table is treated as software.
#: WhatWeb ships ~1,800 plugins and adds more, so an allow-list would silently
#: drop a real product the day it gained a plugin — and the two failure
#: directions are not symmetric. A spurious metadata row is noise in a report; a
#: dropped product is a missing CVE lookup, which is the whole reason the
#: fingerprint feeds ``knowledge/component_cves.py``.
_NON_COMPONENT_PLUGINS: dict[str, str] = {
    "country": "geolocation of the target's address, a property of the IP",
    "ip": "the resolved address itself",
    "title": "the page's <title> text",
    "cookies": "the NAMES of cookies the response set",
    "httponly": "a flag on a cookie",
    "passwordfield": "an <input type=password> was present on the page",
    "redirectlocation": "the value of the Location header",
    "email": "an address scraped out of the page body",
    "script": "a <script> element was present",
    "frame": "a frame or iframe was present",
    "html5": "a doctype declaration, not a shipped component",
    "meta-author": "the author meta tag's text",
    "meta-refresh-redirect": "a refresh meta tag was present",
    "uncommonheaders": "the names of headers whatweb did not recognise",
    "x-frame-options": "a security header's presence",
    "x-content-type-options": "a security header's presence",
    "x-xss-protection": "a security header's presence",
    "strict-transport-security": "a security header's presence",
    "content-security-policy": "a security header's presence",
    "access-control-allow-origin": "a CORS header's presence",
}

#: Plugins whose hit is a HEADER ECHO: the plugin name is the header, and the
#: software is inside the value. Emitting the plugin name gave the inventory
#: ``HTTPServer`` and ``X-Powered-By`` as products with no version, while
#: whatweb's own ``Apache`` and ``PHP`` plugins reported the same software
#: correctly alongside. Resolved through the shared name/version split instead
#: of dropped, so the software survives even on a target where only the header
#: fired — dedup then collapses it against the product plugin's entry.
_HEADER_ECHO_PLUGINS: frozenset[str] = frozenset({"httpserver", "x-powered-by"})

#: A trailing packager parenthetical — ``Apache/2.4.67 (Debian)``. The shared
#: splitter reads the last whitespace-separated token, so ``(Debian)`` defeats
#: it and the whole string stays a name. Stripped before splitting, never after.
_TRAILING_PAREN_RE = re.compile(r"\s*\([^()]*\)\s*$")


class WhatWebScanResult(BaseModel):
    """Fingerprint result for a single URL."""

    target: str
    http_status: int = 0
    technologies: list[str] = []  # plugin names detected
    versions: dict[str, str] = {}  # plugin name -> first version string
    server: str = ""  # value of the HTTPServer plugin
    #: Header-echo plugin name -> the raw string it carried, retained so the
    #: software inside the value can be resolved rather than the header name
    #: being reported as a product. Keyed as whatweb spelled it.
    header_software: dict[str, str] = {}


class WhatWebOutput(ToolOutput):
    """Structured output from WhatWeb."""

    results: list[WhatWebScanResult] = []
    technologies: dict[str, list[str]] = {}  # url -> list of tech names

    def detected_components(self) -> list[DetectedComponent]:
        """Every SOFTWARE plugin hit, carrying its version where WhatWeb has one.

        ``versions`` has been parsed since this wrapper was written and consumed
        by nothing: the recon seam read technology NAMES only, so a version
        WhatWeb had already told us sat in the model unread and no engagement
        could test a dependency against a known CVE. The version is part of the
        observation, so it is part of what the producer declares.

        Not every plugin hit is a component, and this used to emit all of them.
        WhatWeb's plugin set mixes product identification with observations
        about the response — ``Country``, ``IP``, ``Title``, ``HttpOnly``,
        ``PasswordField`` — and 11 of the 14 "components" a DVWA run inventoried
        were of that second kind. Two filters, both keyed on WhatWeb's own
        vocabulary, which is this wrapper's business to know:

        * :data:`_NON_COMPONENT_PLUGINS` drops the observations, each with a
          stated reason. Default-allow, so an unrecognised plugin is still a
          component and no product is lost silently.
        * :data:`_HEADER_ECHO_PLUGINS` resolves the software out of the header
          VALUE, so ``X-Powered-By: PHP/8.5.6`` contributes ``PHP 8.5.6``
          rather than a product called ``X-Powered-By`` with no version.

        Dedup is unchanged and does the rest: a resolved header echo collapses
        against the dedicated product plugin's entry when both fired.

        Nothing is dropped from ``results`` — ``technologies`` still lists every
        plugin hit, so the raw observation stays auditable.
        """
        seen: set[tuple[str, str]] = set()
        components: list[DetectedComponent] = []
        for result in self.results:
            for tech in result.technologies:
                name = (tech or "").strip()
                if not name:
                    continue
                key_name = name.lower()
                if key_name in _NON_COMPONENT_PLUGINS:
                    continue
                version = (result.versions.get(name) or "").strip()
                if key_name in _HEADER_ECHO_PLUGINS:
                    echoed = (result.header_software.get(name) or "").strip()
                    if not echoed:
                        # The header fired with no value we retained. Reporting
                        # the header NAME as a product is what this branch
                        # exists to stop, so contribute nothing rather than a
                        # component called "X-Powered-By".
                        continue
                    name, echoed_version = split_name_version(
                        _TRAILING_PAREN_RE.sub("", echoed).strip()
                    )
                    name = name.strip()
                    if not name:
                        continue
                    version = version or echoed_version
                    key_name = name.lower()
                key = (key_name, version)
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
            header_software: dict[str, str] = {}
            server = ""

            for plugin_name, plugin_data in plugins.items():
                tech_names.append(plugin_name)
                if isinstance(plugin_data, dict):
                    version_list = plugin_data.get("version", [])
                    if version_list:
                        versions[plugin_name] = version_list[0]
                    if plugin_name.lower() in _HEADER_ECHO_PLUGINS:
                        # The header's VALUE, retained so ``detected_components``
                        # can name the software inside it rather than the header.
                        strings = plugin_data.get("string", [])
                        if strings:
                            header_software[plugin_name] = str(strings[0])
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
                    header_software=header_software,
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
