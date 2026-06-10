"""SPA / API route discovery — pluggable discoverers behind a common seam.

Modern single-page apps (Angular/React/Vue) invoke their real surface
(``/api/...``, ``/rest/...``, fragment routes) from JavaScript at runtime;
those routes are not present as HTML links, so an HTML crawler (and even
katana's ``-jc`` JS pass) under-reports them — notably the concatenation-built
param routes a methodology needs (``/rest/products/search?q=``, ``/rest/basket/:id``).

This module recovers those routes deterministically from sources that do not
require a browser:

* :class:`StaticBundleDiscoverer` — fetch the SPA shell, pull its ``<script src>``
  bundles, and regex-extract route-shaped string literals (anchored on the
  ``api``/``rest`` prefixes and a tight set of known top-level routes), with
  path/query param structure.
* :class:`OpenAPIDiscoverer` — probe conventional spec locations
  (``/openapi.json``, ``/v3/api-docs``, …); when a real JSON spec is present it
  is the richest, most reliable source. Falls back to a tight conventional
  JSON-API-root probe when no spec is served.

The discoverers run behind the :class:`RouteDiscoverer` protocol and are unioned
by :func:`run_route_discovery`. This is the **seam**: a future
``HeadlessDiscoverer`` (driving a real browser to observe XHR/fetch traffic) is
just another protocol implementation added to the list — no other code changes.
A headless discoverer is intentionally **not** implemented here and this module
takes **no browser dependency**.

Design constraints (safety — these process attacker-controllable response
bodies):

* Extraction is **regex/JSON only** — never ``eval`` or any code execution.
* Fetching is **bounded**: a capped number of bundles, a capped byte budget per
  bundle, and a capped number of spec paths, so a hostile or pathological target
  cannot blow up memory or time.
* Bundle ``<script src>`` URLs are restricted to the **same origin** as the base
  URL (defence-in-depth against SSRF, on top of the tool layer's scope check).
* A SPA typically answers ``200 + index.html`` for *any* path, so spec/known-root
  probing never trusts a status code alone — it requires a JSON content-type and
  a parseable JSON body (with an ``openapi``/``swagger`` key for specs).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit, urlunsplit

from clinkz.agents._url_safety import is_state_changing_url
from clinkz.models.scan import Endpoint, ParamLocation

logger = logging.getLogger(__name__)

# --- Bounds (safety: untrusted response bodies) ----------------------------
_MAX_BUNDLES = 12  # JS bundles fetched per shell (shell scripts + chunk refs)
_MAX_BUNDLE_BYTES = 6_000_000  # bytes of each bundle scanned for routes
_MAX_SPEC_BYTES = 5_000_000  # max spec body parsed as JSON
_MAX_SPEC_PATHS = 1000  # max paths read from one spec
_MAX_ROUTES = 600  # max routes a single discoverer may emit
_MAX_SCHEMA_DEPTH = 6  # max $ref/allOf recursion when reading a body schema (cycle guard)
_MAX_BODY_PARAMS = 50  # max body field names read from one operation's requestBody

# --- Route shape ------------------------------------------------------------
# Distinctive top-level routes that are not under /api or /rest but matter
# (the alternation is anchored by quotes + a continuation that must be a path
# separator / query / closing quote, so it will not fire on substrings such as
# "restaurant" or "redirection").
_KNOWN_TOP_ROUTES = ("redirect", "ftp", "b2b", "dataerasure", "snippets")

# Route-shaped tokens inside JS. Anchored on a left boundary (so "restaurant"
# / "redirection" are not matched) and able to start mid-literal (so an
# interpolated template such as ``${host}/rest/basket/${id}`` still yields
# ``/rest/basket/``). ``api``/``rest`` must be followed by a ``/resource``; a
# known top-level route must be followed by ``/`` or ``?`` or a closing quote.
_ROUTE_CHARS = r"A-Za-z0-9_./{}:?=&%\-"
_ROUTE_RE: re.Pattern[str] = re.compile(
    r"""(?<![A-Za-z0-9_$])"""
    r"""(?P<route>"""
    rf"""/?(?:api|rest)/[{_ROUTE_CHARS}]*"""
    rf"""|/?(?:{"|".join(_KNOWN_TOP_ROUTES)})(?:[/?][{_ROUTE_CHARS}]*|(?=['\"`]))"""
    r""")""",
)

# Capture the ``src`` of every <script> tag (we filter to same-origin .js below).
_SCRIPT_SRC_RE: re.Pattern[str] = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Quoted ``.js`` filename literals inside a bundle — webpack/vite split chunks.
_JS_CHUNK_RE: re.Pattern[str] = re.compile(r"""['"]([\w./\-]+\.js)['"]""")

# Conventional spec locations, richest first.
_SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs/swagger.json",
    "/api/openapi.json",
)

# Tight set of conventional JSON-API roots, probed only when no spec is served.
# Kept deliberately small — this is a complement, not a fuzz list.
_KNOWN_API_ROOTS = (
    "/rest/products",
    "/rest/user/whoami",
    "/api/Products",
    "/api/Users",
    "/api/Feedbacks",
    "/api/Challenges",
)

# Conventional JSON-POST mutation endpoints and their body field names, probed
# ONLY when no OpenAPI spec is served (OpenAPI is the richer source). This is
# the PART-2 fallback: many SPAs (notably Juice Shop, whose served spec is just
# Swagger-UI HTML + a partial /b2b/v2 doc) expose no parseable spec, so the
# body shape a state-changing methodology needs cannot be harvested from one.
# Each entry is gated on a cheap GET that proves the route exists (status !=
# 404) before a POST endpoint is emitted, so it never invents a phantom route
# on a target that lacks these conventional paths. Kept deliberately tight —
# a complement to OpenAPI, not a fuzz list.
_KNOWN_JSON_POST_BODIES: dict[str, tuple[str, ...]] = {
    "/rest/user/login": ("email", "password"),
    "/api/Feedbacks": ("comment", "rating"),
    "/api/Users": ("email", "password"),  # self-registration
}


@dataclass(frozen=True)
class FetchResult:
    """Outcome of a single GET performed by a :data:`FetchFn`.

    ``headers`` keys are expected lowercased by the caller so content-type
    lookups are case-insensitive.
    """

    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


# A session-carrying GET of an absolute URL. Returns ``None`` on any failure
# (network error, out-of-scope/refused, etc.) so a discoverer never raises on
# a single bad fetch.
FetchFn = Callable[[str], Awaitable["FetchResult | None"]]


@runtime_checkable
class RouteDiscoverer(Protocol):
    """A source of routes for a web target.

    Implementations are pure with respect to I/O: all network access goes
    through the injected :data:`FetchFn`, which carries the engagement session.
    This keeps discoverers trivially unit-testable with a fake fetch and lets a
    future headless discoverer slot in without touching the rest of the system.
    """

    name: str

    async def discover(self, base_url: str, fetch: FetchFn) -> list[Endpoint]:
        """Return discovered endpoints for *base_url* using *fetch*."""
        ...


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _same_origin(url: str, base_url: str) -> bool:
    """True if *url* resolves to the same scheme+host+port as *base_url*."""
    a = urlsplit(urljoin(base_url, url))
    b = urlsplit(base_url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _looks_like_json(res: FetchResult) -> bool:
    """True if a response is plausibly a JSON document (not a SPA 200 shell)."""
    ct = (res.headers.get("content-type") or "").lower()
    if "json" in ct:
        return True
    body = (res.body or "").lstrip()
    return body[:1] in ("{", "[")


def _route_to_endpoint(raw: str, base_url: str) -> Endpoint | None:
    """Normalise one extracted route string into an :class:`Endpoint`.

    Encodes param structure the way the Exploit side consumes it:

    * **Path params** are kept as ``:name`` segments in the URL path
      (``{id}`` → ``:id``; a trailing-slash collection route → ``:id``), so the
      Exploit URL builder substitutes them into the path.
    * **Query params** are carried in ``Endpoint.params`` only (the query string
      is dropped from the URL), so they are appended as ``?name=`` when probed.

    Returns ``None`` for routes that are too short to be a real surface
    (bare ``/api`` / ``/rest``) or that resolve off-origin.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    path_and_query = raw if raw.startswith("/") else "/" + raw
    parsed = urlsplit(urljoin(base_url, path_and_query))
    if (parsed.scheme, parsed.hostname, parsed.port) != (
        urlsplit(base_url).scheme,
        urlsplit(base_url).hostname,
        urlsplit(base_url).port,
    ):
        return None

    path = parsed.path
    # Reject bare prefixes (need at least one resource segment).
    stripped = path.strip("/")
    if not stripped or stripped in ("api", "rest"):
        return None

    # Query param names.
    query_params: list[str] = []
    if parsed.query:
        for pair in parsed.query.split("&"):
            key = pair.split("=", 1)[0]
            if key:
                query_params.append(key)

    # Path params: {name}/:name segments, plus a trailing-slash → :id collection.
    path_params: list[str] = []
    norm_segments: list[str] = []
    for seg in path.split("/"):
        if len(seg) > 2 and seg.startswith("{") and seg.endswith("}"):
            name = seg[1:-1]
            path_params.append(name)
            norm_segments.append(":" + name)
        elif len(seg) > 1 and seg.startswith(":"):
            path_params.append(seg[1:])
            norm_segments.append(seg)
        else:
            norm_segments.append(seg)
    norm_path = "/".join(norm_segments)
    # A multi-segment route ending in "/" is a collection whose item id is
    # concatenated at runtime (e.g. "rest/basket/" + id) — model it as :id.
    if norm_path.endswith("/") and norm_path.count("/") >= 3:
        norm_path = norm_path + ":id"
        path_params.append("id")

    seen: set[str] = set()
    params: list[str] = []
    for name in (*path_params, *query_params):
        if name and name not in seen:
            seen.add(name)
            params.append(name)

    url = urlunsplit((parsed.scheme, parsed.netloc, norm_path, "", ""))
    return Endpoint(url=url, method="GET", params=params)


def _structural_key(ep: Endpoint) -> str:
    """Identity ignoring param values — (method, scheme://host/path, params)."""
    parsed = urlsplit(ep.url)
    method = (ep.method or "GET").upper()
    names = ",".join(sorted(ep.params or []))
    return f"{method} {parsed.scheme}://{parsed.netloc}{parsed.path}?{names}"


# ---------------------------------------------------------------------------
# Static bundle discoverer
# ---------------------------------------------------------------------------


class StaticBundleDiscoverer:
    """Recover routes from a SPA's static JavaScript bundles."""

    name = "static_bundle"

    async def discover(self, base_url: str, fetch: FetchFn) -> list[Endpoint]:
        shell = await fetch(base_url)
        if shell is None or not shell.body:
            return []

        # Breadth-first over bundles: start from the shell's <script src>
        # bundles, then follow same-origin .js chunk references found inside
        # them (webpack/vite split chunks hold lazy-route service calls). The
        # whole walk is bounded by _MAX_BUNDLES fetched bundles.
        queue: list[str] = self._bundle_urls(shell.body, base_url)
        visited: set[str] = set()
        endpoints: list[Endpoint] = []
        seen: set[str] = set()
        while queue and len(visited) < _MAX_BUNDLES:
            bundle_url = queue.pop(0)
            if bundle_url in visited:
                continue
            visited.add(bundle_url)
            res = await fetch(bundle_url)
            if res is None or not res.body:
                continue
            body = res.body[:_MAX_BUNDLE_BYTES]
            for raw in self._extract_routes(body):
                ep = _route_to_endpoint(raw, base_url)
                if ep is None:
                    continue
                key = _structural_key(ep)
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(ep)
                if len(endpoints) >= _MAX_ROUTES:
                    return endpoints
            for chunk in self._chunk_urls(body, base_url):
                if chunk not in visited:
                    queue.append(chunk)
        return endpoints

    @staticmethod
    def _bundle_urls(html: str, base_url: str) -> list[str]:
        """Same-origin ``.js`` script URLs referenced by the shell, in order."""
        return StaticBundleDiscoverer._dedupe_js_urls(
            (m.group(1) for m in _SCRIPT_SRC_RE.finditer(html)), base_url
        )

    @staticmethod
    def _chunk_urls(js: str, base_url: str) -> list[str]:
        """Same-origin ``.js`` chunk filenames referenced inside a bundle body."""
        return StaticBundleDiscoverer._dedupe_js_urls(
            (m.group(1) for m in _JS_CHUNK_RE.finditer(js)), base_url
        )

    @staticmethod
    def _dedupe_js_urls(candidates, base_url: str) -> list[str]:
        """Resolve, same-origin-filter, and dedupe ``.js`` URL candidates."""
        urls: list[str] = []
        seen: set[str] = set()
        for raw in candidates:
            src = (raw or "").strip()
            if not src or src.startswith(("data:", "javascript:")):
                continue
            absolute = urljoin(base_url, src)
            if ".js" not in urlsplit(absolute).path.lower():
                continue
            if not _same_origin(absolute, base_url):
                continue
            if absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)
        return urls

    @staticmethod
    def _extract_routes(js: str) -> list[str]:
        """Route-shaped tokens from a JS body (deduped, order-stable)."""
        out: list[str] = []
        seen: set[str] = set()
        for match in _ROUTE_RE.finditer(js):
            # Strip trailing query punctuation but preserve a trailing "/" — it
            # signals a collection whose item id is concatenated at runtime.
            route = (match.group("route") or "").rstrip("?&=")
            if route and route not in seen:
                seen.add(route)
                out.append(route)
        return out


# ---------------------------------------------------------------------------
# OpenAPI / known-routes discoverer
# ---------------------------------------------------------------------------


class OpenAPIDiscoverer:
    """Parse an OpenAPI/Swagger spec when served; else probe known JSON roots."""

    name = "openapi"

    async def discover(self, base_url: str, fetch: FetchFn) -> list[Endpoint]:
        for spec_path in _SPEC_PATHS:
            res = await fetch(urljoin(base_url, spec_path.lstrip("/")))
            if res is None or res.status != 200:
                continue
            spec = self._parse_spec(res)
            if spec is None:
                continue
            endpoints = self._endpoints_from_spec(spec, base_url)
            if endpoints:
                return endpoints
        # No parseable spec: fall back to conventional GET roots plus the
        # curated JSON-POST body probe (the only source of body params when no
        # spec is served — e.g. on Juice Shop).
        roots = await self._probe_known_roots(base_url, fetch)
        post_bodies = await self._probe_known_post_bodies(base_url, fetch)
        return roots + post_bodies

    @staticmethod
    def _parse_spec(res: FetchResult) -> dict | None:
        """Return the spec dict iff *res* is a real OpenAPI/Swagger JSON doc.

        Guards the SPA-200 trap: a JSON content-type (or a JSON-shaped body) is
        required, the body must parse, and an ``openapi``/``swagger`` key must
        be present.
        """
        if not _looks_like_json(res):
            return None
        body = res.body or ""
        if len(body) > _MAX_SPEC_BYTES:
            return None
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        if "openapi" not in data and "swagger" not in data:
            return None
        return data

    @classmethod
    def _endpoints_from_spec(cls, spec: dict, base_url: str) -> list[Endpoint]:
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return []
        endpoints: list[Endpoint] = []
        seen: set[str] = set()
        for raw_path, item in list(paths.items())[:_MAX_SPEC_PATHS]:
            if not isinstance(raw_path, str) or not isinstance(item, dict):
                continue
            methods = [m for m in ("get", "post", "put", "patch", "delete") if m in item]
            if not methods:
                methods = ["get"]
            for method in methods:
                op = item.get(method)
                op = op if isinstance(op, dict) else {}
                names, locations, content_type = cls._spec_param_model(raw_path, item, op, spec)
                ep = cls._spec_endpoint(raw_path, method, names, locations, content_type, base_url)
                if ep is None:
                    continue
                key = _structural_key(ep)
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(ep)
                if len(endpoints) >= _MAX_ROUTES:
                    return endpoints
        return endpoints

    @classmethod
    def _spec_param_model(
        cls, raw_path: str, item: dict, op: dict, spec: dict
    ) -> tuple[list[str], dict[str, ParamLocation], str | None]:
        """Param names + per-name location + request content-type for an operation.

        Sources, in precedence order (first location for a name wins):

        * Path templating ``{name}`` in the route → :attr:`ParamLocation.PATH`.
        * Declared ``parameters`` with ``in: path|query`` (OpenAPI 3 and
          Swagger 2) → ``PATH`` / ``QUERY``.
        * Swagger-2 ``in: body`` / ``in: formData`` parameters.
        * OpenAPI-3 ``requestBody`` schema properties → ``JSON_BODY`` (for a
          JSON media type) or ``FORM_BODY`` (form-urlencoded / multipart).

        The returned ``content_type`` is the body media type (e.g.
        ``application/json``) so the Exploit-side builder serializes the body
        correctly; it is ``None`` for body-less endpoints.
        """
        names: list[str] = []
        locations: dict[str, ParamLocation] = {}
        content_type: str | None = None

        def _add(name: object, location: ParamLocation) -> None:
            if isinstance(name, str) and name and name not in locations:
                names.append(name)
                locations[name] = location

        for seg in raw_path.split("/"):
            if len(seg) > 2 and seg.startswith("{") and seg.endswith("}"):
                _add(seg[1:-1], ParamLocation.PATH)

        for source in (item.get("parameters"), op.get("parameters")):
            if not isinstance(source, list):
                continue
            for param in source:
                if not isinstance(param, dict):
                    continue
                where = param.get("in")
                if where == "path":
                    _add(param.get("name"), ParamLocation.PATH)
                elif where == "query":
                    _add(param.get("name"), ParamLocation.QUERY)
                elif where == "formData":  # Swagger 2.0 form field
                    _add(param.get("name"), ParamLocation.FORM_BODY)
                    content_type = content_type or "application/x-www-form-urlencoded"
                elif where == "body":  # Swagger 2.0 body param (schema-shaped)
                    for prop in cls._schema_property_names(param.get("schema"), spec):
                        _add(prop, ParamLocation.JSON_BODY)
                    content_type = content_type or "application/json"

        # OpenAPI 3 requestBody (richest source for a JSON API mutation).
        body_props, body_ct = cls._spec_request_body(op, spec)
        if body_props:
            body_location = (
                ParamLocation.JSON_BODY
                if (body_ct or "").lower().find("json") != -1
                else ParamLocation.FORM_BODY
            )
            for prop in body_props:
                _add(prop, body_location)
            content_type = content_type or body_ct

        return names, locations, content_type

    @classmethod
    def _spec_request_body(cls, op: dict, spec: dict) -> tuple[list[str], str | None]:
        """Body field names + media type from an OpenAPI-3 ``requestBody``.

        Prefers ``application/json``, then form-urlencoded, then the first
        declared media type. Returns ``([], None)`` when no requestBody is
        present or its schema yields no property names.
        """
        request_body = op.get("requestBody")
        if not isinstance(request_body, dict):
            return [], None
        content = request_body.get("content")
        if not isinstance(content, dict):
            return [], None
        chosen_ct: str | None = None
        for preferred in ("application/json", "application/x-www-form-urlencoded"):
            if preferred in content:
                chosen_ct = preferred
                break
        if chosen_ct is None:
            for ct in content:
                if isinstance(ct, str):
                    chosen_ct = ct
                    break
        if chosen_ct is None:
            return [], None
        media = content.get(chosen_ct)
        schema = media.get("schema") if isinstance(media, dict) else None
        return cls._schema_property_names(schema, spec), chosen_ct

    @classmethod
    def _schema_property_names(cls, schema: object, spec: dict, _depth: int = 0) -> list[str]:
        """Top-level property names of a (possibly ``$ref``'d) object schema.

        Resolves local ``$ref`` pointers and merges ``allOf`` / ``oneOf`` /
        ``anyOf`` member schemas. Recursion is bounded by ``_MAX_SCHEMA_DEPTH``
        (cycle guard) and the result by ``_MAX_BODY_PARAMS``. Only local
        ``#/...`` refs are followed — never a remote URL — so a hostile spec
        cannot drive an out-of-band fetch (SSRF). Pure dict traversal, no eval.
        """
        if not isinstance(schema, dict) or _depth > _MAX_SCHEMA_DEPTH:
            return []
        if "$ref" in schema:
            resolved = cls._resolve_local_ref(schema.get("$ref"), spec)
            return cls._schema_property_names(resolved, spec, _depth + 1)

        names: list[str] = []
        props = schema.get("properties")
        if isinstance(props, dict):
            names.extend(k for k in props if isinstance(k, str))
        for combiner in ("allOf", "oneOf", "anyOf"):
            members = schema.get(combiner)
            if isinstance(members, list):
                for member in members:
                    names.extend(cls._schema_property_names(member, spec, _depth + 1))

        # Dedupe (order-stable) and bound.
        return list(dict.fromkeys(names))[:_MAX_BODY_PARAMS]

    @staticmethod
    def _resolve_local_ref(ref: object, spec: dict) -> dict | None:
        """Resolve a local ``#/a/b/c`` JSON-pointer ref against *spec*.

        Returns ``None`` for non-string refs, remote/URL refs (anything not
        starting with ``#/``), or pointers that don't resolve to a dict — the
        remote-ref rejection is the SSRF guard.
        """
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None
        node: object = spec
        for part in ref[2:].split("/"):
            # Unescape JSON-pointer tokens (~1 -> /, ~0 -> ~).
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node if isinstance(node, dict) else None

    @staticmethod
    def _spec_endpoint(
        raw_path: str,
        method: str,
        params: list[str],
        locations: dict[str, ParamLocation],
        content_type: str | None,
        base_url: str,
    ) -> Endpoint | None:
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        norm_path = re.sub(r"\{([^{}/]+)\}", r":\1", raw_path)
        parsed = urlsplit(urljoin(base_url, norm_path))
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if not parsed.path.strip("/"):
            return None
        return Endpoint(
            url=url,
            method=method.upper(),
            params=params,
            content_type=content_type,
            param_locations=locations,
        )

    @staticmethod
    async def _probe_known_roots(base_url: str, fetch: FetchFn) -> list[Endpoint]:
        """Probe a tight conventional-root set; keep only JSON responders."""
        endpoints: list[Endpoint] = []
        seen: set[str] = set()
        for root in _KNOWN_API_ROOTS:
            res = await fetch(urljoin(base_url, root.lstrip("/")))
            if res is None:
                continue
            # 2xx/401/403 + JSON => a real API endpoint exists (auth or not).
            # A SPA shell answers text/html and is rejected by _looks_like_json.
            if res.status not in (200, 201, 401, 403):
                continue
            if not _looks_like_json(res):
                continue
            ep = _route_to_endpoint(root, base_url)
            if ep is None:
                continue
            key = _structural_key(ep)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(ep)
        return endpoints

    @staticmethod
    async def _probe_known_post_bodies(base_url: str, fetch: FetchFn) -> list[Endpoint]:
        """Emit curated JSON-POST endpoints with body params, gated on existence.

        For each conventional mutation endpoint in :data:`_KNOWN_JSON_POST_BODIES`,
        a cheap GET confirms the route exists on this target before a POST
        :class:`Endpoint` is emitted with its body fields marked ``json_body``
        and ``content_type=application/json``, so the state-changing
        methodologies (brute-force, CSRF, stored-XSS) can reach the body
        injection point even with no served spec.

        Existence test (SPA-200 safe): a SPA shell answers ``200 + text/html``
        to *any* path, so a bare 200 is not proof a route exists. A route is
        accepted only when the GET returns JSON (``_looks_like_json``) *or* a
        non-200, non-404 status (401/403/405/500 — the route exists but rejects
        the GET method/auth). A 200 that is not JSON is treated as the SPA
        catch-all and skipped, so no phantom endpoint is invented on a SPA or a
        target lacking these conventional paths.
        """
        endpoints: list[Endpoint] = []
        seen: set[str] = set()
        for path, fields in _KNOWN_JSON_POST_BODIES.items():
            res = await fetch(urljoin(base_url, path.lstrip("/")))
            if res is None or res.status == 404:
                continue  # route absent / unreachable — do not emit a phantom
            if res.status == 200 and not _looks_like_json(res):
                continue  # SPA-200 catch-all, not a real API route
            parsed = urlsplit(urljoin(base_url, path.lstrip("/")))
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            ep = Endpoint(
                url=url,
                method="POST",
                params=list(fields),
                content_type="application/json",
                param_locations=dict.fromkeys(fields, ParamLocation.JSON_BODY),
            )
            key = _structural_key(ep)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(ep)
        return endpoints


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def default_discoverers() -> list[RouteDiscoverer]:
    """The discoverers run by default, richest-source-last for union stability."""
    return [StaticBundleDiscoverer(), OpenAPIDiscoverer()]


async def run_route_discovery(
    base_url: str,
    fetch: FetchFn,
    discoverers: list[RouteDiscoverer] | None = None,
    log: logging.Logger | None = None,
) -> list[Endpoint]:
    """Run *discoverers* in sequence, union, and dedupe their endpoints.

    Each discoverer is isolated: a failure in one is logged and skipped, never
    aborting the rest. The union is the single chokepoint that drops
    state-changing routes (``is_state_changing_url`` — logout / WAF toggles) so
    the shared engagement session is never poisoned, and dedupes by structural
    identity (method + path + param names, ignoring values).
    """
    log = log or logger
    discoverers = discoverers if discoverers is not None else default_discoverers()

    collected: list[Endpoint] = []
    for discoverer in discoverers:
        try:
            found = await discoverer.discover(base_url, fetch)
        except Exception as exc:  # noqa: BLE001 — one bad discoverer must not abort the rest
            log.warning("Route discoverer %s failed: %s", getattr(discoverer, "name", "?"), exc)
            continue
        if found:
            collected.extend(found)

    unique: list[Endpoint] = []
    seen: set[str] = set()
    for ep in collected:
        if is_state_changing_url(ep.url):
            continue
        key = _structural_key(ep)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ep)

    log.info(
        "Route discovery: %d unique endpoint(s) from %d discoverer(s)",
        len(unique),
        len(discoverers),
    )
    return unique
