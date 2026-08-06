"""Unit tests for SPA/API route discovery (keyless — fake fetch, no network).

Covers the three deliverables of fix #2: static JS-bundle extraction with param
structure, OpenAPI/known-routes probing with the SPA-200 guard, and the
discoverer seam (union + dedupe + state-changing filter). Also covers the
Exploit-side path-param substitution shim that makes the discovered template
routes (``/rest/basket/:id``) actually probeable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from clinkz.agents._route_discovery import (
    FetchResult,
    OpenAPIDiscoverer,
    RouteDiscoverer,
    StaticBundleDiscoverer,
    run_route_discovery,
)
from clinkz.agents.exploit import ExploitAgent
from clinkz.models.scan import Endpoint, ParamLocation

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
_BUNDLE_JS = (_FIXTURES / "juiceshop_main.js").read_text(encoding="utf-8")
_OPENAPI_SPEC = (_FIXTURES / "openapi_sample.json").read_text(encoding="utf-8")

BASE = "http://clinkz-juiceshop:3000/"

FetchFn = Callable[[str], Awaitable["FetchResult | None"]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _by_path(endpoints: list[Endpoint]) -> dict[str, Endpoint]:
    """Index endpoints by URL path (last write wins — fine for these fixtures)."""
    from urllib.parse import urlsplit

    return {urlsplit(ep.url).path: ep for ep in endpoints}


def _html_shell(*script_srcs: str) -> str:
    scripts = "".join(f'<script src="{s}"></script>' for s in script_srcs)
    return f"<!DOCTYPE html><html><body><app-root></app-root>{scripts}</body></html>"


def _shell_then_bundle(bundle_path: str, bundle_js: str) -> FetchFn:
    """Fetch that serves an Angular shell linking one same-origin bundle."""

    async def fetch(url: str) -> FetchResult | None:
        if url.rstrip("/") == BASE.rstrip("/"):
            return FetchResult(200, _html_shell(bundle_path), {"content-type": "text/html"})
        if url.endswith(bundle_path):
            return FetchResult(200, bundle_js, {"content-type": "application/javascript"})
        return None

    return fetch


def _url_builder():
    """Bind ExploitAgent._build_request_url without constructing the agent."""

    class _Stub:
        pass

    stub = _Stub()
    stub._resolve_path_params = ExploitAgent._resolve_path_params  # staticmethod
    return ExploitAgent._build_request_url.__get__(stub, _Stub)


# ---------------------------------------------------------------------------
# Static bundle discoverer
# ---------------------------------------------------------------------------


async def test_bundle_discoverer_extracts_api_and_rest_routes_with_params() -> None:
    fetch = _shell_then_bundle("main.abc123.js", _BUNDLE_JS)
    endpoints = await StaticBundleDiscoverer().discover(BASE, fetch)
    by_path = _by_path(endpoints)

    # The two routes katana's -jc misses (concat + interpolated), with params.
    assert "/rest/products/search" in by_path
    assert by_path["/rest/products/search"].params == ["q"]
    assert "/rest/basket/:id" in by_path
    assert by_path["/rest/basket/:id"].params == ["id"]

    # Plain collection route.
    assert "/api/Feedbacks" in by_path

    # Interpolated path-param route also recovered.
    assert "/api/Products/:id" in by_path
    assert by_path["/api/Products/:id"].params == ["id"]

    # A route outside the /api and /rest prefixes is NOT this discoverer's job.
    # It used to be, via an alternation of five literal route words lifted from
    # one benchmark application; JSCallSiteDiscoverer recovers it from the
    # navigation idiom instead (see test_call_site_discoverer_finds_navigation).
    assert "/redirect" not in by_path


async def test_bundle_discoverer_rejects_word_lookalikes() -> None:
    fetch = _shell_then_bundle("main.js", _BUNDLE_JS)
    endpoints = await StaticBundleDiscoverer().discover(BASE, fetch)
    joined = " ".join(ep.url for ep in endpoints)
    # "restaurant" / "redirection" / "interesting api note" must not become routes.
    assert "restaurant" not in joined
    assert "redirection" not in joined
    assert "/interesting" not in joined


async def test_bundle_discoverer_skips_offorigin_scripts() -> None:
    """SSRF guard: only same-origin .js bundles are fetched."""
    fetched: list[str] = []

    async def fetch(url: str) -> FetchResult | None:
        fetched.append(url)
        if url.rstrip("/") == BASE.rstrip("/"):
            return FetchResult(
                200,
                _html_shell("main.js", "https://cdn.evil.com/exfil.js"),
                {"content-type": "text/html"},
            )
        if url.endswith("main.js"):
            return FetchResult(200, _BUNDLE_JS, {"content-type": "application/javascript"})
        raise AssertionError(f"unexpected fetch: {url}")

    endpoints = await StaticBundleDiscoverer().discover(BASE, fetch)
    assert not any("cdn.evil.com" in u for u in fetched)
    assert any(ep.url.endswith("/rest/products/search") for ep in endpoints)


async def test_bundle_discoverer_follows_same_origin_chunks() -> None:
    """Routes living in a referenced split chunk (not a shell <script>) are
    recovered by following same-origin .js chunk references."""

    async def fetch(url: str) -> FetchResult | None:
        if url.rstrip("/") == BASE.rstrip("/"):
            return FetchResult(200, _html_shell("main.js"), {"content-type": "text/html"})
        if url.endswith("/main.js"):
            # main references a lazy chunk; no routes itself.
            return FetchResult(
                200,
                'var routes={};__webpack_require__.e("basket.7f3a.js");'
                'loadChunk("https://cdn.evil.com/exfil.js");',
                {"content-type": "application/javascript"},
            )
        if url.endswith("/basket.7f3a.js"):
            return FetchResult(
                200,
                "this.http.get(`${h}/rest/basket/`+id);",
                {"content-type": "application/javascript"},
            )
        if "cdn.evil.com" in url:
            raise AssertionError("SSRF: off-origin chunk fetched")
        return None

    endpoints = await StaticBundleDiscoverer().discover(BASE, fetch)
    assert any(ep.url.endswith("/rest/basket/:id") for ep in endpoints)


async def test_bundle_discoverer_empty_on_plain_html() -> None:
    """A plain server-rendered page (no bundle scripts) yields nothing — the
    discoverer is additive and never disturbs the DVWA-style HTML crawl path."""

    async def fetch(url: str) -> FetchResult | None:
        return FetchResult(
            200,
            "<html><body><h1>DVWA</h1><a href='/x.php'>x</a></body></html>",
            {"content-type": "text/html"},
        )

    assert await StaticBundleDiscoverer().discover(BASE, fetch) == []


# ---------------------------------------------------------------------------
# OpenAPI / known-routes discoverer
# ---------------------------------------------------------------------------


async def test_openapi_discoverer_parses_spec_into_endpoints() -> None:
    async def fetch(url: str) -> FetchResult | None:
        if url.endswith("/openapi.json"):
            return FetchResult(200, _OPENAPI_SPEC, {"content-type": "application/json"})
        return FetchResult(404, "not found", {"content-type": "text/plain"})

    endpoints = await OpenAPIDiscoverer().discover(BASE, fetch)
    by_path = _by_path(endpoints)

    # GET /api/Users/{id} → :id path param + the `fields` query param.
    users_get = [ep for ep in endpoints if ep.url.endswith("/api/Users/:id") and ep.method == "GET"]
    assert users_get, "GET /api/Users/:id not discovered"
    assert set(users_get[0].params) == {"id", "fields"}

    assert "/rest/products/search" in by_path
    assert by_path["/rest/products/search"].params == ["q"]

    # Both declared methods on /api/Feedbacks are emitted.
    methods = {ep.method for ep in endpoints if ep.url.endswith("/api/Feedbacks")}
    assert {"GET", "POST"} <= methods


async def test_openapi_discoverer_rejects_spa_200_shell() -> None:
    """SPA-200 trap: a shell served with 200+text/html at every spec/known path
    must yield no spurious endpoints."""
    spa = FetchResult(200, "<!DOCTYPE html><app-root></app-root>", {"content-type": "text/html"})

    async def fetch(url: str) -> FetchResult | None:
        return spa

    assert await OpenAPIDiscoverer().discover(BASE, fetch) == []


async def test_no_spec_emits_nothing_rather_than_a_remembered_route_list() -> None:
    """No parseable spec → the discoverer emits NOTHING.

    It used to fall back to a hardcoded list of one benchmark application's
    endpoint names and body field names. That list reported the same surface
    whether or not the target had it, which is recall, not discovery — the
    routes and bodies now come from the target's own JavaScript instead.
    """

    async def fetch(url: str) -> FetchResult | None:
        # Every path answers the SPA shell: no spec, and no route is provable.
        return FetchResult(
            200, "<!DOCTYPE html><app-root></app-root>", {"content-type": "text/html"}
        )

    assert await OpenAPIDiscoverer().discover(BASE, fetch) == []


async def test_openapi_discoverer_extracts_json_body_params() -> None:
    """fix #4: requestBody schemas populate json_body params + content-type.

    This is the primary win that lets stored-XSS / CSRF / brute-force reach a
    JSON API's body injection points (they previously only saw HTML forms).
    """

    async def fetch(url: str) -> FetchResult | None:
        if url.endswith("/openapi.json"):
            return FetchResult(200, _OPENAPI_SPEC, {"content-type": "application/json"})
        return FetchResult(404, "not found", {"content-type": "text/plain"})

    endpoints = await OpenAPIDiscoverer().discover(BASE, fetch)

    # POST /api/Feedbacks: inline requestBody schema → comment/rating/captchaId.
    feedbacks_post = [
        ep for ep in endpoints if ep.url.endswith("/api/Feedbacks") and ep.method == "POST"
    ]
    assert feedbacks_post, "POST /api/Feedbacks not discovered"
    fb = feedbacks_post[0]
    assert fb.content_type == "application/json"
    assert fb.param_locations.get("comment") is ParamLocation.JSON_BODY
    assert fb.param_locations.get("rating") is ParamLocation.JSON_BODY
    assert {"comment", "rating", "captchaId"} <= set(fb.params)

    # POST /rest/user/login: $ref'd schema resolves to email/password.
    login = [ep for ep in endpoints if ep.url.endswith("/rest/user/login")]
    assert login, "POST /rest/user/login not discovered"
    assert login[0].method == "POST"
    assert login[0].content_type == "application/json"
    assert set(login[0].params) == {"email", "password"}
    assert all(
        login[0].param_locations[p] is ParamLocation.JSON_BODY for p in ("email", "password")
    )

    # GET /api/Feedbacks stays body-less — no false body params/content-type.
    feedbacks_get = [
        ep for ep in endpoints if ep.url.endswith("/api/Feedbacks") and ep.method == "GET"
    ]
    assert feedbacks_get and feedbacks_get[0].param_locations == {}
    assert feedbacks_get[0].content_type is None


async def test_no_discoverer_carries_a_target_specific_vocabulary() -> None:
    """The generality law, asserted against the source rather than described.

    Route discovery must never recognise an application by name. This reads the
    module's own constants and fails if any of them spell out an endpoint,
    route word, or body field belonging to a particular application — the exact
    regression that turns a general capability back into a target detector.
    """
    import clinkz.agents._route_discovery as rd

    vocabulary: list[str] = []
    for name, value in vars(rd).items():
        if name.startswith("__") or not name.isupper():
            continue
        if isinstance(value, str):
            vocabulary.append(value)
        elif isinstance(value, tuple | list):
            vocabulary.extend(str(v) for v in value)
        elif isinstance(value, dict):
            vocabulary.extend(str(k) for k in value)
            for v in value.values():
                vocabulary.extend(str(x) for x in v) if isinstance(v, tuple | list) else None

    haystack = " ".join(vocabulary).lower()
    # Names from the benchmark applications this engine is validated against.
    # None of them may appear in a constant: the engine must find these routes
    # by reading the target, or not at all.
    for forbidden in (
        "feedback",
        "basket",
        "juice",
        "dvwa",
        "b2b",
        "dataerasure",
        "snippets",
        "whoami",
        "challenges",
    ):
        assert forbidden not in haystack, (
            f"route discovery carries the target-specific token {forbidden!r} in a constant"
        )


async def test_openapi_discoverer_ignores_remote_ref_ssrf() -> None:
    """A remote ``$ref`` (URL) is never followed — SSRF guard on hostile specs."""
    spec = (
        '{"openapi":"3.0.1","info":{"title":"x","version":"1"},"paths":{'
        '"/api/Pwn":{"post":{"requestBody":{"content":{"application/json":'
        '{"schema":{"$ref":"https://evil.example/secret.json"}}}}}}}}'
    )

    async def fetch(url: str) -> FetchResult | None:
        if url.endswith("/openapi.json"):
            return FetchResult(200, spec, {"content-type": "application/json"})
        if "evil.example" in url:
            raise AssertionError("SSRF: remote $ref was fetched")
        return FetchResult(404, "not found", {"content-type": "text/plain"})

    endpoints = await OpenAPIDiscoverer().discover(BASE, fetch)
    pwn = [ep for ep in endpoints if ep.url.endswith("/api/Pwn")]
    # Endpoint still emitted (method/content-type known), but no body params
    # were harvested from the unresolved remote ref.
    assert pwn and pwn[0].method == "POST"
    assert pwn[0].params == []


# ---------------------------------------------------------------------------
# Seam: union + dedupe + isolation
# ---------------------------------------------------------------------------


class _FakeDiscoverer:
    def __init__(self, name: str, endpoints: list[Endpoint]) -> None:
        self.name = name
        self._endpoints = endpoints

    async def discover(self, base_url: str, fetch: FetchFn) -> list[Endpoint]:
        return list(self._endpoints)


class _BoomDiscoverer:
    name = "boom"

    async def discover(self, base_url: str, fetch: FetchFn) -> list[Endpoint]:
        raise RuntimeError("discoverer exploded")


async def _noop_fetch(url: str) -> FetchResult | None:
    return None


async def test_run_route_discovery_unions_dedupes_and_drops_state_changing() -> None:
    a = _FakeDiscoverer(
        "a",
        [
            Endpoint(url=f"{BASE}rest/products/search", method="GET", params=["q"]),
            Endpoint(url=f"{BASE}rest/user/logout", method="GET"),  # state-changing
        ],
    )
    b = _FakeDiscoverer(
        "b",
        [
            Endpoint(url=f"{BASE}rest/products/search", method="GET", params=["q"]),  # dup of a
            Endpoint(url=f"{BASE}api/Feedbacks", method="POST"),
        ],
    )
    endpoints = await run_route_discovery(BASE, _noop_fetch, [a, b])
    urls = [ep.url for ep in endpoints]

    # logout dropped, duplicate collapsed, distinct kept.
    assert not any("logout" in u for u in urls)
    assert sum(u.endswith("/rest/products/search") for u in urls) == 1
    assert any(u.endswith("/api/Feedbacks") for u in urls)


async def test_run_route_discovery_isolates_failing_discoverer() -> None:
    good = _FakeDiscoverer("good", [Endpoint(url=f"{BASE}rest/products", method="GET")])
    endpoints = await run_route_discovery(BASE, _noop_fetch, [_BoomDiscoverer(), good])
    assert [ep.url for ep in endpoints] == [f"{BASE}rest/products"]


def test_discoverers_satisfy_protocol() -> None:
    assert isinstance(StaticBundleDiscoverer(), RouteDiscoverer)
    assert isinstance(OpenAPIDiscoverer(), RouteDiscoverer)


# ---------------------------------------------------------------------------
# Exploit-side path-param substitution shim
# ---------------------------------------------------------------------------


def test_build_request_url_substitutes_path_params() -> None:
    build = _url_builder()
    # Base fetch (empty params) concretizes the placeholder so it never 404s.
    assert build("http://h:3000/rest/basket/:id", {}) == "http://h:3000/rest/basket/1"
    # Supplied value drives the path (the real IDOR probe).
    assert build("http://h:3000/rest/basket/:id", {"id": "2"}) == "http://h:3000/rest/basket/2"
    # {name} form + a leftover query param.
    assert (
        build("http://h:3000/api/Users/{id}", {"id": "5", "verbose": "1"})
        == "http://h:3000/api/Users/5?verbose=1"
    )


def test_build_request_url_leaves_query_routes_unchanged() -> None:
    build = _url_builder()
    # No path placeholder → param is appended/replaced in the query as before.
    assert (
        build("http://h:3000/rest/products/search", {"q": "x"})
        == "http://h:3000/rest/products/search?q=x"
    )
    assert build("http://h:3000/foo?a=1", {"a": "2"}) == "http://h:3000/foo?a=2"
    # SPA fragment route is untouched by the path shim.
    assert build("http://h:3000/#/search?q=test", {"q": "PAY"}) == "http://h:3000/#/search?q=PAY"
