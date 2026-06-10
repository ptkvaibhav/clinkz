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
from clinkz.models.scan import Endpoint

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

    # Plain collection + open-redirect param route.
    assert "/api/Feedbacks" in by_path
    redirects = [ep for ep in endpoints if ep.url.endswith("/redirect")]
    assert any("to" in ep.params for ep in redirects)

    # Interpolated path-param route also recovered.
    assert "/api/Products/:id" in by_path
    assert by_path["/api/Products/:id"].params == ["id"]


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


async def test_known_roots_probe_keeps_only_json_responders() -> None:
    """No spec served → tight conventional-root probe keeps JSON responders and
    drops SPA-shell HTML answers."""

    async def fetch(url: str) -> FetchResult | None:
        if url.endswith("/rest/products"):
            return FetchResult(200, '{"data":[]}', {"content-type": "application/json"})
        # spec paths + other roots: SPA shell
        return FetchResult(
            200, "<!DOCTYPE html><app-root></app-root>", {"content-type": "text/html"}
        )

    endpoints = await OpenAPIDiscoverer().discover(BASE, fetch)
    paths = {ep.url for ep in endpoints}
    assert any(u.endswith("/rest/products") for u in paths)
    # The SPA-shell roots are not emitted.
    assert not any(u.endswith("/api/Users") for u in paths)


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
