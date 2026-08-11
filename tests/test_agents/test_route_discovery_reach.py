"""Two diagnosed-but-unfixed reach defects: the YAML spec, and the root-only seed.

Both had the same shape as the ffuf seam — the bytes were successfully
retrieved and then never reached the code that reads them. Neither was a
parsing failure, and neither made anything look wrong.
"""

from __future__ import annotations

import pytest

from clinkz.agents._route_discovery import (
    FetchResult,
    JSCallSiteDiscoverer,
    OpenAPIDiscoverer,
    StaticBundleDiscoverer,
    default_discoverers,
    run_route_discovery,
)

_SPEC_YAML = """\
openapi: 3.0.0
info:
  title: Inventory
  version: "1.0"
paths:
  /api/widgets:
    get:
      parameters:
        - name: q
          in: query
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                sku:
                  type: string
  /api/widgets/{widgetId}:
    get:
      parameters:
        - name: widgetId
          in: path
"""

_SPEC_JSON = (
    '{"openapi":"3.0.0","paths":{"/api/widgets":{"get":{"parameters":'
    '[{"name":"q","in":"query"}]}}}}'
)


class _Fetcher:
    """Records every URL requested, and serves a fixed route table."""

    def __init__(self, routes: dict[str, FetchResult]) -> None:
        self.routes = routes
        self.requested: list[str] = []

    async def __call__(self, url: str) -> FetchResult | None:
        self.requested.append(url)
        return self.routes.get(url)


def _html(body: str) -> FetchResult:
    return FetchResult(status=200, body=body, headers={"content-type": "text/html"})


def _js(body: str) -> FetchResult:
    return FetchResult(status=200, body=body, headers={"content-type": "application/javascript"})


# ---------------------------------------------------------------------------
# The OpenAPI YAML discard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_yaml_spec_is_read_not_discarded() -> None:
    """A live run fetched 10.4 KB of spec and threw it away for its format."""
    fetch = _Fetcher(
        {
            "http://t/openapi.yaml": FetchResult(
                status=200, body=_SPEC_YAML, headers={"content-type": "application/yaml"}
            )
        }
    )

    endpoints = await OpenAPIDiscoverer().discover("http://t/", fetch)

    paths = {e.url for e in endpoints}
    assert any("/api/widgets" in p for p in paths), f"YAML spec produced nothing: {paths}"
    methods = {e.method.upper() for e in endpoints}
    assert "POST" in methods, "the spec's write verbs must survive the YAML path"
    # The body shape the spec declared is the one field no crawl can supply.
    post = next(e for e in endpoints if e.method.upper() == "POST")
    assert "sku" in (post.params or [])


@pytest.mark.asyncio
async def test_a_yaml_body_without_a_spec_marker_is_still_refused() -> None:
    """Widening the parser must not widen what counts as a spec.

    YAML's grammar accepts nearly any text as a scalar, so a SPA's HTML shell
    'parses' fine. The gate that keeps junk out was never the format check — it
    is the openapi/swagger key — and it still is.
    """
    fetch = _Fetcher(
        {
            "http://t/openapi.yaml": FetchResult(
                status=200,
                body="<!doctype html><html><body>not a spec</body></html>",
                headers={"content-type": "text/html"},
            ),
            "http://t/swagger.yaml": FetchResult(
                status=200, body="title: a config file\nport: 8080\n", headers={}
            ),
        }
    )
    assert await OpenAPIDiscoverer().discover("http://t/", fetch) == []


@pytest.mark.asyncio
async def test_json_specs_still_parse_exactly_as_before() -> None:
    """The regression control for the widened parser."""
    fetch = _Fetcher(
        {
            "http://t/openapi.json": FetchResult(
                status=200, body=_SPEC_JSON, headers={"content-type": "application/json"}
            )
        }
    )
    endpoints = await OpenAPIDiscoverer().discover("http://t/", fetch)
    assert [e.url for e in endpoints] == ["http://t/api/widgets"]
    assert endpoints[0].params == ["q"]


# ---------------------------------------------------------------------------
# The root-only route-discovery seed
# ---------------------------------------------------------------------------


_ADMIN_JS = """
async function check(){
  const r = await fetch('/api/admin/authbypass?token=' + t, {method: 'POST'});
  return r.json();
}
"""

_ROOT_JS = "fetch('/api/health')"


def _spa_routes() -> dict[str, FetchResult]:
    return {
        "http://t/": _html('<html><script src="/js/main.js"></script></html>'),
        "http://t/js/main.js": _js(_ROOT_JS),
        # The admin page's script is referenced ONLY from a sub-page. Nothing in
        # the root bundle mentions it, so the chunk-literal walk cannot reach it
        # either — this is exactly the file the crawl fetched and the miner
        # never saw.
        "http://t/admin.html": _html('<html><script src="/js/authbypass.js"></script></html>'),
        "http://t/js/authbypass.js": _js(_ADMIN_JS),
    }


@pytest.mark.asyncio
async def test_root_only_discovery_cannot_see_a_sub_page_script() -> None:
    """The defect, pinned. With no pages supplied, behaviour is unchanged."""
    fetch = _Fetcher(_spa_routes())
    endpoints = await JSCallSiteDiscoverer().discover("http://t/", fetch)

    urls = {e.url for e in endpoints}
    assert "http://t/js/authbypass.js" not in fetch.requested
    assert not any("authbypass" in u for u in urls)


@pytest.mark.asyncio
async def test_seeding_from_a_discovered_page_reaches_its_script() -> None:
    """The fix: the crawl's pages and the miner are finally joined."""
    fetch = _Fetcher(_spa_routes())
    endpoints = await JSCallSiteDiscoverer(["http://t/admin.html"]).discover("http://t/", fetch)

    urls = {e.url for e in endpoints}
    assert any("authbypass" in u for u in urls), f"sub-page route still unreachable: {urls}"
    found = next(e for e in endpoints if "authbypass" in e.url)
    assert found.method.upper() == "POST", "the call site's method must survive"
    assert "token" in (found.params or [])


@pytest.mark.asyncio
async def test_off_origin_and_duplicate_pages_are_not_fetched() -> None:
    """Seeding widens what we read, never where we read from."""
    routes = _spa_routes()
    fetch = _Fetcher(routes)
    await StaticBundleDiscoverer(
        ["http://evil.example/x.html", "http://t/", "http://t/admin.html"]
    ).discover("http://t/", fetch)

    assert not any("evil.example" in u for u in fetch.requested)
    assert fetch.requested.count("http://t/") == 1, "the root is seeded once, not twice"


@pytest.mark.asyncio
async def test_the_page_seed_count_is_bounded() -> None:
    """A crawl of 500 pages must not become 500 discovery GETs."""
    from clinkz.agents._route_discovery import _MAX_DISCOVERY_PAGES

    routes = {"http://t/": _html("<html></html>")}
    pages = []
    for i in range(_MAX_DISCOVERY_PAGES * 3):
        url = f"http://t/p{i}.html"
        routes[url] = _html("<html></html>")
        pages.append(url)

    fetch = _Fetcher(routes)
    await StaticBundleDiscoverer(pages).discover("http://t/", fetch)

    page_gets = [u for u in fetch.requested if u != "http://t/"]
    assert len(page_gets) == _MAX_DISCOVERY_PAGES


# ---------------------------------------------------------------------------
# The shared memo — what makes per-page seeding affordable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_one_discovery_run_fetches_each_url_once() -> None:
    """Both bundle discoverers read the same pages and bundles.

    Without the shared memo, per-page seeding multiplies the crawl's page count
    by the number of bundle discoverers — a cost the previous root-only code was
    already paying twice over for the shell.
    """
    fetch = _Fetcher(_spa_routes())
    await run_route_discovery("http://t/", fetch, default_discoverers(["http://t/admin.html"]))

    for url in ("http://t/", "http://t/admin.html", "http://t/js/authbypass.js"):
        assert fetch.requested.count(url) == 1, f"{url} fetched {fetch.requested.count(url)}x"


@pytest.mark.asyncio
async def test_discovery_still_unions_and_drops_state_changing_routes() -> None:
    """The union chokepoint's guarantees are unaffected by the new seeding."""
    routes = _spa_routes()
    routes["http://t/admin.html"] = _html('<html><script src="/js/danger.js"></script></html>')
    routes["http://t/js/danger.js"] = _js("fetch('/api/session/logout')")
    fetch = _Fetcher(routes)

    endpoints = await run_route_discovery(
        "http://t/", fetch, default_discoverers(["http://t/admin.html"])
    )
    assert not any("logout" in e.url for e in endpoints)


@pytest.mark.asyncio
async def test_a_yaml_alias_bomb_is_refused_before_it_is_parsed() -> None:
    """safe_load blocks code execution, not geometric alias expansion.

    The byte cap bounds the input, not what it expands to. A spec expresses
    reuse with $ref, so refusing an anchor-heavy document costs nothing real.
    """
    bomb = "openapi: 3.0.0\na: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"b{i}: [{', '.join(['*a'] * 9)}]\n" for i in range(20)
    )
    fetch = _Fetcher(
        {
            "http://t/openapi.yaml": FetchResult(
                status=200, body=bomb, headers={"content-type": "application/yaml"}
            )
        }
    )
    assert await OpenAPIDiscoverer().discover("http://t/", fetch) == []
