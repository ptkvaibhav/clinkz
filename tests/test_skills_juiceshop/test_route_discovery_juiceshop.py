"""Live Juice Shop route-discovery smoke (marker: juiceshop_smoke).

Validates the static-bundle + OpenAPI discoverers against the REAL Angular
production bundle. ``run_route_discovery`` must surface the canonical
param-bearing routes that an HTML/JS crawl under-reports — asserted by specific
route and param structure, not by count:

* ``/rest/products/search`` (q)         — SQLi / reflected-XSS target
* ``/redirect`` (to)                    — open-redirect target
* ``/rest/basket/:id`` or ``/api/Users/:id`` — path-param resource (IDOR)
* ``/api/Feedbacks``                    — stored-XSS / CSRF collection
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import pytest

from clinkz.agents._route_discovery import FetchResult, run_route_discovery

pytestmark = [pytest.mark.juiceshop_smoke]


def _session_fetch(token: str):
    """A session-carrying GET closure (the engagement's FetchFn, via httpx)."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    async def fetch(url: str) -> FetchResult | None:
        try:
            async with httpx.AsyncClient(
                timeout=20.0, follow_redirects=True, headers=headers
            ) as client:
                resp = await client.get(url)
        except Exception:
            return None
        return FetchResult(
            status=resp.status_code,
            body=resp.text,
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    return fetch


async def test_route_discovery_surfaces_juiceshop_canonical_routes(
    juiceshop_url: str, juiceshop_auth: dict[str, str]
) -> None:
    token = juiceshop_auth.get("Authorization", "").removeprefix("Bearer ").strip()
    endpoints = await run_route_discovery(juiceshop_url + "/", _session_fetch(token))

    assert endpoints, "route discovery returned nothing against live Juice Shop"

    paths = {urlsplit(ep.url).path for ep in endpoints}
    params_by_path: dict[str, list[str]] = {}
    for ep in endpoints:
        params_by_path.setdefault(urlsplit(ep.url).path, []).extend(ep.params)

    # /rest/products/search?q= — the route katana's -jc misses, with its param.
    assert "/rest/products/search" in paths, f"missing /rest/products/search; got {sorted(paths)}"
    assert "q" in params_by_path.get("/rest/products/search", []), (
        "search route discovered without its q param"
    )

    # /redirect?to= — open redirect.
    redirect_eps = [ep for ep in endpoints if urlsplit(ep.url).path == "/redirect"]
    assert redirect_eps, f"missing /redirect; got {sorted(paths)}"
    assert any("to" in ep.params for ep in redirect_eps), (
        "/redirect discovered without its to param"
    )

    # A path-param resource route (IDOR surface).
    assert any(p in ("/rest/basket/:id", "/api/Users/:id") for p in paths), (
        f"no path-param resource route discovered; got {sorted(paths)}"
    )

    # /api/Feedbacks — stored-XSS / CSRF collection.
    assert any(p == "/api/Feedbacks" for p in paths), f"missing /api/Feedbacks; got {sorted(paths)}"
