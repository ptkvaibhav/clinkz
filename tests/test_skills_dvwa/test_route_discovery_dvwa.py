"""DVWA route-discovery regression (marker: dvwa_smoke).

The SPA/API discoverers are additive: on a plain server-rendered app like DVWA
(no JS-framework bundles, no OpenAPI spec) they must complete cleanly and
surface no fabricated ``/api`` or ``/rest`` routes — so the existing HTML-crawl
path is unaffected.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import pytest

from clinkz.agents._route_discovery import FetchResult, run_route_discovery

pytestmark = [pytest.mark.dvwa_smoke]


async def _fetch(url: str) -> FetchResult | None:
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
    except Exception:
        return None
    return FetchResult(
        status=resp.status_code,
        body=resp.text,
        headers={k.lower(): v for k, v in resp.headers.items()},
    )


async def test_route_discovery_is_noop_on_dvwa(dvwa_url: str) -> None:
    # Must not raise, and must not invent API/REST routes on a plain app.
    endpoints = await run_route_discovery(dvwa_url + "/", _fetch)
    api_rest = [ep.url for ep in endpoints if urlsplit(ep.url).path.startswith(("/api/", "/rest/"))]
    assert not api_rest, f"discovery fabricated API/REST routes on DVWA: {api_rest}"
