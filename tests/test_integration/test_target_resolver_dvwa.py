"""Live integration test: target resolver + HTTP client reach DVWA.

This test closes the loop the unit tests can't: it actually drives docker,
inspects the running containers, rewrites ``http://localhost:8080`` to the
DVWA container alias, and then issues an HTTP request via the same
docker-mode code path the agents use to confirm the request lands on the
real DVWA process — not the ``clinkz-tools`` container's own loopback.

Prerequisites:
- Docker daemon running.
- ``docker compose -f docker/docker-compose.yml up -d`` so both
  ``clinkz-tools`` and ``clinkz-dvwa`` are up.

Marked with ``@pytest.mark.integration`` so the default ``pytest`` run
(``tests/test_integration`` is excluded by the pre-push gate) skips it.
Run explicitly:

    pytest -m integration tests/test_integration/test_target_resolver_dvwa.py -v -s
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.target_resolver import resolve_target_for_docker_mode

logger = logging.getLogger(__name__)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _container_running(name: str) -> bool:
    if not _docker_available():
        return False
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip().lower() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


_DOCKER_OK = _docker_available()
_TOOLS_UP = _container_running("clinkz-tools")
_DVWA_UP = _container_running("clinkz-dvwa")


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_OK, reason="docker daemon not reachable")
@pytest.mark.skipif(
    not _TOOLS_UP, reason="clinkz-tools container not running — `docker compose up -d`"
)
@pytest.mark.skipif(
    not _DVWA_UP, reason="clinkz-dvwa container not running — `docker compose up -d`"
)
async def test_resolver_lets_http_client_reach_dvwa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: resolve localhost:8080 → DVWA container, then GET it via docker exec.

    Asserts:
    1. The resolver rewrites ``http://localhost:8080`` to a DVWA container alias
       and preserves the original target in ``ScopeEntry.notes``.
    2. The HTTPClientTool in docker mode (i.e. via ``docker exec
       clinkz-tools curl``) successfully fetches the resolved URL.
    3. The response body contains DVWA-specific markers, proving the HTTP
       request reached DVWA and not the clinkz-tools container itself.
    """
    from clinkz.config import settings
    from clinkz.tools.http_client import HTTPClientTool

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")

    scope = EngagementScope(
        name="dvwa-target-resolver-integration",
        targets=[ScopeEntry(value="http://localhost:8080", type=ScopeType.DOMAIN)],
    )

    # --- Step 1: resolver against the real docker daemon ---
    resolved = await resolve_target_for_docker_mode(scope)
    assert len(resolved.targets) == 1
    resolved_url = resolved.targets[0].value
    logger.info("Resolver: %s -> %s", scope.targets[0].value, resolved_url)

    # Should NOT still be localhost — that's the whole point.
    assert "localhost" not in resolved_url
    assert "127.0.0.1" not in resolved_url
    # Should target the DVWA container in some form.
    assert "dvwa" in resolved_url.lower()
    # Original is preserved on the entry for reporting.
    assert "original_target=http://localhost:8080" in resolved.targets[0].notes

    # --- Step 2: build a scope that contains BOTH the original and resolved
    # hostnames, so the http_client scope check accepts the resolved URL. In
    # real engagements the orchestrator passes the resolved scope to the
    # tool; here we widen explicitly because the test instantiates the tool
    # directly.
    from urllib.parse import urlparse

    parsed_resolved = urlparse(resolved_url)
    resolved_host = parsed_resolved.hostname or ""

    test_scope = EngagementScope(
        name="dvwa-resolver-integration",
        targets=[
            ScopeEntry(value=resolved_host, type=ScopeType.DOMAIN),
        ],
    )

    http = HTTPClientTool(scope=test_scope, timeout=30)
    args = http.validate_input({"url": resolved_url, "method": "GET", "follow_redirects": True})
    raw = await asyncio.wait_for(http.execute(args), timeout=30)
    parsed = http.parse_output(raw)

    logger.info(
        "GET %s -> status=%d, body_len=%d",
        resolved_url,
        parsed.status_code,
        len(parsed.response_body),
    )

    # --- Step 3: assert we reached DVWA, not the tools container ---
    assert parsed.status_code != 0, (
        f"http_client could not reach {resolved_url} from inside clinkz-tools — "
        f"resolver mapping is wrong or the docker network is broken. "
        f"error: {parsed.error!r}"
    )
    # 200 (login page) or 302 (redirect to /setup.php) are both acceptable;
    # the key signal is non-zero + DVWA-shaped response.
    assert parsed.status_code in (200, 302), (
        f"Unexpected status from DVWA: {parsed.status_code} (body: {parsed.response_body[:200]!r})"
    )
    body_lower = parsed.response_body.lower()
    headers_lower = " ".join(f"{k}:{v}" for k, v in parsed.response_headers.items()).lower()
    combined = body_lower + " " + headers_lower
    # DVWA serves PHP — at minimum we should see the Apache/PHP fingerprints
    # or a DVWA-branded payload. The clinkz-tools container would NOT serve
    # any of these markers from port 80, so this is a strong signal that the
    # request crossed the docker network into DVWA.
    assert any(marker in combined for marker in ("dvwa", "php", "apache")), (
        f"Response body/headers do not look like DVWA — request may not have "
        f"reached the DVWA container. status={parsed.status_code}, "
        f"headers={parsed.response_headers}, body_head={parsed.response_body[:200]!r}"
    )
