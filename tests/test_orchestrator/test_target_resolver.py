"""Unit tests for :mod:`clinkz.orchestrator.target_resolver`.

The resolver bridges a class of failure that is silent at the tool layer:
when ``TOOL_EXEC_MODE=docker`` and the user passes ``--target
http://localhost:8080`` the tools all run inside the clinkz-tools container
and never reach the sibling DVWA / Juice Shop container.

These tests cover:

- Local exec mode → resolver returns the scope unchanged.
- Non-loopback scope target → resolver returns the scope unchanged.
- Loopback target + matching publishing container → URL is rewritten.
- Loopback target without a host port → ``TargetResolutionError``.
- Loopback target with a port no container publishes → ``TargetResolutionError``.
- The clinkz-tools container is excluded from the port map (resolver must
  never map back onto itself).
- Multiple loopback variants (``127.0.0.1``, ``0.0.0.0``) are detected.
- Original target is preserved in ``ScopeEntry.notes`` for reporting.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.target_resolver import (
    TargetResolutionError,
    resolve_target_for_docker_mode,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _scope(value: str, scope_type: ScopeType = ScopeType.DOMAIN) -> EngagementScope:
    return EngagementScope(
        name="test",
        targets=[ScopeEntry(value=value, type=scope_type)],
    )


def _docker_ps_lines(*names: str) -> tuple[int, str, str]:
    """Fake successful ``docker ps`` output."""
    return 0, "\n".join(names) + ("\n" if names else ""), ""


def _docker_inspect_ports(mapping: dict[str, list[tuple[int, int]]]) -> Any:
    """Build a fake _run_docker side_effect that responds to ps + inspect calls.

    Args:
        mapping: ``container_name`` → list of (host_port, container_port) tuples.
    """
    names = list(mapping.keys())

    async def _fake(cmd: list[str]) -> tuple[int, str, str]:
        if cmd[:2] == ["docker", "ps"]:
            return _docker_ps_lines(*names)
        if len(cmd) >= 3 and cmd[:2] == ["docker", "inspect"]:
            container = cmd[2]
            pairs = mapping.get(container, [])
            # Build a NetworkSettings.Ports JSON blob like docker emits.
            ports_json: dict[str, list[dict[str, str]]] = {}
            for host_port, container_port in pairs:
                key = f"{container_port}/tcp"
                ports_json.setdefault(key, []).append(
                    {"HostIp": "0.0.0.0", "HostPort": str(host_port)}
                )
            import json as _json

            return 0, _json.dumps(ports_json), ""
        return 1, "", f"unexpected command: {cmd}"

    return _fake


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_mode_is_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    """tool_exec_mode=local → resolver is a no-op (no docker calls)."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")
    scope = _scope("http://localhost:8080")

    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=AssertionError("docker must not be called in local mode")),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out is scope


@pytest.mark.asyncio
async def test_non_loopback_target_is_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    """Public IPs / hostnames should not trigger docker inspection."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("https://app.example.com", ScopeType.URL)

    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=AssertionError("docker must not be called for public targets")),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out is scope


@pytest.mark.asyncio
async def test_localhost_port_resolves_to_container_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``http://localhost:8080`` → ``http://clinkz-dvwa:80`` when DVWA is running."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://localhost:8080")

    side_effect = _docker_inspect_ports(
        {
            "clinkz-tools": [],
            "clinkz-dvwa": [(8080, 80)],
            "clinkz-juiceshop": [(3000, 3000)],
        }
    )

    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope, self_container="clinkz-tools")

    assert len(out.targets) == 1
    assert out.targets[0].value == "http://clinkz-dvwa:80"
    # Original URL preserved for reporting clarity
    assert "original_target=http://localhost:8080" in out.targets[0].notes


@pytest.mark.asyncio
async def test_127_0_0_1_is_treated_as_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://127.0.0.1:3000")

    side_effect = _docker_inspect_ports(
        {"clinkz-juiceshop": [(3000, 3000)]},
    )
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out.targets[0].value == "http://clinkz-juiceshop:3000"


@pytest.mark.asyncio
async def test_0_0_0_0_is_treated_as_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://0.0.0.0:8080")

    side_effect = _docker_inspect_ports({"clinkz-dvwa": [(8080, 80)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out.targets[0].value == "http://clinkz-dvwa:80"


@pytest.mark.asyncio
async def test_unknown_port_raises_target_resolution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A localhost port no container publishes must fail loudly, not silently."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://localhost:9999")

    side_effect = _docker_inspect_ports({"clinkz-dvwa": [(8080, 80)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        with pytest.raises(TargetResolutionError) as excinfo:
            await resolve_target_for_docker_mode(scope)

    assert "9999" in str(excinfo.value)
    # The error message must point users at running containers / published ports
    assert "8080" in str(excinfo.value)


@pytest.mark.asyncio
async def test_loopback_without_port_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare localhost target (no port) cannot be resolved."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("localhost", ScopeType.DOMAIN)

    side_effect = _docker_inspect_ports({"clinkz-dvwa": [(8080, 80)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        with pytest.raises(TargetResolutionError) as excinfo:
            await resolve_target_for_docker_mode(scope)

    assert "no port" in str(excinfo.value).lower() or "port" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_self_container_is_excluded_from_port_map(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If clinkz-tools itself publishes the same host port, prefer the target container."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://localhost:8080")

    side_effect = _docker_inspect_ports(
        {
            # clinkz-tools "publishes" 8080 too (hypothetical / dev-rebound), but
            # we must NOT map back onto ourselves.
            "clinkz-tools": [(8080, 8080)],
            "clinkz-dvwa": [(8080, 80)],
        }
    )
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope, self_container="clinkz-tools")

    assert out.targets[0].value == "http://clinkz-dvwa:80"


@pytest.mark.asyncio
async def test_https_default_port_is_inferred(monkeypatch: pytest.MonkeyPatch) -> None:
    """``https://localhost`` (no port) defaults to 443 and resolves accordingly."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("https://localhost", ScopeType.URL)

    side_effect = _docker_inspect_ports({"some-tls-app": [(443, 8443)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out.targets[0].value == "https://some-tls-app:8443"


@pytest.mark.asyncio
async def test_multiple_targets_partial_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mixed scope: localhost target gets rewritten, public target left alone."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = EngagementScope(
        name="mixed",
        targets=[
            ScopeEntry(value="http://localhost:8080", type=ScopeType.DOMAIN),
            ScopeEntry(value="https://api.example.com", type=ScopeType.URL),
        ],
    )

    side_effect = _docker_inspect_ports({"clinkz-dvwa": [(8080, 80)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out.targets[0].value == "http://clinkz-dvwa:80"
    assert out.targets[1].value == "https://api.example.com"


@pytest.mark.asyncio
async def test_url_path_and_query_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Path / query / fragment must survive the netloc rewrite."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "docker")
    scope = _scope("http://localhost:8080/login.php?foo=bar#section")

    side_effect = _docker_inspect_ports({"clinkz-dvwa": [(8080, 80)]})
    with patch(
        "clinkz.orchestrator.target_resolver._run_docker",
        new=AsyncMock(side_effect=side_effect),
    ):
        out = await resolve_target_for_docker_mode(scope)

    assert out.targets[0].value == "http://clinkz-dvwa:80/login.php?foo=bar#section"
