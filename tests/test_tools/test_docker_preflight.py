"""Tests for the Docker pre-flight checks."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.tools import docker_preflight
from clinkz.tools.docker_preflight import ClinkzDockerError, ensure_container_ready


def _install_run_mock(
    monkeypatch: pytest.MonkeyPatch,
    responses: dict[tuple[str, ...], tuple[int, str, str]],
) -> AsyncMock:
    """Replace ``docker_preflight._run`` with a lookup over fixed responses.

    Keys are the command argv tuple; values are ``(rc, stdout, stderr)``.
    Missing commands raise to make drift obvious.
    """

    async def _fake(cmd: list[str], *, timeout: float = 0.0) -> tuple[int, str, str]:
        key = tuple(cmd)
        if key not in responses:
            raise AssertionError(f"unexpected docker command: {cmd}")
        return responses[key]

    mock = AsyncMock(side_effect=_fake)
    monkeypatch.setattr(docker_preflight, "_run", mock)
    return mock


@pytest.mark.asyncio
async def test_preflight_succeeds_when_container_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: daemon up, container exists, running, canary reachable."""
    responses: dict[tuple[str, ...], Any] = {
        ("docker", "info"): (0, "Server Version: 25.0", ""),
        ("docker", "inspect", "clinkz-tools"): (0, "[]", ""),
        (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "clinkz-tools",
        ): (0, "true\n", ""),
        ("docker", "exec", "clinkz-tools", "which", "nmap"): (
            0,
            "/usr/bin/nmap\n",
            "",
        ),
    }
    _install_run_mock(monkeypatch, responses)

    await ensure_container_ready("clinkz-tools")


@pytest.mark.asyncio
async def test_preflight_starts_stopped_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``State.Running`` is false, preflight must call ``docker start``."""
    responses: dict[tuple[str, ...], Any] = {
        ("docker", "info"): (0, "", ""),
        ("docker", "inspect", "clinkz-tools"): (0, "[]", ""),
        (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "clinkz-tools",
        ): (0, "false\n", ""),
        ("docker", "start", "clinkz-tools"): (0, "clinkz-tools\n", ""),
        ("docker", "exec", "clinkz-tools", "which", "nmap"): (
            0,
            "/usr/bin/nmap\n",
            "",
        ),
    }
    mock = _install_run_mock(monkeypatch, responses)

    await ensure_container_ready("clinkz-tools")

    called = [tuple(call.args[0]) for call in mock.call_args_list]
    assert ("docker", "start", "clinkz-tools") in called


@pytest.mark.asyncio
async def test_preflight_raises_when_docker_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``docker info`` failure must raise an actionable ClinkzDockerError."""
    responses: dict[tuple[str, ...], Any] = {
        ("docker", "info"): (1, "", "Cannot connect to the Docker daemon"),
    }
    _install_run_mock(monkeypatch, responses)

    with pytest.raises(ClinkzDockerError) as excinfo:
        await ensure_container_ready("clinkz-tools")

    msg = str(excinfo.value)
    assert "Docker not installed" in msg or "daemon not running" in msg
    assert "Install Docker Desktop" in msg


@pytest.mark.asyncio
async def test_preflight_raises_when_container_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the canary tool can't be resolved, preflight must raise."""
    responses: dict[tuple[str, ...], Any] = {
        ("docker", "info"): (0, "", ""),
        ("docker", "inspect", "clinkz-tools"): (0, "[]", ""),
        (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "clinkz-tools",
        ): (0, "true\n", ""),
        ("docker", "exec", "clinkz-tools", "which", "nmap"): (
            1,
            "",
            "which: nmap: not found",
        ),
    }
    # Shrink retry budget so the test is fast.
    monkeypatch.setattr(docker_preflight, "_CANARY_RETRIES", 2)
    monkeypatch.setattr(docker_preflight, "_CANARY_BACKOFF", 0.0)
    _install_run_mock(monkeypatch, responses)

    with pytest.raises(ClinkzDockerError) as excinfo:
        await ensure_container_ready("clinkz-tools")

    msg = str(excinfo.value)
    assert "tools aren't reachable" in msg
    assert "docker compose" in msg


@pytest.mark.asyncio
async def test_preflight_invokes_compose_when_container_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``docker inspect`` fails, preflight must try ``docker compose up``."""
    first_inspect = {"seen": False}

    async def _fake(cmd: list[str], *, timeout: float = 0.0) -> tuple[int, str, str]:
        key = tuple(cmd)
        if key == ("docker", "info"):
            return 0, "", ""
        if key == ("docker", "inspect", "clinkz-tools"):
            if not first_inspect["seen"]:
                first_inspect["seen"] = True
                return 1, "", "No such object"
            return 0, "[]", ""
        if key[:4] == ("docker", "compose", "-f", str(docker_preflight._compose_file())):
            return 0, "Network created\n", ""
        if key == (
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            "clinkz-tools",
        ):
            return 0, "true\n", ""
        if key == ("docker", "exec", "clinkz-tools", "which", "nmap"):
            return 0, "/usr/bin/nmap\n", ""
        raise AssertionError(f"unexpected docker command: {cmd}")

    mock = AsyncMock(side_effect=_fake)
    monkeypatch.setattr(docker_preflight, "_run", mock)

    await ensure_container_ready("clinkz-tools")

    called = [tuple(call.args[0]) for call in mock.call_args_list]
    assert any(c[:2] == ("docker", "compose") for c in called)
