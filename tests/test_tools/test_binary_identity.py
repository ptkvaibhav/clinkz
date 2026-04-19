"""Tests for binary identity verification."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.config import settings
from clinkz.tools import binary_identity
from clinkz.tools.binary_identity import BINARY_SIGNATURES, verify_binary_identity
from clinkz.tools.resolver import ToolResolver


class _FakeProc:
    """Minimal asyncio subprocess-like stand-in."""

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        hang: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(60)
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return 0


def _spawn_returning(
    stdout: bytes = b"",
    stderr: bytes = b"",
    *,
    hang: bool = False,
) -> AsyncMock:
    """Return an AsyncMock usable as ``asyncio.create_subprocess_exec``."""
    captured: dict[str, list[str]] = {"argv": []}

    async def _factory(*args: str, **_: object) -> _FakeProc:
        captured["argv"] = list(args)
        return _FakeProc(stdout=stdout, stderr=stderr, hang=hang)

    mock = AsyncMock(side_effect=_factory)
    mock.captured = captured  # type: ignore[attr-defined]
    return mock


async def test_verify_identity_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe output that contains the expected signature returns True."""
    spawn = _spawn_returning(stdout=b"projectdiscovery httpx v1.3.7")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    assert await verify_binary_identity("httpx") is True


async def test_verify_identity_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe output from the Python ``httpx`` CLI (no signature) returns False."""
    # The python-httpx CLI prints something like "HTTPX 0.27.0" with no mention
    # of projectdiscovery.
    spawn = _spawn_returning(stdout=b"HTTPX 0.27.0\nUsage: httpx [OPTIONS]")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    assert await verify_binary_identity("httpx") is False


async def test_verify_identity_with_docker_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exec_prefix must be prepended to the command."""
    spawn = _spawn_returning(stdout=b"Nmap version 7.94")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    ok = await verify_binary_identity(
        "nmap", exec_prefix=["docker", "exec", "clinkz-tools"]
    )

    assert ok is True
    argv = spawn.captured["argv"]  # type: ignore[attr-defined]
    assert argv[:3] == ["docker", "exec", "clinkz-tools"]
    assert argv[3] == "nmap"


async def test_verify_identity_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A probe that never returns (emulated via hang) resolves to False."""
    spawn = _spawn_returning(hang=True)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    # Shrink the timeout so the test stays fast.
    monkeypatch.setattr(binary_identity, "_VERIFY_TIMEOUT", 0.05)

    assert await verify_binary_identity("nmap") is False


async def test_verify_identity_unknown_tool_returns_true() -> None:
    """Tools without a registered signature skip verification."""
    assert await verify_binary_identity("definitely-not-a-real-tool") is True


async def test_verify_identity_spawn_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A FileNotFoundError during spawn resolves to False."""

    async def _boom(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(side_effect=_boom))

    assert await verify_binary_identity("nmap") is False


def test_is_available_rejects_wrong_binary_in_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``shutil.which`` finding a binary is not enough — identity must match.

    Simulates the Python ``httpx`` library: on PATH, but the identity probe
    reports output that lacks the ProjectDiscovery signature. The resolver
    must report it as unavailable.
    """
    monkeypatch.setattr(settings, "tool_exec_mode", "local")

    resolver = ToolResolver()

    # Replace the identity helper with one that captures its args and
    # pretends the binary failed verification.
    captured: dict[str, object] = {}

    def _fake_identity(name: str, prefix: list[str]) -> bool:
        captured["name"] = name
        captured["prefix"] = prefix
        return False

    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/httpx"):
        with patch("clinkz.tools.resolver._identity_ok", side_effect=_fake_identity):
            assert resolver.is_available("httpx") is False

    assert captured["name"] == "httpx"
    assert captured["prefix"] == []


def test_is_available_accepts_correct_binary_in_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When identity verification succeeds, is_available returns True."""
    monkeypatch.setattr(settings, "tool_exec_mode", "local")

    resolver = ToolResolver()
    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
        with patch("clinkz.tools.resolver._identity_ok", return_value=True):
            assert resolver.is_available("nmap") is True


def test_binary_signatures_cover_core_tools() -> None:
    """Core head-of-chain tools should all be in the signatures registry."""
    for tool in ("httpx", "nmap", "nuclei", "katana", "ffuf", "subfinder"):
        assert tool in BINARY_SIGNATURES, f"no signature registered for {tool}"
