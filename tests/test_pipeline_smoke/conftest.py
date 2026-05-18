"""Fixtures for the pipeline_smoke suite.

These tests run the real Clinkz pipeline against a real container target
(DVWA on :8080, Juice Shop on :3000). The fixtures skip the suite when
the target is unreachable so developers without the container stack can
still run the rest of pytest unattended.

The orchestrator owns the trace and step_inputs sidecars — every smoke
test asserts on those sidecars, not just on the returned summary dict.
Asserting on the sidecars is what makes regressions visible: a fix that
quietly stops emitting tool invocations will fail these tests even when
the pipeline still returns *something*.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

DVWA_DEFAULT_URL = "http://localhost:8080"
JUICESHOP_DEFAULT_URL = "http://localhost:3000"


def _is_reachable(url: str, timeout: float = 2.0) -> bool:
    """Cheap TCP-level reachability check — avoids an httpx dep for the gate."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def dvwa_url() -> str:
    """DVWA base URL — skips the suite if it isn't reachable."""
    url = os.getenv("DVWA_URL", DVWA_DEFAULT_URL).rstrip("/")
    if not _is_reachable(url):
        pytest.skip(f"DVWA not reachable at {url}")
    return url


@pytest.fixture(scope="session")
def juiceshop_url() -> str:
    """Juice Shop base URL — skips the suite if it isn't reachable."""
    url = os.getenv("JUICESHOP_URL", JUICESHOP_DEFAULT_URL).rstrip("/")
    if not _is_reachable(url):
        pytest.skip(f"Juice Shop not reachable at {url}")
    return url


@pytest.fixture
def outputs_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Per-test outputs directory.

    Engagements scribble into ``outputs/<engagement_id>/`` relative to the
    process cwd. Pinning the cwd to ``tmp_path`` keeps tests hermetic and
    lets assertions look up the sidecar files (trace.jsonl,
    tool_invocations/, step_inputs/) without poisoning the developer's
    working tree.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "outputs").mkdir(parents=True, exist_ok=True)
    yield tmp_path / "outputs"
