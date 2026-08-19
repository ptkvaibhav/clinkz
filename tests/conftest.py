"""Shared pytest fixtures and environment for the Clinkz test suite.

Three defaults apply to every test unless a test explicitly overrides them:

- ``settings.tool_exec_mode`` is pinned to ``"local"`` so tests that mock the
  host PATH behave the way they did before container-first execution became
  the runtime default.
- ``clinkz.tools.docker_preflight.ensure_container_ready`` is neutralised so
  the orchestrator's start-of-run preflight check does not require a live
  Docker daemon during unit / integration tests.
- ``settings.outputs_root`` is redirected into the test's own ``tmp_path`` so
  no test can write into the developer's real ``outputs/``.

Tests that specifically exercise docker-mode or preflight behaviour can
monkeypatch these back as needed (see ``tests/test_tools/test_docker_preflight.py``
and ``tests/test_tools/test_binary_identity.py``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.config import settings
from clinkz.tools import docker_preflight


@pytest.fixture(autouse=True)
def _bypass_docker_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin tool_exec_mode to local and no-op the docker preflight.

    Sets ``TOOL_EXEC_MODE=local`` in the environment *and* patches the
    current settings singleton. The env var covers tests that reload
    settings mid-run (e.g. ``tests/test_llm/test_anthropic_client.py``
    which does ``config.settings = Settings.from_env()``).

    Also seeds dummy LLM API keys so the orchestrator's engagement-start
    chain validation (``validate_agent_chains``) passes in tests that do
    not mock out the whole ``run()`` path. Tests that specifically
    exercise the no-key case override with ``monkeypatch.delenv``.
    """
    monkeypatch.setenv("TOOL_EXEC_MODE", "local")
    monkeypatch.setattr(settings, "tool_exec_mode", "local")

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")

    async def _noop_preflight(container_name: str = "clinkz-tools") -> None:
        return None

    monkeypatch.setattr(docker_preflight, "ensure_container_ready", _noop_preflight)
    monkeypatch.setattr(
        "clinkz.orchestrator.orchestrator.ensure_container_ready",
        _noop_preflight,
    )


@pytest.fixture(autouse=True)
def _redirect_outputs_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every artifact writer at this test's own ``tmp_path``.

    The default root is the RELATIVE path ``outputs``, so a test that reaches a
    writer without passing ``outputs_root=`` explicitly wrote into the
    developer's real ``outputs/`` — measured at **25 directories per keyless
    run**, which is how thousands of report-less engagement directories
    accumulated there.

    That is not untidiness. ``outputs/`` is the region
    :func:`~clinkz.engagement.artifact_scan.scan_artifact_tree` sweeps as the
    COMPANION region, so a test byproduct is scanned as though it were part of
    an operator's bundle, and any test that ever handles real credential
    material lands it inside a swept region. The disclosure gate's own answer
    should be about engagement artifacts, not about the test suite's litter.

    Both levers are set, mirroring :func:`_bypass_docker_defaults`: the env var
    covers tests that rebuild the settings object mid-run
    (``config.settings = Settings.from_env()``), and the attribute covers the
    singleton every already-imported writer resolves through.

    A test that wants the real root back can ``monkeypatch.setattr`` it, and a
    test that passes ``outputs_root=`` explicitly is unaffected — the fixture
    changes only the resolved DEFAULT.
    """
    root = tmp_path / "outputs"
    monkeypatch.setenv("CLINKZ_OUTPUTS_ROOT", str(root))
    monkeypatch.setattr(settings, "outputs_root", root)
    return root
