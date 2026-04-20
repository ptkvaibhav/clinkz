"""Shared pytest fixtures and environment for the Clinkz test suite.

Two defaults apply to every test unless a test explicitly overrides them:

- ``settings.tool_exec_mode`` is pinned to ``"local"`` so tests that mock the
  host PATH behave the way they did before container-first execution became
  the runtime default.
- ``clinkz.tools.docker_preflight.ensure_container_ready`` is neutralised so
  the orchestrator's start-of-run preflight check does not require a live
  Docker daemon during unit / integration tests.

Tests that specifically exercise docker-mode or preflight behaviour can
monkeypatch these back as needed (see ``tests/test_tools/test_docker_preflight.py``
and ``tests/test_tools/test_binary_identity.py``).
"""

from __future__ import annotations

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
