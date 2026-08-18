"""Shared fixtures for Juice Shop skill smoke tests.

Provides:
- ``juiceshop_url``: session-scoped base URL, skips the suite if Juice Shop
  is unreachable.
- ``juiceshop_auth``: session-scoped auth header dict. Registers a fresh
  test user via ``POST /api/Users``, logs in via ``POST /rest/user/login``,
  returns ``{"Authorization": "Bearer <jwt>"}``.
- ``exploit_agent``: function-scoped ``ExploitAgent`` preloaded with the
  Juice Shop JWT in cookies/headers and mocked LLM / persistent-KB
  dependencies.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

JUICESHOP_DEFAULT_URL = "http://localhost:3000"


# ---------------------------------------------------------------------------
# Juice Shop reachability + auth
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def juiceshop_url() -> str:
    """Juice Shop base URL. Skip the whole suite if it isn't reachable."""
    url = os.getenv("JUICESHOP_URL", JUICESHOP_DEFAULT_URL).rstrip("/")
    try:
        resp = httpx.get(url, timeout=3.0, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — broad is intentional
        pytest.skip(
            f"Juice Shop not reachable at {url}: {exc}. "
            "Start it with `docker compose -f docker/docker-compose.yml up -d juiceshop`."
        )
    return url


@pytest.fixture(scope="session")
def juiceshop_auth(juiceshop_url: str) -> dict[str, str]:
    """Register a fresh test user, log in, return ``{"Authorization": "Bearer <jwt>"}``.

    Sequence:
        1. POST /api/Users — register a unique-per-session test account.
           Juice Shop allows self-registration with just email + password.
        2. POST /rest/user/login — log in, capture JWT from
           ``data.authentication.token``.
    """
    # Unique address per session so reruns don't collide on the unique-email
    # constraint. Domain `local.test` is RFC2606-reserved.
    email = f"clinkz_test_{uuid.uuid4().hex[:12]}_{int(time.time())}@local.test"
    password = "Clinkz!SmokeTest123"

    with httpx.Client(base_url=juiceshop_url, timeout=10.0, follow_redirects=False) as client:
        # Step 1: register
        r = client.post(
            "/api/Users",
            json={"email": email, "password": password, "passwordRepeat": password},
        )
        if r.status_code not in (200, 201):
            pytest.skip(
                f"Juice Shop registration POST /api/Users returned {r.status_code}: {r.text[:200]}"
            )

        # Step 2: log in to capture JWT
        r = client.post("/rest/user/login", json={"email": email, "password": password})
        if r.status_code != 200:
            pytest.skip(f"Juice Shop login returned {r.status_code}: {r.text[:200]}")
        try:
            token = r.json()["authentication"]["token"]
        except (KeyError, ValueError) as exc:
            pytest.skip(f"Juice Shop login response missing token: {exc}; body={r.text[:200]}")
        if not token:
            pytest.skip("Juice Shop login produced an empty token")

    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Exploit agent with mocked dependencies
# ---------------------------------------------------------------------------


class _SilentLLM(LLMClient):
    """Minimal LLM that returns neutral responses.

    Skill tests are about the deterministic detection paths, not LLM output.
    When a skill calls ``_llm_analyze`` we return a string that neither
    triggers nor suppresses detection, so the skill falls through to its
    deterministic fallbacks.
    """

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_scope(juiceshop_url: str) -> EngagementScope:
    return EngagementScope(
        name="juiceshop-skill-smoke",
        targets=[ScopeEntry(value=juiceshop_url, type=ScopeType.URL)],
    )


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-juiceshop")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


@pytest_asyncio.fixture
async def exploit_agent(juiceshop_url: str, juiceshop_auth: dict[str, str]) -> ExploitAgent:
    """Build an ExploitAgent scoped to Juice Shop with the JWT preloaded.

    Juice Shop authenticates via the ``Authorization: Bearer <jwt>`` header.
    The agent's HTTP path takes session cookies but not arbitrary headers,
    so we also store the bearer as a ``token`` cookie which Juice Shop
    accepts for many authenticated endpoints. The XSS-reflected methodology
    operates on unauthenticated reflection, so this only matters for
    skills that need a session.
    """
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=_make_scope(juiceshop_url),
        state=_make_state(),
        engagement_id="juiceshop-skill-smoke",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    bearer = juiceshop_auth.get("Authorization", "")
    token = bearer.removeprefix("Bearer ").strip()
    if token:
        agent._session_cookies = {"token": token}
    # Pin the methodology LLM to the silent one so we don't accidentally hit
    # a configured Anthropic key during the test.
    agent._methodology_llm = agent.llm
    return agent
