"""Shared fixtures for DVWA skill smoke tests.

Provides:
- ``dvwa_url``: session-scoped base URL, skips the suite if DVWA is unreachable.
- ``dvwa_session``: session-scoped auth cookie dict. Logs in as admin/password,
  sets security to low, returns ``{"PHPSESSID": ..., "security": "low"}``.
- ``exploit_agent``: function-scoped ``ExploitAgent`` preloaded with the DVWA
  session cookies and mocked LLM / persistent-KB dependencies.
"""

from __future__ import annotations

import os
import re
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

DVWA_DEFAULT_URL = "http://localhost:8080"
_USER_TOKEN_RE = re.compile(
    r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]+)['"]""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# DVWA reachability + auth
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def dvwa_url() -> str:
    """DVWA base URL. Skip the whole suite if it isn't reachable."""
    url = os.getenv("DVWA_URL", DVWA_DEFAULT_URL).rstrip("/")
    try:
        resp = httpx.get(url, timeout=3.0, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — broad is intentional
        pytest.skip(f"DVWA not reachable at {url}: {exc}")
    return url


@pytest.fixture(scope="session")
def dvwa_session(dvwa_url: str) -> dict[str, str]:
    """Authenticate to DVWA and set security=low. Skip the suite if auth fails.

    Sequence:
        1. GET /login.php — extract user_token.
        2. POST /login.php — admin / password + token.
        3. GET /security.php — extract user_token.
        4. POST /security.php — security=low + token.
    """
    with httpx.Client(base_url=dvwa_url, timeout=10.0, follow_redirects=False) as client:
        # Step 1: GET login page, grab token + PHPSESSID
        r = client.get("/login.php")
        if r.status_code not in (200, 302):
            pytest.skip(f"DVWA /login.php returned {r.status_code}")
        token_match = _USER_TOKEN_RE.search(r.text)
        if not token_match:
            pytest.skip("DVWA login form missing user_token — is setup complete?")
        user_token = token_match.group(1)

        # Step 2: POST credentials
        r = client.post(
            "/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": user_token,
            },
        )
        if r.status_code not in (200, 302):
            pytest.skip(f"DVWA login POST returned {r.status_code}")
        # Successful login redirects to /index.php; a failed one redirects back to /login.php
        location = r.headers.get("location", "")
        if "login.php" in location:
            pytest.skip("DVWA login failed — wrong credentials or database not initialised")

        # Step 3: GET security.php, grab token
        r = client.get("/security.php", follow_redirects=True)
        if r.status_code != 200:
            pytest.skip(f"DVWA /security.php returned {r.status_code}")
        token_match = _USER_TOKEN_RE.search(r.text)
        if not token_match:
            pytest.skip("DVWA /security.php missing user_token")
        sec_token = token_match.group(1)

        # Step 4: POST security=low
        r = client.post(
            "/security.php",
            data={
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": sec_token,
            },
        )
        if r.status_code not in (200, 302):
            pytest.skip(f"DVWA security POST returned {r.status_code}")

        cookies: dict[str, str] = {k: v for k, v in client.cookies.items()}

    if "PHPSESSID" not in cookies:
        pytest.skip(f"DVWA auth did not produce a PHPSESSID cookie (got {list(cookies)})")
    # Ensure security cookie is present
    cookies.setdefault("security", "low")
    return cookies


# ---------------------------------------------------------------------------
# Exploit agent with mocked dependencies
# ---------------------------------------------------------------------------


class _SilentLLM(LLMClient):
    """Minimal LLM that returns neutral responses.

    Skill tests are about the deterministic detection paths, not LLM output.
    When a skill calls ``_llm_analyze`` we return a string that neither
    triggers nor suppresses detection, so the skill falls through to its
    signature / shape checks (error strings, reflection, timing, etc).
    """

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_scope(dvwa_url: str) -> EngagementScope:
    return EngagementScope(
        name="dvwa-skill-smoke",
        targets=[ScopeEntry(value=dvwa_url, type=ScopeType.URL)],
    )


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-smoke")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


@pytest_asyncio.fixture
async def exploit_agent(dvwa_url: str, dvwa_session: dict[str, str]) -> ExploitAgent:
    """Build an ExploitAgent with DVWA session cookies preloaded."""
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=_make_scope(dvwa_url),
        state=_make_state(),
        engagement_id="dvwa-skill-smoke",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._session_cookies = dict(dvwa_session)
    return agent
