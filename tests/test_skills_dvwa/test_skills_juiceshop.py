"""Reflected XSS smoke test against OWASP Juice Shop.

Lives in the same directory as the DVWA skill tests so the same harness,
fixtures, and ``-m dvwa_smoke`` filter apply. The test skips with a clear
message when Juice Shop is not running on the expected port — so it's
safe to leave in CI without forcing every contributor to start the
container.

Juice Shop's reflected-XSS surface differs by version. The test probes a
small set of endpoints known to reflect a query parameter into HTML, and
asserts that ``_test_xss_reflected`` finds at least one of them.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

pytestmark = [pytest.mark.dvwa_smoke, pytest.mark.asyncio]

JUICESHOP_DEFAULT_URL = "http://localhost:3000"


# ---------------------------------------------------------------------------
# Fixtures (Juice Shop has no auth/security setting, so they're simpler than
# the DVWA equivalents in conftest.py).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def juiceshop_url() -> str:
    """Juice Shop base URL. Skip the test cleanly if it isn't reachable.

    To stand it up locally::

        docker compose -f docker/docker-compose.yml up -d juiceshop
    """
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


class _SilentLLM(LLMClient):
    """No-op LLM. The skill's deterministic fallbacks carry the test."""

    async def reason(self, messages: list[LLMMessage], tools: list[dict] | None = None) -> object:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-juiceshop")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


@pytest_asyncio.fixture
async def juiceshop_agent(juiceshop_url: str) -> ExploitAgent:
    """Build an ExploitAgent scoped to the Juice Shop instance."""
    scope = EngagementScope(
        name="juiceshop-skill-smoke",
        targets=[ScopeEntry(value=juiceshop_url, type=ScopeType.URL)],
    )
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=scope,
        state=_make_state(),
        engagement_id="juiceshop-skill-smoke",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    # Pin the methodology LLM to the silent one so we don't accidentally hit
    # a configured Anthropic key during the test.
    agent._methodology_llm = agent.llm
    return agent


# ---------------------------------------------------------------------------
# Reflected XSS — try multiple known-vulnerable endpoints
# ---------------------------------------------------------------------------

# Candidate endpoints that have historically reflected unsanitised query
# parameters into the response. We probe each in order and stop on the
# first hit. If none reflect, the test fails with the full attempted set
# so a maintainer can update the list against a newer Juice Shop release.
_JUICESHOP_REFLECTED_CANDIDATES: list[tuple[str, list[str]]] = [
    ("/profile?username=test", ["username"]),
    ("/rest/products/search?q=test", ["q"]),
    ("/rest/track-order/test", []),
    ("/?redirect=test", ["redirect"]),
    ("/search?q=test", ["q"]),
]


async def test_xss_reflected_against_juiceshop(
    juiceshop_url: str,
    juiceshop_agent: ExploitAgent,
) -> None:
    """``_test_xss_reflected`` must find at least one reflected XSS in Juice Shop.

    Iterates a known-vulnerable endpoint list and stops on the first
    finding. If every candidate produces no finding, that's a real signal
    the skill is broken — the test fails with diagnostic context listing
    every endpoint that was probed.
    """
    attempted: list[str] = []
    for path, params in _JUICESHOP_REFLECTED_CANDIDATES:
        url = f"{juiceshop_url}{path}"
        attempted.append(url)
        page = await juiceshop_agent._fetch_page(url, params=params or None)
        if not page.input_params:
            continue
        findings = await juiceshop_agent._test_xss_reflected(page)
        if findings:
            assert any("xss" in f.title.lower() for f in findings), (
                f"Findings produced but none labelled XSS at {url}: {findings}"
            )
            # Methodology evidence should be attached.
            assert any("phases_completed=" in ev for ev in findings[0].evidence), (
                f"Methodology evidence missing on Juice Shop finding at {url}: "
                f"{findings[0].evidence}"
            )
            return
    pytest.fail(
        "_test_xss_reflected found no reflected XSS in any Juice Shop "
        f"candidate endpoint. Attempted: {attempted}. The skill or the "
        "candidate list may need updating against the running Juice Shop "
        "version."
    )
