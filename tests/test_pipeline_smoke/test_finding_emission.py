"""Regression gates for "methodology runs but emits nothing".

Engagement 64940821 ran all 13 methodologies with 300 HTTP calls yet
produced zero findings. Root cause: the authenticated katana crawl
followed DVWA's ``logout.php`` link, destroying the session; every
exploit-phase request then reused the dead cookie, was bounced (302) to
the login page, and each methodology analysed the login page instead of
the vulnerable endpoint.

The DVWA skill smoke suite did not catch it: those tests call ``_test_*``
directly with a freshly-authenticated session and never crawl, so nothing
logs them out. These tests close that gap by reproducing the exact
regression surface — the **crawl → session → methodology** handoff:

    1. Authenticate to DVWA (host).
    2. Run the *real* katana crawl with that session (docker mode, the
       step that destroyed the session pre-fix — it visits logout.php).
    3. Run the specific ``_test_*`` methodology against the discovered
       endpoint using the *same* (server-side) session.
    4. Assert the finding the methodology is a contract for is emitted.

Pre-fix this fails (crawl kills the session → step 3 sees the login page
→ no finding). Post-fix the session survives the crawl and the finding
comes out. The methodology runs through the silent-LLM deterministic path
(no API key, no flaky planner / phase-timeout), so the gate is fast and
reliable — unlike the full-orchestrator E2E in ``test_exploit_execution``,
which is the complementary (but timeout-prone) end-to-end check.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from clinkz.agents.exploit import ExploitAgent
from clinkz.agents.scan import ScanAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

pytestmark = [pytest.mark.pipeline_smoke, pytest.mark.asyncio]

# The crawl runs inside the clinkz-tools container, so it must target the
# DVWA container by its docker-network alias (the same shape the
# orchestrator's target_resolver produces). The methodology, by contrast,
# probes from the host over the localhost port mapping — both reference the
# same server-side PHP session keyed by PHPSESSID.
_DOCKER_ALIAS_URL = "http://clinkz-dvwa"
_USER_TOKEN_RE = re.compile(
    r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]+)['"]""", re.IGNORECASE
)


class _SilentLLM(LLMClient):
    """LLM stub that returns neutral output.

    Forces the adaptive SQLi / reflected-XSS methodologies down their
    deterministic detection path (the v2 contract) instead of depending on
    a live model, exactly as the DVWA skill smoke suite does.
    """

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-pipeline-smoke")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


def _authenticate(dvwa_url: str) -> dict[str, str]:
    """Log in to DVWA as admin/password, set security=low, return cookies."""
    import httpx

    with httpx.Client(base_url=dvwa_url, timeout=10.0, follow_redirects=False) as client:
        r = client.get("/login.php")
        if r.status_code not in (200, 302):
            pytest.skip(f"DVWA /login.php returned {r.status_code}")
        m = _USER_TOKEN_RE.search(r.text)
        if not m:
            pytest.skip("DVWA login form missing user_token — is setup complete?")
        r = client.post(
            "/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": m.group(1),
            },
        )
        if "login.php" in r.headers.get("location", ""):
            pytest.skip("DVWA login failed — wrong credentials or DB not initialised")

        r = client.get("/security.php", follow_redirects=True)
        m = _USER_TOKEN_RE.search(r.text)
        if m:
            client.post(
                "/security.php",
                data={"security": "low", "seclev_submit": "Submit", "user_token": m.group(1)},
            )
        cookies = {k: v for k, v in client.cookies.items()}

    cookies.setdefault("security", "low")
    if "PHPSESSID" not in cookies:
        pytest.skip(f"DVWA auth did not produce PHPSESSID (got {list(cookies)})")
    return cookies


@pytest.fixture(scope="session")
def crawled_dvwa_cookies(dvwa_url: str) -> dict[str, str]:
    """Authenticate, run the real katana crawl, return the surviving session.

    The crawl is the step that de-authenticated engagement 64940821. If
    katana still follows ``logout.php`` the returned cookies are dead and
    every methodology test below fails — which is precisely the regression
    these gates exist to catch.

    Sync + session-scoped (the single async crawl is driven via
    ``asyncio.run``) so it runs once and sidesteps pytest-asyncio's
    function-scoped event loop.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker CLI required to run the in-container katana crawl")
    ps = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    running = set(ps.stdout.split())
    required = {"clinkz-tools", "clinkz-dvwa"}
    if not required.issubset(running):
        pytest.skip(f"required containers not running: {sorted(required - running)}")

    cookies = _authenticate(dvwa_url)

    # The crawl must run inside the tools container against the docker alias.
    # The root conftest pins tool_exec_mode=local; flip to docker just for
    # the crawl, then restore so the methodology tests run host-local.
    from clinkz.config import settings as _settings

    resolver = ToolResolver()
    crawl_match = resolver.find_tool("web_crawling")
    if crawl_match is None or not getattr(crawl_match, "available", False):
        pytest.skip("No crawling tool available — bring up the clinkz-tools container")

    scan_scope = EngagementScope(
        name="pipeline-smoke-crawl",
        targets=[
            ScopeEntry(value=_DOCKER_ALIAS_URL, type=ScopeType.URL),
            ScopeEntry(value="clinkz-dvwa", type=ScopeType.DOMAIN),
        ],
    )
    agent = ScanAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=scan_scope,
        state=_make_state(),
        engagement_id="pipeline-smoke-crawl",
        resolver=resolver,
    )
    agent._session_cookies = dict(cookies)

    prev_mode = _settings.tool_exec_mode
    _settings.tool_exec_mode = "docker"
    try:
        urls = asyncio.run(agent._run_crawl_tool("katana", _DOCKER_ALIAS_URL))
    finally:
        _settings.tool_exec_mode = prev_mode

    # Sanity: the crawl genuinely ran and reached authenticated content —
    # otherwise a no-op crawl could mask the regression by never visiting
    # logout in the first place.
    assert any("/vulnerabilities/" in u for u in urls), (
        "Katana crawl surfaced no /vulnerabilities/* paths — the crawl did "
        f"not run against authenticated DVWA. URLs: {urls[:10]}"
    )
    return cookies


@pytest_asyncio.fixture
async def exploit_agent(dvwa_url: str, crawled_dvwa_cookies: dict[str, str]) -> ExploitAgent:
    """ExploitAgent loaded with the session that survived the real crawl."""
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=EngagementScope(
            name="pipeline-smoke-exploit",
            targets=[ScopeEntry(value=dvwa_url, type=ScopeType.URL)],
        ),
        state=_make_state(),
        engagement_id="pipeline-smoke-exploit",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._session_cookies = dict(crawled_dvwa_cookies)
    agent._methodology_llm = agent.llm
    return agent


async def test_sqli_finding_emitted_against_dvwa(
    dvwa_url: str, exploit_agent: ExploitAgent
) -> None:
    """SQLi must still be detected after the authenticated crawl runs.

    This is engagement 64940821's failure mode end to end: the crawl had
    killed the session, so the SQLi methodology saw the login page and
    emitted nothing. With the crawl no longer logging out, the session
    survives and the finding comes back.
    """
    url = f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    page = await exploit_agent._fetch_page(url, params=["id"])
    findings = await exploit_agent._test_sqli(page)
    assert findings, (
        f"_test_sqli emitted no finding at {url} after the crawl "
        f"(status={page.status}, params={page.input_params}). "
        "If status is a redirect, the crawl de-authenticated the session."
    )
    assert any("sql" in f.title.lower() for f in findings)


async def test_xss_reflected_finding_emitted_against_dvwa(
    dvwa_url: str, exploit_agent: ExploitAgent
) -> None:
    """Reflected XSS must still be detected after the authenticated crawl."""
    url = f"{dvwa_url}/vulnerabilities/xss_r/?name=test"
    page = await exploit_agent._fetch_page(url, params=["name"])
    findings = await exploit_agent._test_xss_reflected(page)
    assert findings, (
        f"_test_xss_reflected emitted no finding at {url} after the crawl "
        f"(status={page.status}, params={page.input_params}). "
        "If status is a redirect, the crawl de-authenticated the session."
    )
    assert any("xss" in f.title.lower() for f in findings)


async def test_brute_force_finding_emitted_against_dvwa(
    dvwa_url: str, exploit_agent: ExploitAgent
) -> None:
    """Brute-force (no lockout) must still be detected after the crawl."""
    url = f"{dvwa_url}/vulnerabilities/brute/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_brute_force(page)
    assert findings, (
        f"_test_brute_force emitted no finding at {url} after the crawl "
        f"(status={page.status}, forms={len(page.forms)}). "
        "If status is a redirect, the crawl de-authenticated the session."
    )
    assert any("brute" in f.title.lower() for f in findings)
