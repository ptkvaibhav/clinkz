"""Regression gate: findings survive a phase interruption (engagement ff06b952).

ff06b952 verified 3 real vulnerabilities in the exploit phase (lfi, file_upload,
xss_dom) but lost ALL of them: findings were only persisted in an end-of-phase
batch by the orchestrator, and the phase was force-killed at the 10-minute cap
before that batch ran — so the report came out empty.

The fix makes the Exploit Agent (a) persist each verified finding to the state
store the instant a methodology returns it and (b) stop dispatching new tasks at
a cooperative deadline instead of being force-killed mid-task. This test proves
the durability half: run the exploit phase against DVWA with a deadline short
enough to GUARANTEE interruption, then assert the findings verified before the
deadline are present in the state store and queryable by ``engagement_id`` —
exactly the property ff06b952 violated.

The Exploit Agent is driven directly with a *real* ``StateStore`` (no LLM key,
deterministic methodology path), so the gate is fast and reliable — unlike the
full-orchestrator E2E in ``test_exploit_execution``. Crucially, there is no
orchestrator here, so the batch-persist safety net never runs: the ONLY way a
finding reaches the store is the incremental persist. A non-empty
``get_findings()`` after an interrupted phase is therefore unambiguous proof
that work is durable across interruption.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scan import Endpoint, HTTPScanResult, ScanResult, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

pytestmark = [pytest.mark.pipeline_smoke, pytest.mark.asyncio]

_USER_TOKEN_RE = re.compile(
    r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]+)['"]""", re.IGNORECASE
)


class _SilentLLM(LLMClient):
    """Neutral LLM stub.

    Forces the adaptive methodologies down their deterministic detection path
    and the planner onto the deterministic plan (one task per Tier 1 test per
    endpoint), so the plan is large enough to outlast the short deadline.
    """

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


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


def _scan_result(dvwa_url: str) -> ScanResult:
    """A scan result covering the ff06b952 trio plus proven-emitting endpoints.

    The SQLi endpoint is listed first: the deterministic plan runs every Tier 1
    test on endpoint[0] before moving on, and ``_test_sqli`` /
    ``_test_security_headers`` against DVWA emit quickly — so at least one
    finding is verified (and persisted) well before the short deadline.
    """
    endpoints = [
        Endpoint(url=f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit", params=["id"]),
        Endpoint(url=f"{dvwa_url}/vulnerabilities/xss_r/?name=test", params=["name"]),
        Endpoint(url=f"{dvwa_url}/vulnerabilities/fi/?page=include.php", params=["page"]),
        Endpoint(url=f"{dvwa_url}/vulnerabilities/upload/", params=[]),
        Endpoint(url=f"{dvwa_url}/vulnerabilities/xss_d/?default=English", params=["default"]),
        Endpoint(url=f"{dvwa_url}/vulnerabilities/brute/", params=[]),
    ]
    return ScanResult(
        target=dvwa_url,
        service_scans=[
            ServiceScanResult(
                service_type="http",
                port=80,
                result=HTTPScanResult(endpoints=endpoints),
            )
        ],
        total_endpoints=len(endpoints),
    )


@pytest_asyncio.fixture
async def dvwa_cookies(dvwa_url: str) -> dict[str, str]:
    """Authenticated DVWA session cookies (security=low)."""
    return _authenticate(dvwa_url)


async def test_findings_persist_on_phase_interruption(
    dvwa_url: str, dvwa_cookies: dict[str, str], tmp_path: Path
) -> None:
    """Findings verified before a phase deadline must be queryable from the store.

    Runs the exploit phase against authenticated DVWA with a deadline far shorter
    than the full plan needs, guaranteeing the phase is interrupted. The findings
    verified in that window must already be in the state store, queryable by
    ``engagement_id`` — the durability property engagement ff06b952 lost.
    """
    # A real on-disk state store (the report and any post-mortem query read from
    # here). Engagement must exist first — findings reference it.
    db_path = tmp_path / "interruption.db"
    async with StateStore(db_path) as state:
        scope = EngagementScope(
            name="phase-interruption-smoke",
            targets=[ScopeEntry(value=dvwa_url, type=ScopeType.URL)],
        )
        engagement_id = await state.create_engagement(scope.name, scope.model_dump())

        agent = ExploitAgent(
            llm=_SilentLLM(),
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            resolver=ToolResolver(),
            persistent_kb=None,
        )
        agent._session_cookies = dict(dvwa_cookies)
        agent._methodology_llm = agent.llm

        # Reproduce the interruption deterministically. The real ff06b952 phase
        # was slow because of live LLM latency; the deterministic methodology
        # path here is fast, so a wall-clock budget can't reliably land mid-plan
        # on every machine. Instead, arm the cooperative deadline the instant the
        # first finding is persisted — the next dispatch check then stops the
        # phase. This exercises the real persist + real cooperative-stop path
        # (state.add_finding, _should_stop_dispatching, stopped_early) with a
        # plan far larger than the one task that ran, guaranteeing interruption.
        original_persist = agent._persist_finding
        armed = {"done": False}

        async def _persist_then_arm(finding: Any) -> None:
            await original_persist(finding)
            if not armed["done"]:
                armed["done"] = True
                # Move the deadline into the past so the next dispatch stops.
                agent._deadline_ts = time.monotonic() - 1.0

        agent._persist_finding = _persist_then_arm  # type: ignore[method-assign]

        result_payload = await agent.run(
            {
                "scan_result": _scan_result(dvwa_url),
                "research_result": {"technologies": [], "runbook": []},
                "session_cookies": dict(dvwa_cookies),
                # Generous real deadline — the persist wrapper is what trips the
                # stop, right after the first finding is durably written.
                "deadline_ts": time.monotonic() + 300.0,
                "stop_margin_seconds": 0.0,
            }
        )

        result = result_payload["result"]

        # Precondition: at least one finding was verified (and persisted) before
        # the interruption. sqli / security_headers against DVWA emit fast — if
        # this fails, check DVWA auth/setup; the deterministic methodologies
        # themselves are gated by test_finding_emission.
        assert result["total_findings"] >= 1, (
            "No findings verified before the interruption — cannot demonstrate "
            "durability. Check that DVWA is authenticated and security=low. "
            f"tests_run={result['total_tests_run']}"
        )

        # The phase must have stopped early (mid-plan), not run to completion —
        # that is the ff06b952 condition we are reproducing.
        assert result["stopped_early"] is True, (
            "Exploit phase did not stop early — the interruption never triggered, "
            f"so durability under a force-kill is untested. tests_run={result['total_tests_run']}"
        )
        assert result["total_tests_run"] < result["plan"]["tier1_count"], (
            "Phase ran every planned task — interruption did not land mid-plan. "
            f"tests_run={result['total_tests_run']}, planned={result['plan']['tier1_count']}"
        )

        # THE durability assertion: every finding the agent verified mid-flight
        # is already in the state store, queryable by engagement_id — with no
        # orchestrator batch-persist in this harness, the incremental write is
        # the only thing that could have put them there.
        stored = await state.get_findings(engagement_id)
        stored_ids = {f.get("id") for f in stored}
        result_ids = {f["id"] for f in result["findings"]}

        assert stored, (
            "State store has zero findings after an interrupted phase — the "
            "ff06b952 regression: verified findings were lost on interruption."
        )
        # Strict invariant: the store holds EXACTLY the findings the agent
        # verified before stopping — nothing verified was lost (subset of result
        # ⊆ store) and nothing was fabricated. A persist failure would leave a
        # finding in the result but not the store, and this catches it.
        assert result_ids == stored_ids, (
            "State store does not match the verified findings. "
            f"Missing from store: {sorted(result_ids - stored_ids)}; "
            f"unexpected in store: {sorted(stored_ids - result_ids)}. "
            "Incremental persistence did not durably write every finding."
        )
