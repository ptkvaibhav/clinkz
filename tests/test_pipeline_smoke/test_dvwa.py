"""Pipeline smoke tests against a live DVWA container.

These tests run the real orchestrator (or one of its phase agents) end to
end and assert on the resulting trace + findings. They are slow (10-90s
each) and require DVWA running at ``http://localhost:8080`` — skipped
otherwise.

The rule the suite enforces: any fix that changes a tool wrapper, an
agent step, or an orchestration path requires a pipeline_smoke test that
would have caught the bug without it. Mocked unit tests are insufficient
because they let the orchestration glue silently drift.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

pytestmark = [pytest.mark.pipeline_smoke, pytest.mark.asyncio]


def _build_scope(url: str) -> EngagementScope:
    return EngagementScope(
        name="pipeline-smoke-dvwa",
        targets=[ScopeEntry(value=url, type=ScopeType.URL)],
    )


def _read_trace_lines(outputs_root: Path, engagement_id: str) -> list[dict]:
    trace = outputs_root / engagement_id / "trace.jsonl"
    if not trace.exists():
        return []
    lines: list[dict] = []
    for raw in trace.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            lines.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return lines


# ---------------------------------------------------------------------------
# Helpers — find_engagement_id reads the latest engagement that wrote a trace.
# ---------------------------------------------------------------------------


def _latest_engagement_id(outputs_root: Path) -> str:
    """Return the most recently-modified engagement subdirectory name."""
    candidates = [p for p in outputs_root.iterdir() if p.is_dir() and (p / "trace.jsonl").exists()]
    if not candidates:
        raise AssertionError(
            f"No engagement output written under {outputs_root}. "
            "The orchestrator did not produce a trace — check the run."
        )
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0].name


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_recon_fingerprints_dvwa(dvwa_url: str, outputs_root: Path) -> None:
    """Recon must surface Apache + PHP for a vanilla DVWA target.

    Asserts on the structured tech_stack, not on summary text — a regression
    that strips structured fingerprinting but keeps the LLM summary would
    pass a text-based assertion and silently break downstream agents.
    """
    from clinkz.agents.recon import ReconAgent
    from clinkz.llm.fallback import ResilientLLMClient
    from clinkz.observability.trace import (
        TraceWriter,
        set_active_trace_writer,
    )
    from clinkz.state import StateStore

    scope = _build_scope(dvwa_url)
    engagement_id = "smoke-recon"

    state = StateStore(":memory:")
    await state.connect()
    await state.create_engagement(scope.name, scope.model_dump())

    writer = TraceWriter(engagement_id=engagement_id)
    set_active_trace_writer(writer)
    try:
        try:
            llm = ResilientLLMClient(agent_role="recon")
        except Exception:
            pytest.skip("No LLM provider configured for recon")

        agent = ReconAgent(
            llm=llm,
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        result = await agent.run({"target": dvwa_url})
    finally:
        writer.close()
        set_active_trace_writer(None)
        await state.close()

    assert result.get("status") == "complete", result
    tech_stack = (result.get("result") or {}).get("tech_stack", {})
    tech_names = {(t.get("name") or "").lower() for t in tech_stack.get("technologies", [])}
    web_info = (result.get("result") or {}).get("web_info", {}) or {}
    body_techs = {(t or "").lower() for t in web_info.get("technologies_found", [])}
    all_tech = tech_names | body_techs

    assert any("apache" in t or "php" in t or "dvwa" in t for t in all_tech), (
        f"Recon failed to fingerprint Apache/PHP/DVWA. Got: {sorted(all_tech)}"
    )

    # Sidecar guarantees: the engagement must have produced step_inputs
    # for the named recon steps that wrap with _record_step.
    step_inputs_dir = outputs_root / engagement_id / "step_inputs"
    assert step_inputs_dir.exists(), "Recon did not write any step_inputs/"
    step_files = list(step_inputs_dir.glob("*.json"))
    assert len(step_files) >= 1, f"Expected ≥1 step_inputs file, got {len(step_files)}"

    step_names = set()
    for f in step_files:
        payload = json.loads(f.read_text(encoding="utf-8"))
        step_names.add(payload.get("step_name", ""))
    assert "port_scan" in step_names, f"Expected port_scan step recorded; got {step_names}"


async def test_scan_discovers_dvwa_vuln_pages_authenticated(
    dvwa_url: str, outputs_root: Path
) -> None:
    """Authenticated scan must surface the DVWA vulnerability endpoints.

    Authenticates as admin/password, runs the orchestrator's recon→scan
    flow, and asserts that the scan's discovered endpoints include the
    classic DVWA vuln pages (sqli, exec, xss_r). A regression that breaks
    cookie propagation or crawl scoping shows up here as a missing endpoint.
    """
    pytest.importorskip("httpx")
    import re as _re

    import httpx

    user_token_re = _re.compile(
        r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]+)['"]""", _re.IGNORECASE
    )

    # --- Authenticate to DVWA ---
    with httpx.Client(base_url=dvwa_url, timeout=10.0, follow_redirects=False) as client:
        r = client.get("/login.php")
        if r.status_code not in (200, 302):
            pytest.skip(f"DVWA /login.php returned {r.status_code}")
        m = user_token_re.search(r.text)
        if not m:
            pytest.skip("DVWA login form missing user_token")
        token = m.group(1)
        r = client.post(
            "/login.php",
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
        )
        if "login.php" in r.headers.get("location", ""):
            pytest.skip("DVWA login failed — wrong credentials or fresh install needed")

        r = client.get("/security.php", follow_redirects=True)
        m = user_token_re.search(r.text)
        if m:
            client.post(
                "/security.php",
                data={
                    "security": "low",
                    "seclev_submit": "Submit",
                    "user_token": m.group(1),
                },
            )

        cookies: dict[str, str] = {k: v for k, v in client.cookies.items()}
    cookies.setdefault("security", "low")
    if "PHPSESSID" not in cookies:
        pytest.skip(f"DVWA auth did not produce PHPSESSID (got {list(cookies)})")

    # --- Run the scan agent against DVWA with the authenticated cookies ---
    from clinkz.agents.scan import ScanAgent
    from clinkz.llm.fallback import ResilientLLMClient
    from clinkz.models.recon import (
        PortScanResult,
        ReconResult,
        ReconService,
        ServiceScanResult,
        TechStack,
        WebReconResult,
    )
    from clinkz.observability.trace import (
        TraceWriter,
        set_active_trace_writer,
    )
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    # The full scan needs a real crawler (katana / gospider / hakrawler).
    # Skip if none of them resolve — the fallback HTTP path can't surface
    # /vulnerabilities/* and the smoke assertion wouldn't be honest.
    resolver = ToolResolver()
    crawl_match = resolver.find_tool("web_crawling")
    if crawl_match is None or not getattr(crawl_match, "available", False):
        pytest.skip(
            "No crawling tool available (katana / gospider / hakrawler). "
            "Bring up the clinkz-tools container to run this smoke test."
        )

    scope = _build_scope(dvwa_url)
    engagement_id = "smoke-scan"

    recon_result = ReconResult(
        target=dvwa_url,
        ports=PortScanResult(open_ports=[80], tool_used="smoke"),
        services=ServiceScanResult(
            services=[ReconService(port=80, protocol="tcp", service_name="http")],
            tool_used="smoke",
        ),
        tech_stack=TechStack(technologies=[]),
        web_info=WebReconResult(),
        llm_summary="smoke recon stub",
    )

    state = StateStore(":memory:")
    await state.connect()
    await state.create_engagement(scope.name, scope.model_dump())

    writer = TraceWriter(engagement_id=engagement_id)
    set_active_trace_writer(writer)
    try:
        try:
            llm = ResilientLLMClient(agent_role="scan")
        except Exception:
            pytest.skip("No LLM provider configured for scan")

        agent = ScanAgent(
            llm=llm,
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        result = await agent.run(
            {
                "recon_result": recon_result.model_dump(mode="json"),
                "session_cookies": cookies,
            }
        )
    finally:
        writer.close()
        set_active_trace_writer(None)
        await state.close()

    assert result.get("status") == "complete", result
    scan_result = result.get("result") or {}
    endpoints_seen: list[dict] = []
    for svc_scan in scan_result.get("service_scans") or []:
        nested = (svc_scan.get("result") or {}) if isinstance(svc_scan, dict) else {}
        endpoints_seen.extend(nested.get("endpoints") or [])

    urls = " ".join(e.get("url", "") for e in endpoints_seen if isinstance(e, dict)).lower()
    # The orchestrator-driven crawl normally hits these paths; assert at least
    # one of the DVWA vuln endpoints is present.
    assert any(
        marker in urls
        for marker in ("/vulnerabilities/sqli", "/vulnerabilities/exec", "/vulnerabilities/xss_r")
    ), (
        "Scan failed to surface DVWA vuln endpoints. "
        f"endpoints={[e.get('url') for e in endpoints_seen if isinstance(e, dict)][:20]}"
    )

    # The trace must include at least one tool_call entry pointing at an
    # invocation_file. This is the regression guard for the recording layer.
    lines = _read_trace_lines(outputs_root, engagement_id)
    tool_call_lines = [ln for ln in lines if ln.get("category") == "tool_call"]
    assert tool_call_lines, "Scan ran but produced no tool_call trace events"
    assert any((ln.get("payload") or {}).get("invocation_file") for ln in tool_call_lines), (
        "No tool_call event linked to an invocation_file sidecar"
    )


async def test_exploit_plan_non_empty_with_endpoints(dvwa_url: str, outputs_root: Path) -> None:
    """ExploitAgent's planner must produce ≥1 task when given real endpoints.

    Doesn't run the exploits — just exercises the planning checkpoint
    against a ScanResult that contains live DVWA endpoints. Catches
    regressions where the LLM planning prompt or the deterministic seed
    plan drift apart.
    """
    from clinkz.agents.exploit import ExploitAgent
    from clinkz.llm.fallback import ResilientLLMClient
    from clinkz.models.scan import (
        Endpoint,
        HTTPScanResult,
        ScanResult,
    )
    from clinkz.models.scan import (
        ServiceScanResult as ScanServiceResult,
    )
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    scope = _build_scope(dvwa_url)
    engagement_id = "smoke-exploit-plan"

    state = StateStore(":memory:")
    await state.connect()
    await state.create_engagement(scope.name, scope.model_dump())

    try:
        llm = ResilientLLMClient(agent_role="exploit")
    except Exception:
        pytest.skip("No LLM provider configured for exploit")

    endpoints = [
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/sqli/",
            method="GET",
            params=["id"],
        ),
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/exec/",
            method="POST",
            params=["ip"],
        ),
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/xss_r/",
            method="GET",
            params=["name"],
        ),
    ]
    http_result = HTTPScanResult(endpoints=endpoints)
    scan_result = ScanResult(
        target=dvwa_url,
        service_scans=[
            ScanServiceResult(service_type="http", port=80, result=http_result),
        ],
        total_endpoints=len(endpoints),
    )

    agent = ExploitAgent(
        llm=llm,
        tools=[],
        scope=scope,
        state=state,
        engagement_id=engagement_id,
        resolver=ToolResolver(),
    )

    plan = await agent._llm_plan_exploits(scan_result, research_result=None, recon_result=None)
    assert plan is not None, "Exploit planner returned None"
    assert getattr(plan, "tasks", []), (
        f"Exploit plan has no tasks for {len(endpoints)} live endpoints"
    )

    # Sanity: the planner should have hit at least one endpoint path
    plan_text = " ".join(getattr(t, "endpoint_url", "") for t in plan.tasks).lower()
    assert any(marker in plan_text for marker in ("sqli", "exec", "xss")), (
        f"Plan endpoints don't match the scan endpoints: {plan_text[:300]}"
    )

    await state.close()
