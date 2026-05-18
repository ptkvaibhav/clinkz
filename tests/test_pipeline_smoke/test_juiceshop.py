"""Pipeline smoke tests against a live Juice Shop container.

Sibling of :mod:`test_dvwa` — same shape, different target. Juice Shop's
attack surface is JavaScript-heavy and exposes a JSON API, so the
assertions differ: we look for the REST endpoints and the bundled JS
chunks rather than the PHP vuln pages.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

pytestmark = [pytest.mark.pipeline_smoke, pytest.mark.asyncio]


def _build_scope(url: str) -> EngagementScope:
    return EngagementScope(
        name="pipeline-smoke-juiceshop",
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


async def test_recon_fingerprints_juiceshop(juiceshop_url: str, outputs_root: Path) -> None:
    """Recon must surface Node.js / Express for a vanilla Juice Shop target.

    Catches regressions in the body-fingerprinting fallback used when the
    server omits an ``x-powered-by`` header.
    """
    from clinkz.agents.recon import ReconAgent
    from clinkz.llm.fallback import ResilientLLMClient
    from clinkz.observability.trace import (
        TraceWriter,
        set_active_trace_writer,
    )
    from clinkz.state import StateStore

    scope = _build_scope(juiceshop_url)
    engagement_id = "smoke-recon-juiceshop"

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
        result = await agent.run({"target": juiceshop_url})
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

    assert any("juice" in t or "express" in t or "node" in t or "angular" in t for t in all_tech), (
        f"Recon failed to fingerprint Juice Shop / Node / Angular. Got: {sorted(all_tech)}"
    )

    # Sidecar guarantees
    step_inputs_dir = outputs_root / engagement_id / "step_inputs"
    assert step_inputs_dir.exists(), "Recon did not write any step_inputs/"
    assert list(step_inputs_dir.glob("*.json")), "step_inputs/ exists but is empty"
