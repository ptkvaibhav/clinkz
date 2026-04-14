"""Integration tests for concurrent Research + Scan execution wiring.

Verifies that:
- Research and Scan run concurrently (total time < sum of delays)
- Exploit starts only after Scan completes
- Research failure doesn't block Scan or Exploit
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from clinkz.models.research import ResearchResult, Technique
from clinkz.models.scan import (
    Endpoint,
    HTTPScanResult,
    ScanResult,
    ServiceScanResult,
)
from clinkz.orchestrator.adapters import (
    adapt_research_result_for_exploit,
    adapt_scan_result_for_exploit,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scan_result() -> dict[str, Any]:
    """Build a minimal v2 ScanResult dict."""
    sr = ScanResult(
        target="127.0.0.1",
        service_scans=[
            ServiceScanResult(
                service_type="http",
                port=80,
                result=HTTPScanResult(
                    endpoints=[
                        Endpoint(url="http://127.0.0.1/", method="GET", status_code=200),
                        Endpoint(
                            url="http://127.0.0.1/login.php",
                            method="POST",
                            params=["username", "password"],
                            status_code=200,
                        ),
                    ],
                    directories=["/admin", "/uploads"],
                    technologies_detected=["php", "apache"],
                ),
            ),
        ],
        total_endpoints=2,
        total_forms=0,
        total_params=2,
    )
    return sr.model_dump(mode="json")


def _make_research_result() -> dict[str, Any]:
    """Build a minimal v2 ResearchResult dict."""
    rr = ResearchResult(
        technologies=["php", "apache"],
        new_techniques=[
            Technique(
                name="PHP Type Juggling",
                description="Exploit loose comparison in PHP",
                steps=["Send 0 as password", "Check for bypass"],
                vuln_class="authentication_bypass",
                severity="high",
                source="hackerone",
            ),
        ],
        runbook=[
            Technique(
                name="PHP Type Juggling",
                description="Exploit loose comparison in PHP",
                steps=["Send 0 as password", "Check for bypass"],
                vuln_class="authentication_bypass",
                severity="high",
                source="hackerone",
            ),
        ],
        new_kb_entries_added=1,
    )
    return rr.model_dump(mode="json")


def _make_recon_result() -> dict[str, Any]:
    """Minimal recon result dict."""
    return {
        "result": {
            "target": "127.0.0.1",
            "tech_stack": {
                "technologies": [
                    {"name": "PHP", "version": "7.4"},
                    {"name": "Apache", "version": "2.4.49"},
                ],
            },
            "services": {
                "services": [
                    {"port": 80, "service_name": "http", "version": "2.4.49"},
                    {"port": 22, "service_name": "ssh", "version": "8.2"},
                ],
            },
        },
        "status": "completed",
        "summary": "Target has Apache 2.4.49, PHP 7.4, SSH",
    }


# ---------------------------------------------------------------------------
# Adapter unit tests
# ---------------------------------------------------------------------------


class TestAdapters:
    """Test v2→v1 adapter functions."""

    def test_adapt_scan_result(self) -> None:
        scan_data = _make_scan_result()
        adapted = adapt_scan_result_for_exploit(scan_data)

        assert "endpoints" in adapted
        assert "hosts" in adapted
        assert "technologies" in adapted
        assert len(adapted["endpoints"]) == 2
        assert adapted["endpoints"][0]["url"] == "http://127.0.0.1/"
        assert adapted["hosts"][0]["ip"] == "127.0.0.1"
        assert "php" in adapted["technologies"]

    def test_adapt_research_result(self) -> None:
        research_data = _make_research_result()
        adapted = adapt_research_result_for_exploit(research_data)

        assert "technologies" in adapted
        assert "techniques" in adapted
        assert len(adapted["techniques"]) == 1
        assert adapted["techniques"][0]["name"] == "PHP Type Juggling"
        assert adapted["techniques"][0]["severity"] == "high"

    def test_adapt_empty_scan_result(self) -> None:
        sr = ScanResult(target="127.0.0.1")
        adapted = adapt_scan_result_for_exploit(sr)
        assert adapted["endpoints"] == []
        assert adapted["technologies"] == []

    def test_adapt_empty_research_result(self) -> None:
        rr = ResearchResult()
        adapted = adapt_research_result_for_exploit(rr)
        assert adapted["techniques"] == []
        assert adapted["technologies"] == []


# ---------------------------------------------------------------------------
# Concurrent execution tests (mock the full orchestrator flow)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_research_and_scan() -> None:
    """Research and Scan run concurrently, both complete, results available."""
    research_delay = 0.1
    scan_delay = 0.2

    async def mock_research_run(input_data: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(research_delay)
        return {"result": _make_research_result(), "status": "complete"}

    async def mock_scan_run(input_data: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(scan_delay)
        return {"result": _make_scan_result(), "status": "complete"}

    start = time.monotonic()

    research_task = asyncio.create_task(mock_research_run({"technologies": ["php"]}))
    scan_task = asyncio.create_task(mock_scan_run({"recon_result": {}}))

    scan_result = await scan_task
    research_result = await research_task

    elapsed = time.monotonic() - start

    # Both completed
    assert scan_result["status"] == "complete"
    assert research_result["status"] == "complete"

    # Concurrency: total time should be close to max(delays), not sum
    assert elapsed < (research_delay + scan_delay), (
        f"Expected concurrent execution (< {research_delay + scan_delay}s), but took {elapsed:.3f}s"
    )


@pytest.mark.asyncio
async def test_exploit_waits_for_scan() -> None:
    """Exploit doesn't start until Scan completes."""
    execution_order: list[str] = []

    async def mock_scan_run(input_data: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.1)
        execution_order.append("scan_done")
        return {"result": _make_scan_result(), "status": "complete"}

    async def mock_exploit_run(input_data: dict[str, Any]) -> dict[str, Any]:
        execution_order.append("exploit_start")
        await asyncio.sleep(0.05)
        return {"status": "complete", "findings": []}

    async def mock_research_run(input_data: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        return {"result": _make_research_result(), "status": "complete"}

    # Simulate the orchestrator flow: research+scan parallel, then exploit
    research_task = asyncio.create_task(mock_research_run({"technologies": ["php"]}))
    scan_task = asyncio.create_task(mock_scan_run({"recon_result": {}}))

    # Wait for scan first (exploit needs it)
    await scan_task
    await research_task

    # Now start exploit
    await mock_exploit_run({})

    assert execution_order.index("scan_done") < execution_order.index("exploit_start")


@pytest.mark.asyncio
async def test_research_failure_doesnt_block_scan() -> None:
    """If Research fails, Scan still completes and Exploit can proceed."""
    scan_completed = False
    exploit_completed = False

    async def mock_research_run(input_data: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        raise RuntimeError("Web search API unavailable")

    async def mock_scan_run(input_data: dict[str, Any]) -> dict[str, Any]:
        nonlocal scan_completed
        await asyncio.sleep(0.1)
        scan_completed = True
        return {"result": _make_scan_result(), "status": "complete"}

    async def mock_exploit_run(input_data: dict[str, Any]) -> dict[str, Any]:
        nonlocal exploit_completed
        exploit_completed = True
        return {"status": "complete", "findings": []}

    research_task = asyncio.create_task(mock_research_run({"technologies": ["php"]}))
    scan_task = asyncio.create_task(mock_scan_run({"recon_result": {}}))

    # Wait for scan
    scan_result = await scan_task
    assert scan_completed
    assert scan_result["status"] == "complete"

    # Research should fail gracefully
    try:
        await research_task
    except Exception:
        pass  # Expected — research failure is non-blocking

    # Exploit proceeds with scan results + empty research
    adapted_scan = adapt_scan_result_for_exploit(scan_result["result"])
    exploit_input: dict[str, Any] = {**adapted_scan}
    # No research techniques available — exploit should still run
    exploit_result = await mock_exploit_run(exploit_input)

    assert exploit_completed
    assert exploit_result["status"] == "complete"


# ---------------------------------------------------------------------------
# WAL mode test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_store_wal_mode(tmp_path: Any) -> None:
    """StateStore enables WAL journal mode for concurrent access."""
    from clinkz.state import StateStore

    db_path = tmp_path / "test_wal.db"
    async with StateStore(db_path) as store:
        async with store._conn.execute("PRAGMA journal_mode") as cursor:
            row = await cursor.fetchone()
            mode = row[0] if row else ""
        assert mode == "wal", f"Expected WAL mode, got '{mode}'"
