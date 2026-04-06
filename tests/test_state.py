"""Unit tests for StateStore v2 additions: endpoints, runbook, migrations.

Tests cover:
- Endpoint CRUD + deduplication + filtering
- Runbook CRUD + deduplication
- ALTER TABLE migrations (service_type on targets, source_technique on findings)
- Per-agent LLM config in Settings
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio

from clinkz.config import Settings
from clinkz.state import StateStore

EID = "eng-test-0001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def store(tmp_path: Path) -> StateStore:
    """Yield an in-memory-like StateStore backed by a temp file."""
    s = StateStore(tmp_path / "test.db")
    await s.connect()
    # Seed an engagement
    await s._conn.execute(
        "INSERT INTO engagements (id, name, scope_json, created_at, updated_at) "
        "VALUES (?, 'Test', '{}', '2026-01-01', '2026-01-01')",
        (EID,),
    )
    await s._conn.commit()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------


class TestEndpoints:
    @pytest.mark.asyncio
    async def test_add_and_get(self, store: StateStore) -> None:
        eid = await store.add_endpoint(
            EID,
            url="http://target.local/api/login",
            method="POST",
            parameters={"username": "admin"},
            service_type="http",
            discovered_by="recon",
            port=8080,
            notes="login form",
        )
        assert eid
        rows = await store.get_endpoints(EID)
        assert len(rows) == 1
        assert rows[0]["url"] == "http://target.local/api/login"
        assert rows[0]["method"] == "POST"
        assert rows[0]["parameters"] == {"username": "admin"}
        assert rows[0]["service_type"] == "http"
        assert rows[0]["discovered_by"] == "recon"
        assert rows[0]["port"] == 8080
        assert rows[0]["notes"] == "login form"
        assert rows[0]["status"] == "discovered"

    @pytest.mark.asyncio
    async def test_dedup_same_url_method(self, store: StateStore) -> None:
        id1 = await store.add_endpoint(EID, url="http://x.com/a", method="GET")
        id2 = await store.add_endpoint(
            EID, url="http://x.com/a", method="GET", notes="updated"
        )
        assert id1 == id2  # same endpoint returned
        rows = await store.get_endpoints(EID)
        assert len(rows) == 1
        assert rows[0]["notes"] == "updated"

    @pytest.mark.asyncio
    async def test_different_method_not_dedup(self, store: StateStore) -> None:
        id1 = await store.add_endpoint(EID, url="http://x.com/a", method="GET")
        id2 = await store.add_endpoint(EID, url="http://x.com/a", method="POST")
        assert id1 != id2
        rows = await store.get_endpoints(EID)
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_filter_by_status(self, store: StateStore) -> None:
        eid = await store.add_endpoint(EID, url="http://x.com/1")
        await store.add_endpoint(EID, url="http://x.com/2")
        await store.update_endpoint_status(eid, "tested", tested_by="exploit")

        discovered = await store.get_endpoints(EID, status="discovered")
        assert len(discovered) == 1
        assert discovered[0]["url"] == "http://x.com/2"

        tested = await store.get_endpoints(EID, status="tested")
        assert len(tested) == 1
        assert tested[0]["tested_by"] == "exploit"

    @pytest.mark.asyncio
    async def test_filter_by_service_type(self, store: StateStore) -> None:
        await store.add_endpoint(EID, url="http://x.com/a", service_type="http")
        await store.add_endpoint(EID, url="ssh://x.com", service_type="ssh")

        http_eps = await store.get_endpoints(EID, service_type="http")
        assert len(http_eps) == 1
        ssh_eps = await store.get_endpoints(EID, service_type="ssh")
        assert len(ssh_eps) == 1

    @pytest.mark.asyncio
    async def test_get_new_endpoints(self, store: StateStore) -> None:
        eid1 = await store.add_endpoint(EID, url="http://x.com/1")
        await store.add_endpoint(EID, url="http://x.com/2")
        await store.update_endpoint_status(eid1, "testing")

        new = await store.get_new_endpoints(EID)
        assert len(new) == 1
        assert new[0]["url"] == "http://x.com/2"

    @pytest.mark.asyncio
    async def test_update_endpoint_status(self, store: StateStore) -> None:
        eid = await store.add_endpoint(EID, url="http://x.com/a")
        await store.update_endpoint_status(eid, "skipped", tested_by="scan")

        rows = await store.get_endpoints(EID)
        assert rows[0]["status"] == "skipped"
        assert rows[0]["tested_by"] == "scan"


# ---------------------------------------------------------------------------
# Runbook tests
# ---------------------------------------------------------------------------


class TestRunbook:
    @pytest.mark.asyncio
    async def test_add_and_get(self, store: StateStore) -> None:
        rid = await store.add_runbook_entry(
            EID,
            technology="nginx 1.24",
            technique_name="path traversal",
            technique_description="Bypass with ..;/",
            source_url="https://hackerone.com/reports/123",
            source_type="hackerone",
            steps=["Send request", "Check response"],
            applicable_to=["lfi", "path_traversal"],
            cve_id="CVE-2024-1234",
            severity="high",
        )
        assert rid is not None
        rows = await store.get_runbook_for_technology(EID, "nginx 1.24")
        assert len(rows) == 1
        r = rows[0]
        assert r["technique_name"] == "path traversal"
        assert r["steps"] == ["Send request", "Check response"]
        assert r["applicable_to"] == ["lfi", "path_traversal"]
        assert r["cve_id"] == "CVE-2024-1234"
        assert r["severity"] == "high"
        assert r["source_type"] == "hackerone"

    @pytest.mark.asyncio
    async def test_dedup_same_tech_technique(self, store: StateStore) -> None:
        r1 = await store.add_runbook_entry(
            EID, technology="nginx", technique_name="path traversal"
        )
        r2 = await store.add_runbook_entry(
            EID, technology="nginx", technique_name="path traversal"
        )
        assert r1 is not None
        assert r2 is None  # duplicate skipped
        rows = await store.get_all_runbook_entries(EID)
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_different_technique_not_dedup(self, store: StateStore) -> None:
        await store.add_runbook_entry(EID, technology="nginx", technique_name="t1")
        await store.add_runbook_entry(EID, technology="nginx", technique_name="t2")
        rows = await store.get_runbook_for_technology(EID, "nginx")
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_get_all_runbook_entries(self, store: StateStore) -> None:
        await store.add_runbook_entry(EID, technology="nginx", technique_name="t1")
        await store.add_runbook_entry(EID, technology="apache", technique_name="t2")
        rows = await store.get_all_runbook_entries(EID)
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# Migration tests (new columns on existing tables)
# ---------------------------------------------------------------------------


class TestMigrations:
    @pytest.mark.asyncio
    async def test_targets_service_type_column(self, store: StateStore) -> None:
        """The targets table should have a service_type column after migration."""
        tid = await store.upsert_target(EID, {"ip": "10.0.0.1"})
        async with store._conn.execute(
            "SELECT service_type FROM targets WHERE id=?", (tid,)
        ) as cursor:
            row = await cursor.fetchone()
        assert row["service_type"] == "other"

    @pytest.mark.asyncio
    async def test_findings_source_technique_column(self, store: StateStore) -> None:
        """The findings table should have a source_technique column after migration."""
        fid = await store.add_finding(EID, {"title": "XSS"})
        # Verify column exists and is NULL by default
        async with store._conn.execute(
            "SELECT source_technique FROM findings WHERE id=?", (fid,)
        ) as cursor:
            row = await cursor.fetchone()
        assert row["source_technique"] is None

    @pytest.mark.asyncio
    async def test_idempotent_reconnect(self, store: StateStore) -> None:
        """Calling connect() twice should not fail (migrations are idempotent)."""
        await store.close()
        await store.connect()
        # Should still work
        rows = await store.get_endpoints(EID)
        assert isinstance(rows, list)


# ---------------------------------------------------------------------------
# Per-agent LLM config tests
# ---------------------------------------------------------------------------


class TestPerAgentLLMConfig:
    def test_defaults(self) -> None:
        s = Settings()
        assert s.recon_llm_provider == "gemini"
        assert s.scan_llm_provider == "gemini"
        assert s.exploit_llm_provider == "gemini"
        assert s.research_llm_provider == "gemini"
        assert s.report_llm_provider == "gemini"

    def test_override_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECON_LLM_PROVIDER", "openai")
        monkeypatch.setenv("EXPLOIT_LLM_PROVIDER", "ollama")
        s = Settings.from_env()
        assert s.recon_llm_provider == "openai"
        assert s.exploit_llm_provider == "ollama"
        # Unchanged defaults
        assert s.scan_llm_provider == "gemini"
