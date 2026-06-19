"""Tests for the persistent knowledge base."""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.knowledge.seed_playbook import seed_tier1_tests


@pytest_asyncio.fixture
async def kb(tmp_path):
    """Create a temporary knowledge base for each test."""
    db_path = str(tmp_path / "test_kb.db")
    kb = await PersistentKnowledgeBase.create(db_path)
    yield kb
    await kb.close()


@pytest.mark.asyncio
async def test_create_and_close(tmp_path):
    """DB file created, tables exist."""
    db_path = str(tmp_path / "create_test.db")
    kb = await PersistentKnowledgeBase.create(db_path)

    assert os.path.exists(db_path)

    # Verify tables exist by querying them
    cursor = await kb._db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = {row["name"] for row in await cursor.fetchall()}
    assert "playbook_entries" in tables
    assert "past_engagements" in tables
    assert "technique_results" in tables
    assert "technology_relations" in tables

    await kb.close()


@pytest.mark.asyncio
async def test_add_and_get_playbook_entry(kb):
    """Add entry, retrieve by technology."""
    entry_id = await kb.add_playbook_entry(
        tier=2,
        technique_name="test_apache_rce",
        technology_pattern="apache.*2\\.4",
        technique_description="Test Apache 2.4 RCE",
        steps=["Step 1", "Step 2"],
        severity="critical",
        applicable_vuln_classes=["rce"],
    )
    assert entry_id is not None

    results = await kb.get_playbook_for_technology("Apache 2.4.51")
    assert len(results) == 1
    assert results[0]["technique_name"] == "test_apache_rce"
    assert results[0]["tier"] == 2


@pytest.mark.asyncio
async def test_tier_filtering(kb):
    """Add entries at tiers 1/2/3, verify get_tier1/2/3 return correct subsets."""
    await kb.add_playbook_entry(
        tier=1, technique_name="t1_test", technology_pattern=".*", severity="info"
    )
    await kb.add_playbook_entry(
        tier=2,
        technique_name="t2_test",
        technology_pattern="nginx.*",
        severity="high",
    )
    await kb.add_playbook_entry(
        tier=3,
        technique_name="t3_test",
        technology_pattern="nginx.*",
        severity="medium",
    )

    tier1 = await kb.get_tier1_tests()
    assert len(tier1) == 1
    assert tier1[0]["technique_name"] == "t1_test"

    tier2 = await kb.get_tier2_tests("nginx 1.21")
    assert len(tier2) == 1
    assert tier2[0]["technique_name"] == "t2_test"

    tier3 = await kb.get_tier3_tests("nginx 1.21")
    assert len(tier3) == 1
    assert tier3[0]["technique_name"] == "t3_test"

    # Tier 2/3 should not match unrelated tech
    assert await kb.get_tier2_tests("Apache 2.4") == []
    assert await kb.get_tier3_tests("Apache 2.4") == []


@pytest.mark.asyncio
async def test_technology_pattern_matching(kb):
    """Entry with pattern "apache.*2\\.4" matches "Apache 2.4.51" but not "nginx"."""
    await kb.add_playbook_entry(
        tier=2,
        technique_name="apache24_test",
        technology_pattern="apache.*2\\.4",
        severity="high",
    )

    matches = await kb.get_playbook_for_technology("Apache 2.4.51")
    assert len(matches) == 1

    no_match = await kb.get_playbook_for_technology("nginx 1.21.0")
    assert len(no_match) == 0


@pytest.mark.asyncio
async def test_record_technique_result(kb):
    """Record success/failure, verify times_tried/times_succeeded increment."""
    entry_id = await kb.add_playbook_entry(
        tier=1, technique_name="result_test", technology_pattern=".*", severity="info"
    )

    # Record a success
    await kb.record_technique_result(entry_id, "eng-001", success=True, finding_id="f-001")
    # Record a failure
    await kb.record_technique_result(entry_id, "eng-001", success=False)

    cursor = await kb._db.execute(
        "SELECT times_tried, times_succeeded FROM playbook_entries WHERE id = ?",
        (entry_id,),
    )
    row = await cursor.fetchone()
    assert row["times_tried"] == 2
    assert row["times_succeeded"] == 1


@pytest.mark.asyncio
async def test_update_success_rates(kb):
    """Add results, recalculate, verify rates."""
    entry_id = await kb.add_playbook_entry(
        tier=1, technique_name="rate_test", technology_pattern=".*", severity="info"
    )

    # 3 tries, 2 successes
    await kb.record_technique_result(entry_id, "eng-001", success=True)
    await kb.record_technique_result(entry_id, "eng-002", success=True)
    await kb.record_technique_result(entry_id, "eng-003", success=False)

    await kb.update_success_rates()

    cursor = await kb._db.execute(
        "SELECT success_rate FROM playbook_entries WHERE id = ?", (entry_id,)
    )
    row = await cursor.fetchone()
    assert abs(row["success_rate"] - 2.0 / 3.0) < 0.01


@pytest.mark.asyncio
async def test_technology_relations(kb):
    """Add relation, query related techs."""
    await kb.add_technology_relation(
        tech_a="Apache 2.4",
        tech_b="Apache 2.2",
        relation_type="successor",
        similarity_score=0.9,
        notes="Major version upgrade",
    )

    related = await kb.get_related_technologies("Apache 2.4")
    assert len(related) == 1
    assert related[0]["tech_b"] == "Apache 2.2"
    assert related[0]["similarity_score"] == 0.9

    # Also found via tech_b
    related_b = await kb.get_related_technologies("Apache 2.2")
    assert len(related_b) == 1


@pytest.mark.asyncio
async def test_record_engagement(kb):
    """Record engagement, verify retrieval."""
    await kb.record_engagement(
        engagement_id="eng-test-001",
        target_description="Test DVWA instance",
        technologies=["PHP 8.1", "Apache 2.4", "MySQL 8.0"],
        findings_count=5,
        findings_summary=[{"title": "SQLi in login", "severity": "high", "category": "sqli"}],
        duration_minutes=30,
    )

    cursor = await kb._db.execute(
        "SELECT * FROM past_engagements WHERE engagement_id = ?",
        ("eng-test-001",),
    )
    row = await cursor.fetchone()
    assert row is not None
    assert row["target_description"] == "Test DVWA instance"
    assert row["findings_count"] == 5
    assert row["duration_minutes"] == 30


@pytest.mark.asyncio
async def test_seed_tier1(kb):
    """Run seed function, verify all 16 entries exist, run again = no duplicates."""
    await seed_tier1_tests(kb)
    entries = await kb.get_tier1_tests()
    assert len(entries) == 16

    # Run again — should be idempotent
    await seed_tier1_tests(kb)
    entries = await kb.get_tier1_tests()
    assert len(entries) == 16


@pytest.mark.asyncio
async def test_get_past_results_for_technology(kb):
    """End-to-end join query."""
    entry_id = await kb.add_playbook_entry(
        tier=2,
        technique_name="join_test",
        technology_pattern="php.*8",
        severity="high",
        applicable_vuln_classes=["sqli"],
    )
    await kb.record_technique_result(
        entry_id,
        "eng-join-001",
        success=True,
        technology_actual="PHP 8.1",
        finding_id="f-join-001",
        response_summary="SQLi confirmed",
    )

    results = await kb.get_past_results_for_technology("PHP 8.2")
    assert len(results) == 1
    assert results[0]["technique_name"] == "join_test"
    assert results[0]["success"] == 1
    assert results[0]["finding_id"] == "f-join-001"
