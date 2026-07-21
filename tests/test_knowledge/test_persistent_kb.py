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
    """Run seed function, verify all 19 entries exist, run again = no duplicates."""
    await seed_tier1_tests(kb)
    entries = await kb.get_tier1_tests()
    assert len(entries) == 19

    # Run again — should be idempotent
    await seed_tier1_tests(kb)
    entries = await kb.get_tier1_tests()
    assert len(entries) == 19


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


# ---------------------------------------------------------------------------
# Layer-2 capability memory (discovery learning loop, §2.2 / §3 / §S1.2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capability_tables_exist(tmp_path):
    """The two Layer-2 tables are created, with NO target-identity column (§5.3)."""
    kb = await PersistentKnowledgeBase.create(str(tmp_path / "cap.db"))
    cursor = await kb._db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row["name"] for row in await cursor.fetchall()}
    assert "capability_facts" in tables
    assert "capability_observations" in tables
    # Schema-level exfil guardrail: no host/URL/IP/port/secret column anywhere.
    forbidden = {"host", "hostname", "url", "ip", "ip_address", "port", "target", "secret", "token"}
    for table in ("capability_facts", "capability_observations"):
        cursor = await kb._db.execute(f"PRAGMA table_info({table})")
        cols = {row["name"].lower() for row in await cursor.fetchall()}
        assert cols.isdisjoint(forbidden), f"{table} leaks target identity: {cols & forbidden}"
    await kb.close()


@pytest.mark.asyncio
async def test_capability_confirmed_upsert_and_observation(kb):
    """A confirmed fact upserts once on its UNIQUE key; a confirming observation
    links (not copies) the evidence; confidence is a positive PRIOR."""
    assert await kb.get_capability_facts() == []  # before: 0 rows
    fid = await kb.upsert_capability_fact(
        technology_key="log4j-core",
        version_predicate="=2.14.1",
        primitive_class="log_interpolation",
        sink_shape_id="log4j.log_sink",
        engagement_id="eng-A",
        confirmation_primitive="P6",
        evidence_grade="confirmed",
        last_outcome="confirmed",
    )
    await kb.add_capability_observation(
        engagement_id="eng-A",
        primitive_class="log_interpolation",
        outcome="confirmed",
        capability_fact_id=fid,
        observed_technology="Apache Solr 8.11.0",
        observed_version="2.14.1",
        sink_shape_id="log4j.log_sink",
        confirmation_primitive="P6",
        reachability_grade="static_heuristic",
        evidence_ref="finding:abc-123:P6",
    )
    conf = await kb.recompute_capability_confidence(fid)

    facts = await kb.get_capability_facts()
    assert len(facts) == 1
    fact = facts[0]
    assert fact["technology_key"] == "log4j-core"
    assert fact["version_predicate"] == "=2.14.1"
    assert fact["primitive_class"] == "log_interpolation"
    assert fact["sink_shape_id"] == "log4j.log_sink"
    assert fact["evidence_grade"] == "confirmed"
    assert fact["first_seen_engagement"] == "eng-A"
    assert conf == 0.5 and fact["confidence"] == 0.5  # one confirm → 0.5

    obs = await kb.get_capability_observations()
    assert len(obs) == 1
    assert obs[0]["outcome"] == "confirmed"
    assert obs[0]["evidence_ref"] == "finding:abc-123:P6"  # a LINK, no response bytes

    # Re-confirming the SAME key is idempotent — one fact, not two.
    fid2 = await kb.upsert_capability_fact(
        technology_key="log4j-core",
        version_predicate="=2.14.1",
        primitive_class="log_interpolation",
        sink_shape_id="log4j.log_sink",
        engagement_id="eng-A",
        evidence_grade="confirmed",
    )
    assert fid2 == fid
    assert len(await kb.get_capability_facts()) == 1


@pytest.mark.asyncio
async def test_capability_confidence_from_confirming_only(kb):
    """Non-confirming outcomes NEVER lower confidence; a 2nd distinct confirming
    engagement raises it (design §S1.2 — the §3.5 firewall)."""
    fid = await kb.upsert_capability_fact(
        technology_key="log4j-core",
        version_predicate="=2.14.1",
        primitive_class="log_interpolation",
        sink_shape_id="log4j.log_sink",
        engagement_id="A",
        evidence_grade="confirmed",
    )
    await kb.add_capability_observation(
        engagement_id="A", primitive_class="log_interpolation", outcome="confirmed",
        capability_fact_id=fid,
    )
    c1 = await kb.recompute_capability_confidence(fid)
    assert c1 == 0.5

    # Pile on every non-confirming outcome from a different engagement.
    for outcome in (
        "failed_unreachable",
        "blind_unconfirmed",
        "collaborator_unavailable",
        "failed_gated",
    ):
        await kb.add_capability_observation(
            engagement_id="B", primitive_class="log_interpolation", outcome=outcome,
            capability_fact_id=fid,
        )
    c2 = await kb.recompute_capability_confidence(fid)
    assert c2 == c1, "a non-confirming outcome lowered a real capability's confidence"

    # A second DISTINCT confirming engagement corroborates upward.
    await kb.add_capability_observation(
        engagement_id="C", primitive_class="log_interpolation", outcome="confirmed",
        capability_fact_id=fid,
    )
    c3 = await kb.recompute_capability_confidence(fid)
    assert c3 == 0.75 and c3 > c1


@pytest.mark.asyncio
async def test_capability_upsert_never_lowers_grade(kb):
    """A confirmed fact stays confirmed even if a later engagement gates it."""
    fid = await kb.upsert_capability_fact(
        technology_key="log4j-core", version_predicate="=2.14.1",
        primitive_class="log_interpolation", sink_shape_id="log4j.log_sink",
        engagement_id="A", evidence_grade="confirmed",
    )
    # A later 'gated' write must not downgrade the confirmed fact.
    fid2 = await kb.upsert_capability_fact(
        technology_key="log4j-core", version_predicate="=2.14.1",
        primitive_class="log_interpolation", sink_shape_id="log4j.log_sink",
        engagement_id="B", gating_config="log4j2.formatMsgNoLookups",
        evidence_grade="gated", last_outcome="failed_gated",
    )
    assert fid2 == fid
    fact = (await kb.get_capability_facts())[0]
    assert fact["evidence_grade"] == "confirmed"  # grade never lowered
    assert fact["gating_config"] == "log4j2.formatMsgNoLookups"  # but gating refined


@pytest.mark.asyncio
async def test_capability_nonconfirming_observation_no_fact(kb):
    """A pure non-confirming observation writes a ledger row and NO durable fact (§3.5)."""
    await kb.add_capability_observation(
        engagement_id="A",
        primitive_class="egress_fetch",
        outcome="blind_unconfirmed",
        capability_fact_id=None,
        observed_technology="Apache Solr 8.11.0",
        sink_shape_id="java.url_openconnection",
    )
    assert await kb.get_capability_facts() == []  # no durable negative fact
    obs = await kb.get_capability_observations()
    assert len(obs) == 1
    assert obs[0]["outcome"] == "blind_unconfirmed"
    assert obs[0]["capability_fact_id"] is None
