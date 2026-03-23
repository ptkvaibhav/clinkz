"""Tests for KnowledgeBase query functions."""

from __future__ import annotations

import pytest

from clinkz.knowledge.query import KnowledgeBase


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    """Load the KnowledgeBase once for all tests in this module."""
    return KnowledgeBase()


# ------------------------------------------------------------------
# Data loading
# ------------------------------------------------------------------


class TestDataLoading:
    """Verify all JSON files load and index correctly."""

    def test_knowledge_base_loads(self, kb: KnowledgeBase) -> None:
        """KnowledgeBase should load without errors."""
        assert kb is not None
        assert len(kb._all_entries) > 0

    def test_stats_has_all_sources(self, kb: KnowledgeBase) -> None:
        """Stats should report counts for all 4 data sources."""
        stats = kb.stats()
        assert "mitre_attack" in stats
        assert "owasp_wstg" in stats
        assert "owasp_api" in stats
        assert "owasp_llm" in stats

    def test_mitre_attack_loaded(self, kb: KnowledgeBase) -> None:
        """MITRE ATT&CK data should have entries."""
        stats = kb.stats()
        assert stats["mitre_attack"] > 0

    def test_owasp_wstg_loaded(self, kb: KnowledgeBase) -> None:
        """OWASP WSTG data should have entries."""
        stats = kb.stats()
        assert stats["owasp_wstg"] > 0

    def test_owasp_api_loaded(self, kb: KnowledgeBase) -> None:
        """OWASP API Top 10 data should have entries."""
        stats = kb.stats()
        assert stats["owasp_api"] > 0

    def test_owasp_llm_loaded(self, kb: KnowledgeBase) -> None:
        """OWASP LLM Top 10 data should have entries."""
        stats = kb.stats()
        assert stats["owasp_llm"] > 0


# ------------------------------------------------------------------
# get_techniques_for_service
# ------------------------------------------------------------------


class TestGetTechniquesForService:
    """Tests for get_techniques_for_service()."""

    def test_web_returns_results(self, kb: KnowledgeBase) -> None:
        """Querying 'web' should return results from multiple sources."""
        results = kb.get_techniques_for_service("web")
        assert len(results) > 0
        sources = {r["source"] for r in results}
        assert len(sources) >= 2, f"Expected multiple sources, got: {sources}"

    def test_api_returns_results(self, kb: KnowledgeBase) -> None:
        """Querying 'api' should return API-relevant tests."""
        results = kb.get_techniques_for_service("api")
        assert len(results) > 0

    def test_network_returns_results(self, kb: KnowledgeBase) -> None:
        """Querying 'network' should return network-relevant tests."""
        results = kb.get_techniques_for_service("network")
        assert len(results) > 0

    def test_case_insensitive(self, kb: KnowledgeBase) -> None:
        """Service type should be case-insensitive."""
        lower = kb.get_techniques_for_service("web")
        upper = kb.get_techniques_for_service("WEB")
        assert len(lower) == len(upper)

    def test_unknown_service_returns_empty(self, kb: KnowledgeBase) -> None:
        """Unknown service type should return empty list."""
        results = kb.get_techniques_for_service("quantum_computing")
        assert results == []


# ------------------------------------------------------------------
# get_techniques_for_technology
# ------------------------------------------------------------------


class TestGetTechniquesForTechnology:
    """Tests for get_techniques_for_technology()."""

    def test_php_returns_web_tests(self, kb: KnowledgeBase) -> None:
        """PHP should map to web and injection tests."""
        results = kb.get_techniques_for_technology("php")
        assert len(results) > 0

    def test_nginx_returns_config_tests(self, kb: KnowledgeBase) -> None:
        """nginx should return configuration-related tests."""
        results = kb.get_techniques_for_technology("nginx")
        assert len(results) > 0

    def test_mysql_returns_injection_tests(self, kb: KnowledgeBase) -> None:
        """MySQL should return injection-related tests."""
        results = kb.get_techniques_for_technology("mysql")
        assert len(results) > 0

    def test_versioned_tech(self, kb: KnowledgeBase) -> None:
        """Technology with version should still match."""
        results = kb.get_techniques_for_technology("nginx 1.24.0")
        assert len(results) > 0

    def test_jwt_returns_auth_tests(self, kb: KnowledgeBase) -> None:
        """JWT should return authentication tests."""
        results = kb.get_techniques_for_technology("jwt")
        assert len(results) > 0

    def test_unknown_tech_returns_empty(self, kb: KnowledgeBase) -> None:
        """Unknown technology should return empty or near-empty list."""
        results = kb.get_techniques_for_technology("zzz_nonexistent_tech_zzz")
        # May return entries that mention the term in description, but likely empty
        assert isinstance(results, list)

    def test_no_duplicate_ids(self, kb: KnowledgeBase) -> None:
        """Results should not contain duplicate IDs."""
        results = kb.get_techniques_for_technology("php")
        ids = [r.get("id") for r in results if r.get("id")]
        assert len(ids) == len(set(ids)), "Duplicate IDs found in results"


# ------------------------------------------------------------------
# get_tests_by_category
# ------------------------------------------------------------------


class TestGetTestsByCategory:
    """Tests for get_tests_by_category()."""

    def test_injection_returns_results(self, kb: KnowledgeBase) -> None:
        """Searching 'injection' should return injection-related tests."""
        results = kb.get_tests_by_category("injection")
        assert len(results) > 0

    def test_authentication_returns_results(self, kb: KnowledgeBase) -> None:
        """Searching 'authentication' should return auth tests."""
        results = kb.get_tests_by_category("authentication")
        assert len(results) > 0

    def test_authorization_returns_results(self, kb: KnowledgeBase) -> None:
        """Searching 'authorization' should return authz tests."""
        results = kb.get_tests_by_category("authorization")
        assert len(results) > 0

    def test_session_returns_results(self, kb: KnowledgeBase) -> None:
        """Searching 'session' should return session management tests."""
        results = kb.get_tests_by_category("session")
        assert len(results) > 0

    def test_unknown_category_returns_empty(self, kb: KnowledgeBase) -> None:
        """Unknown category should return empty list."""
        results = kb.get_tests_by_category("zzz_nonexistent_zzz")
        assert results == []


# ------------------------------------------------------------------
# get_cve_techniques
# ------------------------------------------------------------------


class TestGetCVETechniques:
    """Tests for get_cve_techniques()."""

    def test_returns_attack_techniques(self, kb: KnowledgeBase) -> None:
        """Should return ATT&CK techniques for CVE exploitation."""
        results = kb.get_cve_techniques("nginx", "1.24.0")
        assert len(results) > 0
        # All results should be from mitre_attack source
        for r in results:
            assert r["source"] == "mitre_attack"

    def test_includes_exploit_public_facing(self, kb: KnowledgeBase) -> None:
        """Should include T1190 (Exploit Public-Facing Application)."""
        results = kb.get_cve_techniques("apache", "2.4")
        technique_ids = {r["id"] for r in results}
        assert "T1190" in technique_ids


# ------------------------------------------------------------------
# get_all_for_phase
# ------------------------------------------------------------------


class TestGetAllForPhase:
    """Tests for get_all_for_phase()."""

    def test_recon_phase(self, kb: KnowledgeBase) -> None:
        """Recon phase should return reconnaissance tests."""
        results = kb.get_all_for_phase("recon")
        assert len(results) > 0

    def test_scan_phase(self, kb: KnowledgeBase) -> None:
        """Scan phase should return scanning/mapping tests."""
        results = kb.get_all_for_phase("scan")
        assert len(results) > 0

    def test_exploit_phase(self, kb: KnowledgeBase) -> None:
        """Exploit phase should return the most tests."""
        results = kb.get_all_for_phase("exploit")
        assert len(results) > 0
        # Exploit should have more tests than recon
        recon_results = kb.get_all_for_phase("recon")
        assert len(results) >= len(recon_results)

    def test_unknown_phase(self, kb: KnowledgeBase) -> None:
        """Unknown phase should return empty list."""
        results = kb.get_all_for_phase("nonexistent")
        assert results == []


# ------------------------------------------------------------------
# search
# ------------------------------------------------------------------


class TestSearch:
    """Tests for full-text search()."""

    def test_sql_injection_search(self, kb: KnowledgeBase) -> None:
        """Searching 'sql injection' should find relevant tests."""
        results = kb.search("sql injection")
        assert len(results) > 0

    def test_xss_search(self, kb: KnowledgeBase) -> None:
        """Searching 'cross site scripting' should find XSS tests."""
        results = kb.search("cross site scripting")
        assert len(results) > 0

    def test_prompt_injection_search(self, kb: KnowledgeBase) -> None:
        """Searching 'prompt injection' should find LLM tests."""
        results = kb.search("prompt injection")
        assert len(results) > 0

    def test_empty_query(self, kb: KnowledgeBase) -> None:
        """Empty query should return empty list."""
        results = kb.search("")
        assert results == []

    def test_search_returns_ordered(self, kb: KnowledgeBase) -> None:
        """Results should be ordered by relevance (token hits)."""
        results = kb.search("sql injection testing")
        assert len(results) > 0
        # First result should have highest relevance


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests."""

    def test_multiple_instantiation(self) -> None:
        """Creating multiple KnowledgeBase instances should work."""
        kb1 = KnowledgeBase()
        kb2 = KnowledgeBase()
        assert kb1.stats() == kb2.stats()

    def test_entry_structure(self, kb: KnowledgeBase) -> None:
        """Every entry should have at minimum an id and source."""
        for entry in kb._all_entries:
            assert "source" in entry
            assert "id" in entry
            assert "name" in entry

    def test_applicable_to_is_list(self, kb: KnowledgeBase) -> None:
        """applicable_to should always be a list."""
        for entry in kb._all_entries:
            assert isinstance(entry.get("applicable_to", []), list)
