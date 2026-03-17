"""KnowledgeBase — runtime query engine for security testing references.

Loads MITRE ATT&CK, OWASP WSTG, OWASP API Top 10, and OWASP LLM Top 10
from bundled JSON files and provides fast lookup methods that agents call
at runtime to discover relevant tests for discovered technologies.

Usage::

    kb = KnowledgeBase()
    tests = kb.get_techniques_for_service("web")
    sqli  = kb.get_tests_by_category("injection")
    phase = kb.get_all_for_phase("recon")
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent


def _load_json(filename: str) -> list[dict[str, Any]]:
    """Load a JSON file from the knowledge data directory.

    Args:
        filename: JSON filename relative to this module's directory.

    Returns:
        Parsed JSON list (empty list on error).
    """
    path = _DATA_DIR / filename
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("Knowledge file not found: %s", path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        return []


# ── Phase → applicable_to tag mapping ─────────────────────────────────
_PHASE_TAGS: dict[str, set[str]] = {
    "recon": {
        "reconnaissance", "recon", "information_gathering", "osint",
        "network", "infrastructure", "dns",
    },
    "scan": {
        "web", "api", "crawling", "fuzzing", "scanning",
        "configuration", "network", "infrastructure",
    },
    "exploit": {
        "web", "api", "network", "injection", "authentication",
        "authorization", "session", "cryptography", "exploitation",
        "infrastructure", "cloud", "active_directory",
    },
    "report": {"web", "api", "network"},
    "critic": {"web", "api", "network"},
}

# ── Technology → tags mapping ─────────────────────────────────────────
_TECH_TAGS: dict[str, set[str]] = {
    "php": {"web", "api"},
    "java": {"web", "api"},
    "python": {"web", "api"},
    "node": {"web", "api"},
    "nodejs": {"web", "api"},
    "ruby": {"web", "api"},
    "asp": {"web", "api"},
    "aspnet": {"web", "api"},
    ".net": {"web", "api"},
    "nginx": {"web", "configuration", "infrastructure"},
    "apache": {"web", "configuration", "infrastructure"},
    "iis": {"web", "configuration", "infrastructure"},
    "tomcat": {"web", "api", "configuration", "infrastructure"},
    "mysql": {"web", "api", "infrastructure"},
    "postgres": {"web", "api", "infrastructure"},
    "postgresql": {"web", "api", "infrastructure"},
    "mssql": {"web", "api", "infrastructure"},
    "oracle": {"web", "api", "infrastructure"},
    "sqlite": {"web", "api"},
    "mongodb": {"web", "api", "infrastructure"},
    "redis": {"network", "infrastructure"},
    "wordpress": {"web", "api", "authentication"},
    "drupal": {"web", "api", "authentication"},
    "joomla": {"web", "api", "authentication"},
    "django": {"web", "api"},
    "flask": {"web", "api"},
    "spring": {"web", "api"},
    "express": {"web", "api"},
    "react": {"web"},
    "angular": {"web"},
    "vue": {"web"},
    "docker": {"infrastructure", "containers"},
    "kubernetes": {"infrastructure", "containers", "cloud"},
    "aws": {"cloud", "infrastructure"},
    "azure": {"cloud", "infrastructure"},
    "gcp": {"cloud", "infrastructure"},
    "ssh": {"network", "authentication", "infrastructure"},
    "ftp": {"network", "infrastructure"},
    "smtp": {"network", "infrastructure"},
    "dns": {"network", "infrastructure"},
    "ldap": {"network", "active_directory"},
    "kerberos": {"network", "active_directory", "authentication"},
    "smb": {"network", "active_directory", "infrastructure"},
    "api": {"api", "web"},
    "rest": {"api", "web"},
    "graphql": {"api", "web"},
    "grpc": {"api"},
    "soap": {"api", "web"},
    "jwt": {"authentication", "api", "web"},
    "oauth": {"authentication", "api", "web"},
    "saml": {"authentication", "api", "web"},
    "openai": {"ai", "api"},
    "llm": {"ai", "api"},
    "chatgpt": {"ai", "api"},
    "claude": {"ai", "api"},
    "gemini": {"ai", "api"},
}


class KnowledgeBase:
    """Security testing knowledge base with runtime query support.

    Loads all JSON data files on construction and provides methods for
    agents to discover relevant tests based on service type, technology,
    category, or engagement phase.

    Thread-safe for read-only access (no mutation after ``__init__``).
    """

    def __init__(self) -> None:
        self._attack: list[dict[str, Any]] = _load_json("mitre_attack.json")
        self._wstg: list[dict[str, Any]] = _load_json("owasp_wstg.json")
        self._api: list[dict[str, Any]] = _load_json("owasp_api.json")
        self._llm: list[dict[str, Any]] = _load_json("owasp_llm.json")

        # Pre-flatten all test entries for fast full-text search
        self._all_entries: list[dict[str, Any]] = []
        self._build_index()

    # ------------------------------------------------------------------
    # Index builder
    # ------------------------------------------------------------------

    def _build_index(self) -> None:
        """Flatten all data sources into a unified entry list for search."""
        # ATT&CK techniques
        for tactic in self._attack:
            tactic_name = tactic.get("tactic_name", "")
            tactic_id = tactic.get("tactic_id", "")
            for tech in tactic.get("techniques", []):
                entry = {
                    "source": "mitre_attack",
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "id": tech.get("id", ""),
                    "name": tech.get("name", ""),
                    "description": tech.get("description", ""),
                    "applicable_to": tech.get("applicable_to", []),
                    "pentest_actions": tech.get("pentest_actions", []),
                    "tools": tech.get("tools", []),
                    "sub_techniques": tech.get("sub_techniques", []),
                }
                self._all_entries.append(entry)

        # WSTG tests
        for category in self._wstg:
            category_name = category.get("category_name", "")
            category_id = category.get("category_id", "")
            for test in category.get("tests", []):
                entry = {
                    "source": "owasp_wstg",
                    "category_id": category_id,
                    "category_name": category_name,
                    "id": test.get("id", ""),
                    "name": test.get("name", ""),
                    "description": test.get("description", ""),
                    "test_steps": test.get("test_steps", []),
                    "applicable_to": test.get("applicable_to", []),
                    "tools": test.get("tools", []),
                    "severity_if_found": test.get("severity_if_found", ""),
                }
                self._all_entries.append(entry)

        # OWASP API Top 10
        for risk in self._api:
            for sub in risk.get("sub_tests", []):
                entry = {
                    "source": "owasp_api",
                    "parent_id": risk.get("id", ""),
                    "parent_name": risk.get("name", ""),
                    "id": sub.get("id", ""),
                    "name": sub.get("name", ""),
                    "description": risk.get("description", ""),
                    "test_steps": sub.get("test_steps", []),
                    "payloads": sub.get("payloads", []),
                    "applicable_to": risk.get("applicable_to", []),
                    "tools": risk.get("tools", []),
                    "severity_if_found": sub.get("severity", risk.get("overall_severity", "")),
                }
                self._all_entries.append(entry)

        # OWASP LLM Top 10
        for risk in self._llm:
            for sub in risk.get("sub_tests", []):
                entry = {
                    "source": "owasp_llm",
                    "parent_id": risk.get("id", ""),
                    "parent_name": risk.get("name", ""),
                    "id": sub.get("id", ""),
                    "name": sub.get("name", ""),
                    "description": risk.get("description", ""),
                    "test_steps": sub.get("test_steps", []),
                    "payloads": sub.get("payloads", []),
                    "applicable_to": risk.get("applicable_to", []),
                    "tools": risk.get("tools", []),
                    "severity_if_found": sub.get("severity", risk.get("overall_severity", "")),
                }
                self._all_entries.append(entry)

        logger.info("KnowledgeBase indexed %d entries", len(self._all_entries))

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------

    def get_techniques_for_service(self, service_type: str) -> list[dict[str, Any]]:
        """Return all techniques/tests applicable to a service type.

        Args:
            service_type: One of "web", "api", "network", "infrastructure",
                          "cloud", "mobile", "endpoint", "active_directory",
                          "containers", "saas", "ai".

        Returns:
            List of matching entry dicts from all knowledge sources.
        """
        service_lower = service_type.lower().strip()
        return [
            entry for entry in self._all_entries
            if service_lower in [t.lower() for t in entry.get("applicable_to", [])]
        ]

    def get_techniques_for_technology(self, tech: str) -> list[dict[str, Any]]:
        """Return tests relevant to a specific technology.

        Maps the technology name to applicable service tags, then returns
        all entries matching those tags. Also includes entries whose name
        or description mentions the technology.

        Args:
            tech: Technology name (e.g., "php", "nginx 1.24", "mysql").

        Returns:
            List of matching entry dicts (deduplicated by id).
        """
        tech_lower = tech.lower().strip()
        # Find the best matching tag set
        tags: set[str] = set()
        for key, key_tags in _TECH_TAGS.items():
            if key in tech_lower:
                tags |= key_tags

        # Collect by tag match
        seen_ids: set[str] = set()
        results: list[dict[str, Any]] = []

        for entry in self._all_entries:
            entry_id = entry.get("id", "")
            applicable = {t.lower() for t in entry.get("applicable_to", [])}
            if tags & applicable and entry_id not in seen_ids:
                results.append(entry)
                seen_ids.add(entry_id)

        # Also include entries that mention the tech by name
        for entry in self._all_entries:
            entry_id = entry.get("id", "")
            if entry_id in seen_ids:
                continue
            searchable = (
                f"{entry.get('name', '')} {entry.get('description', '')} "
                f"{' '.join(entry.get('pentest_actions', []))}"
            ).lower()
            if tech_lower in searchable:
                results.append(entry)
                seen_ids.add(entry_id)

        return results

    def get_tests_by_category(self, category: str) -> list[dict[str, Any]]:
        """Return all tests matching a category keyword.

        Searches category names, tactic names, parent names, and entry
        names for the keyword.

        Args:
            category: Category keyword (e.g., "injection", "authentication",
                      "session", "cryptography", "information_gathering").

        Returns:
            List of matching entry dicts.
        """
        cat_lower = category.lower().strip()
        results: list[dict[str, Any]] = []
        for entry in self._all_entries:
            searchable = " ".join([
                entry.get("category_name", ""),
                entry.get("tactic_name", ""),
                entry.get("parent_name", ""),
                entry.get("name", ""),
            ]).lower()
            if cat_lower in searchable:
                results.append(entry)
        return results

    def get_cve_techniques(self, service: str, version: str) -> list[dict[str, Any]]:
        """Return ATT&CK techniques relevant to exploiting known CVEs.

        Filters for techniques related to the given service/version that
        involve exploitation of public-facing applications, known
        vulnerabilities, or software deployment.

        Args:
            service: Service or product name (e.g., "nginx", "apache").
            version: Version string (e.g., "1.24.0").

        Returns:
            List of matching ATT&CK technique entries.
        """
        service_lower = service.lower().strip()
        results: list[dict[str, Any]] = []

        # CVE-relevant ATT&CK technique IDs
        cve_technique_ids = {
            "T1190",  # Exploit Public-Facing Application
            "T1210",  # Exploitation of Remote Services
            "T1203",  # Exploitation for Client Execution
            "T1068",  # Exploitation for Privilege Escalation
            "T1211",  # Exploitation for Defense Evasion
            "T1212",  # Exploitation for Credential Access
            "T1189",  # Drive-by Compromise
        }

        for entry in self._all_entries:
            if entry.get("source") != "mitre_attack":
                continue
            entry_id = entry.get("id", "")
            # Match by technique ID
            if entry_id in cve_technique_ids:
                results.append(entry)
                continue
            # Match by service mention in description/actions
            searchable = (
                f"{entry.get('description', '')} "
                f"{' '.join(entry.get('pentest_actions', []))}"
            ).lower()
            if service_lower in searchable:
                results.append(entry)

        return results

    def get_all_for_phase(self, phase: str) -> list[dict[str, Any]]:
        """Return all tests applicable to a pentest phase.

        Maps phases (recon, scan, exploit, report, critic) to relevant
        service tags and returns matching entries.

        Args:
            phase: Phase name ("recon", "scan", "exploit", "report", "critic").

        Returns:
            List of matching entry dicts.
        """
        phase_lower = phase.lower().strip()
        tags = _PHASE_TAGS.get(phase_lower, set())
        if not tags:
            logger.warning("Unknown phase '%s' — returning empty list", phase)
            return []

        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for entry in self._all_entries:
            entry_id = entry.get("id", "")
            if entry_id in seen_ids:
                continue
            applicable = {t.lower() for t in entry.get("applicable_to", [])}
            if tags & applicable:
                results.append(entry)
                seen_ids.add(entry_id)

        # For recon phase, also include ATT&CK Reconnaissance tactic
        if phase_lower == "recon":
            for entry in self._all_entries:
                entry_id = entry.get("id", "")
                if entry_id in seen_ids:
                    continue
                if entry.get("tactic_name", "").lower() == "reconnaissance":
                    results.append(entry)
                    seen_ids.add(entry_id)

        return results

    def search(self, query: str) -> list[dict[str, Any]]:
        """Full-text search across all test descriptions and names.

        Splits the query into tokens and returns entries where ALL tokens
        appear in the combined searchable text (name + description +
        actions/steps + tools).

        Args:
            query: Free-text search query.

        Returns:
            List of matching entry dicts, scored by number of token hits.
        """
        tokens = [t.lower() for t in re.split(r"\s+", query.strip()) if t]
        if not tokens:
            return []

        scored: list[tuple[int, dict[str, Any]]] = []
        for entry in self._all_entries:
            searchable = " ".join([
                entry.get("name", ""),
                entry.get("description", ""),
                " ".join(entry.get("pentest_actions", [])),
                " ".join(entry.get("test_steps", [])),
                " ".join(entry.get("tools", [])),
                " ".join(entry.get("payloads", [])),
                entry.get("tactic_name", ""),
                entry.get("category_name", ""),
                entry.get("parent_name", ""),
            ]).lower()

            hits = sum(1 for t in tokens if t in searchable)
            if hits == len(tokens):
                scored.append((hits, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored]

    # ------------------------------------------------------------------
    # Summary / stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        """Return counts of loaded entries by source.

        Returns:
            Dict mapping source name to entry count.
        """
        counts: dict[str, int] = {}
        for entry in self._all_entries:
            source = entry.get("source", "unknown")
            counts[source] = counts.get(source, 0) + 1
        return counts
