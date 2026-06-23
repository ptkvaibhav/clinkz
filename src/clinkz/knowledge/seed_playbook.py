"""Seed data for the persistent knowledge base.

Populates Tier 1 universal tests that run on every engagement regardless
of the target's technology stack.
"""

from __future__ import annotations

import logging

from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier 1 universal tests — run on EVERY engagement
# ---------------------------------------------------------------------------

_TIER1_ENTRIES: list[dict] = [
    {
        "technique_name": "port_scan_full",
        "technique_description": "Scan all 65535 TCP ports",
        "steps": ["Run full TCP port scan on target", "Record all open ports"],
        "severity": "info",
        "applicable_vuln_classes": ["recon"],
    },
    {
        "technique_name": "service_version_detect",
        "technique_description": "Identify service versions on all open ports",
        "steps": [
            "Run service/version detection on open ports",
            "Record service banners and versions",
        ],
        "severity": "info",
        "applicable_vuln_classes": ["recon"],
    },
    {
        "technique_name": "web_crawl",
        "technique_description": "Deep crawl all HTTP services to discover endpoints",
        "steps": [
            "Crawl all HTTP/HTTPS services",
            "Extract URLs, forms, and parameters",
            "Record discovered endpoints",
        ],
        "severity": "info",
        "applicable_vuln_classes": ["recon"],
    },
    {
        "technique_name": "directory_fuzz",
        "technique_description": "Fuzz directories with common wordlists",
        "steps": [
            "Run directory fuzzing against web roots",
            "Use common wordlists (common.txt, raft-medium)",
            "Record discovered paths",
        ],
        "severity": "info",
        "applicable_vuln_classes": ["recon"],
    },
    {
        "technique_name": "sqli_detection",
        "technique_description": "Test all input parameters for SQL injection",
        "steps": [
            "Identify all input parameters",
            "Test each parameter with SQLi payloads",
            "Observe response for error-based/blind indicators",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["sqli"],
    },
    {
        "technique_name": "nosqli_detection",
        "technique_description": "Test JSON-body and query/path params for NoSQL injection",
        "steps": [
            "Identify JSON-body and query/path parameters",
            "Probe operator injection ($ne/$gt/$regex) and string $where breaks",
            "Confirm via match-set widening, auth bypass, regex differential, or $where delay",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["nosqli"],
    },
    {
        "technique_name": "ssti_detection",
        "technique_description": "Test query/JSON-body params for server-side template injection",
        "steps": [
            "Identify query and JSON-body parameters",
            "Send polyglot arithmetic probes ({{a*b}}/${a*b}/#{a*b}/<%= a*b %>) and detect eval",
            "Fingerprint the template engine, then confirm via arithmetic eval or RCE echo-canary",
        ],
        "severity": "critical",
        "applicable_vuln_classes": ["ssti"],
    },
    {
        "technique_name": "xxe_detection",
        "technique_description": "Test XML-accepting endpoints for XML external entity injection",
        "steps": [
            "Identify endpoints that parse XML (file uploads, application/xml bodies, SOAP/B2B)",
            "Fingerprint parser capabilities (entity resolution, external/parameter entities)",
            "Confirm via disclosed file content (SYSTEM file://) or bounded entity-expansion delay",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["xxe"],
    },
    {
        "technique_name": "xss_detection",
        "technique_description": "Test all reflected parameters for XSS",
        "steps": [
            "Identify reflected input parameters",
            "Test with XSS probe payloads",
            "Check if payload renders unescaped in response",
        ],
        "severity": "medium",
        "applicable_vuln_classes": ["xss"],
    },
    {
        "technique_name": "cmdi_detection",
        "technique_description": "Test suspicious parameters for OS command injection",
        "steps": [
            "Identify parameters likely passed to OS commands",
            "Test with command injection payloads",
            "Observe response for command output indicators",
        ],
        "severity": "critical",
        "applicable_vuln_classes": ["cmdi"],
    },
    {
        "technique_name": "lfi_detection",
        "technique_description": "Test file-path parameters for local file inclusion",
        "steps": [
            "Identify parameters referencing file paths",
            "Test with path traversal payloads",
            "Check for file content in response",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["lfi"],
    },
    {
        "technique_name": "csrf_detection",
        "technique_description": "Test state-changing forms for missing CSRF tokens",
        "steps": [
            "Identify state-changing forms (POST, PUT, DELETE)",
            "Check for CSRF token presence",
            "Attempt cross-origin request without token",
        ],
        "severity": "medium",
        "applicable_vuln_classes": ["csrf"],
    },
    {
        "technique_name": "file_upload_test",
        "technique_description": "Test upload endpoints for unrestricted file upload",
        "steps": [
            "Identify file upload endpoints",
            "Attempt uploading executable file types",
            "Check if uploaded files are accessible/executable",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["file_upload"],
    },
    {
        "technique_name": "brute_force_test",
        "technique_description": "Test login forms for account lockout policy",
        "steps": [
            "Identify login forms",
            "Attempt multiple failed logins",
            "Check if account lockout is enforced",
        ],
        "severity": "medium",
        "applicable_vuln_classes": ["brute_force"],
    },
    {
        "technique_name": "security_headers",
        "technique_description": "Check all HTTP responses for missing security headers",
        "steps": [
            "Fetch HTTP responses from all endpoints",
            "Check for X-Frame-Options, CSP, HSTS, X-Content-Type-Options",
            "Report missing or misconfigured headers",
        ],
        "severity": "low",
        "applicable_vuln_classes": ["misconfiguration"],
    },
    {
        "technique_name": "open_redirect",
        "technique_description": "Test URL parameters for open redirect",
        "steps": [
            "Identify parameters containing URLs or paths",
            "Test with external domain redirect payloads",
            "Check if redirect occurs to attacker-controlled domain",
        ],
        "severity": "medium",
        "applicable_vuln_classes": ["open_redirect"],
    },
    {
        "technique_name": "idor_detection",
        "technique_description": "Test object references for insecure direct access",
        "steps": [
            "Identify endpoints with object IDs in parameters",
            "Attempt accessing other users' objects",
            "Check for authorization enforcement",
        ],
        "severity": "high",
        "applicable_vuln_classes": ["idor"],
    },
    {
        "technique_name": "jwt_detection",
        "technique_description": "Test JWT-authenticated endpoints for token forgery / tampering",
        "steps": [
            "Acquire the engagement's JWT and confirm the endpoint validates its signature",
            "Fingerprint the token (algorithm, kid, claims, expiry) to gate the attack set",
            "Forge via alg:none / weak-secret / algorithm-confusion / claim-tamper and re-send",
            "Confirm in-band when the forged token is accepted like the valid baseline",
        ],
        "severity": "critical",
        "applicable_vuln_classes": ["jwt"],
    },
    {
        "technique_name": "ssrf_detection",
        "technique_description": "Coerce the in-scope server to fetch internal/metadata addresses",
        "steps": [
            "Find URL/fetch params and confirm the param drives a server-side fetch",
            "Fingerprint the fetcher: fetch-confirmed? content reflected (in-band)? schemes?",
            "Point the fetch at cloud-metadata / internal / file:// targets (param value only)",
            "Confirm in-band when the response reflects internal content it should not have",
            "If the fetch is blind (no reflected content), note OOB-deferred — never a phantom",
        ],
        "severity": "critical",
        "applicable_vuln_classes": ["ssrf"],
    },
]


async def seed_tier1_tests(kb: PersistentKnowledgeBase) -> None:
    """Populate Tier 1 universal tests if they don't already exist.

    Idempotent — safe to call multiple times. Existing entries are skipped
    via INSERT OR IGNORE (unique constraint on technique_name + technology_pattern).

    Args:
        kb: An initialised PersistentKnowledgeBase instance.
    """
    existing = await kb.get_tier1_tests()
    existing_names = {e["technique_name"] for e in existing}

    added = 0
    for entry in _TIER1_ENTRIES:
        if entry["technique_name"] in existing_names:
            continue
        await kb.add_playbook_entry(
            tier=1,
            technique_name=entry["technique_name"],
            technology_pattern=".*",
            technique_description=entry["technique_description"],
            steps=entry["steps"],
            source_type="manual",
            severity=entry["severity"],
            applicable_vuln_classes=entry["applicable_vuln_classes"],
        )
        added += 1

    logger.info("Seed: added %d Tier 1 entries (%d already existed)", added, len(existing_names))
