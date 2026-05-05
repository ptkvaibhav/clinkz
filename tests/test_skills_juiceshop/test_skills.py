"""Direct skill invocation smoke tests against OWASP Juice Shop.

Every test:
    1. Builds a ``PageAnalysis`` for a known-vulnerable Juice Shop endpoint
       using ``ExploitAgent._fetch_page``.
    2. Calls a single ``_test_*`` method directly.
    3. Asserts at least one Finding is produced.

No orchestrator, no plan, no Scan/Research/Report. Pure skill validation.
If a test fails, the methodology does not handle Juice Shop's SPA-style
parameter consumption and is broken for that pattern.
"""

from __future__ import annotations

import pytest

from clinkz.agents.exploit import ExploitAgent

pytestmark = [pytest.mark.juiceshop_smoke, pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Reflected XSS — DOM context (SPA fragment-driven search)
# ---------------------------------------------------------------------------


async def test_xss_reflected_against_juiceshop(
    juiceshop_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    """``_test_xss_reflected`` must find reflected XSS at Juice Shop's search bar.

    Target: ``GET /#/search?q=<payload>``. Juice Shop's search bar reflects
    the ``q`` fragment value into the DOM via Angular's binding (param
    value lands in JS rendering, not a server-side HTML body). The
    reflection-mapping methodology should map this as a DOM-context
    reflection and synthesize a payload that executes in that context.

    If this test passes, reflection-mapping handles SPA-style param
    consumption — not just PHP-style server reflection.
    """
    url = f"{juiceshop_url}/#/search?q=test"
    page = await exploit_agent._fetch_page(url, params=["q"])
    findings = await exploit_agent._test_xss_reflected(page)
    assert len(findings) >= 1, (
        f"_test_xss_reflected failed to detect DOM-context reflected XSS at {url} "
        f"(params={page.input_params}, status={page.status})"
    )
    assert any("xss" in f.title.lower() for f in findings), (
        f"Findings produced but none labelled XSS at {url}: {findings}"
    )


# ---------------------------------------------------------------------------
# SQL Injection — server-side (SQLite-backed Juice Shop product search)
# ---------------------------------------------------------------------------


async def test_sqli_against_juiceshop(
    juiceshop_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    """``_test_sqli`` must find SQL injection at Juice Shop's product search.

    Target: ``GET /rest/products/search?q=<payload>``. Juice Shop builds the
    underlying query by string-concatenating ``q`` into a raw SQLite
    statement, so a single quote breaks the query and surfaces a Sequelize
    / SQLite error in the response body.

    Expected methodology outcome: dialect classified as SQLITE (via the
    ``SequelizeDatabaseError`` / ``SQLITE_ERROR`` / ``unrecognized token``
    error fingerprints), and verification via either error-based or
    union-based injection. If the methodology returns a finding whose
    evidence carries ``dialect=sqlite`` plus an error-string or union-data
    indicator, the rewrite handles SPA / Node-stack SQLi — not just
    PHP/MySQL reflection.
    """
    url = f"{juiceshop_url}/rest/products/search?q=test"
    page = await exploit_agent._fetch_page(url, params=["q"])
    findings = await exploit_agent._test_sqli(page)
    assert len(findings) >= 1, (
        f"_test_sqli failed to detect SQL injection at {url} "
        f"(params={page.input_params}, status={page.status})"
    )
    assert any("sql" in f.title.lower() for f in findings), (
        f"Findings produced but none labelled SQL injection at {url}: {findings}"
    )
    # Methodology evidence should be attached.
    finding = findings[0]
    assert any("phases_completed=" in ev for ev in finding.evidence), (
        f"Methodology evidence missing on Juice Shop SQLi finding: {finding.evidence}"
    )
    assert any("dialect=sqlite" in ev for ev in finding.evidence), (
        f"Expected dialect=sqlite in evidence: {finding.evidence}"
    )
    assert any(
        ("injection_type=error_based" in ev) or ("injection_type=union_based" in ev)
        for ev in finding.evidence
    ), f"Expected injection_type=error_based or union_based in evidence: {finding.evidence}"
