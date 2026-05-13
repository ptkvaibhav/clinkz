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

import httpx
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


# ---------------------------------------------------------------------------
# Command Injection — Juice Shop has limited surface
# ---------------------------------------------------------------------------


async def test_cmdi_against_juiceshop(
    juiceshop_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    """``_test_cmdi`` against any Juice Shop endpoint with an OS-shell sink.

    Juice Shop is a Node.js SPA and does not, by default, expose endpoints
    that drop user input directly into ``child_process.exec``. The few
    challenge surfaces that touch the filesystem (e.g. the legacy /ftp
    download path) are file-inclusion-shaped, not shell-shaped. We
    document this and skip rather than force a fake target — the CMDI
    methodology's deterministic contract is "if the vulnerability is
    present and the skill runs, it MUST find it," not "fabricate a vuln
    where none exists."

    If a future Juice Shop release exposes a real OS-command surface, drop
    this skip and point the URL at it.
    """
    pytest.skip(
        "Juice Shop has no canonical OS-command-injection challenge surface. "
        "The /ftp directory-traversal challenge is LFI, not CMDI. Skipping "
        "rather than forcing a fake target. Re-enable when a Juice Shop "
        "release adds a child_process.exec sink reachable from HTTP input."
    )


# ---------------------------------------------------------------------------
# Local File Inclusion — Juice Shop /ftp directory-traversal challenge
# ---------------------------------------------------------------------------


async def test_lfi_against_juiceshop(
    juiceshop_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    """``_test_lfi`` must find directory traversal at Juice Shop's /ftp.

    Target: ``GET /ftp/<file>``. Juice Shop's static-file route under
    ``/ftp`` serves a curated set of legacy documents and explicitly
    blocks ``..`` traversal — the canonical challenge is to defeat the
    block via URL-encoding (``%2e%2e%2f``). Our methodology should map
    that as a divergent traversal primitive in phase 2 and synthesise a
    payload that retrieves a known file.

    The route takes the path as a path segment rather than a query
    parameter, so we drive the methodology by treating the trailing
    filename as the injection point. Juice Shop also responds with 200
    + plain-text content for in-allowlist files and 403 / 404 for
    blocked traversal — the response divergence alone is enough for
    phase 1 to flag the parameter as a candidate.

    Skip if the /ftp route is missing in the running Juice Shop build —
    older releases place the challenge elsewhere.
    """
    # Probe the route exists before driving the methodology.
    try:
        head_resp = httpx.get(f"{juiceshop_url}/ftp/legal.md", timeout=5.0, follow_redirects=False)
    except Exception as exc:
        pytest.skip(f"Juice Shop /ftp probe failed ({exc}); skipping LFI smoke")
    if head_resp.status_code not in (200, 301, 302):
        pytest.skip(
            f"Juice Shop /ftp returned {head_resp.status_code}; legacy ftp route "
            "may have been removed in this build"
        )

    # We synthesise a PageAnalysis directly because the /ftp route takes
    # the file as a path segment, not a query param. Treat the segment as
    # an input param so the methodology's phase-1 probes vary it.
    from clinkz.agents.exploit import PageAnalysis

    url = f"{juiceshop_url}/ftp/legal.md"
    page = PageAnalysis(
        url=url,
        body="",
        status=200,
        input_params=["file"],
    )
    findings = await exploit_agent._test_lfi(page)
    if not findings:
        # Surface the methodology's diagnostic state on failure.
        result = await exploit_agent._run_lfi_methodology(page, "file")
        pytest.fail(
            f"_test_lfi failed to detect LFI at {url}. "
            f"phases_completed={result.phases_completed} "
            f"primitives={result.primitives.model_dump()} "
            f"retrieval_type={result.retrieval_type} "
            f"verified={result.verified}"
        )
    assert any("local file inclusion" in f.title.lower() for f in findings), (
        f"Findings produced but none labelled LFI at {url}: {findings}"
    )
