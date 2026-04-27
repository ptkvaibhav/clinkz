"""Direct skill invocation smoke tests against DVWA.

Every test:
    1. Builds a ``PageAnalysis`` for a known-vulnerable DVWA endpoint using
       ``ExploitAgent._fetch_page``.
    2. Calls a single ``_test_*`` method directly.
    3. Asserts at least one Finding is produced.

No orchestrator, no plan, no Scan/Research/Report. Pure skill validation.
If a test fails, the skill is broken.
"""

from __future__ import annotations

import httpx
import pytest

from clinkz.agents.exploit import ExploitAgent

pytestmark = [pytest.mark.dvwa_smoke, pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _endpoint_exists(dvwa_url: str, path: str, cookies: dict[str, str]) -> bool:
    """Return True if the DVWA endpoint is present (not 404)."""
    try:
        r = httpx.get(
            f"{dvwa_url}{path}",
            cookies=cookies,
            timeout=5.0,
            follow_redirects=False,
        )
    except Exception:
        return False
    return r.status_code != 404


# ---------------------------------------------------------------------------
# 1. SQL Injection (error / UNION path)
# ---------------------------------------------------------------------------


async def test_sqli_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    page = await exploit_agent._fetch_page(url, params=["id"])
    findings = await exploit_agent._test_sqli(page)
    assert len(findings) >= 1, (
        f"_test_sqli failed to detect SQL injection at {url} "
        f"(params={page.input_params}, status={page.status})"
    )
    assert any("sql" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# 2. SQL Injection — Blind
# ---------------------------------------------------------------------------


async def test_sqli_blind_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    page = await exploit_agent._fetch_page(url, params=["id"])
    findings = await exploit_agent._test_sqli(page)
    assert len(findings) >= 1, (
        f"_test_sqli (blind path) failed to detect SQL injection at {url} "
        f"(params={page.input_params}, status={page.status})"
    )


# ---------------------------------------------------------------------------
# 3. Reflected XSS
# ---------------------------------------------------------------------------


async def test_xss_reflected_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/xss_r/?name=test"
    page = await exploit_agent._fetch_page(url, params=["name"])
    findings = await exploit_agent._test_xss_reflected(page)
    assert len(findings) >= 1, (
        f"_test_xss_reflected failed to detect reflected XSS at {url} (params={page.input_params})"
    )
    assert any("xss" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# 4. Stored XSS
# ---------------------------------------------------------------------------


async def test_xss_stored_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/xss_s/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_xss_stored(page)
    assert len(findings) >= 1, (
        f"_test_xss_stored failed to detect stored XSS at {url} (forms={len(page.forms)})"
    )


# ---------------------------------------------------------------------------
# 5. Command Injection
# ---------------------------------------------------------------------------


async def test_command_injection_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/exec/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_cmdi(page)
    assert len(findings) >= 1, (
        f"_test_cmdi failed to detect command injection at {url} (params={page.input_params})"
    )
    assert any("command" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# 6. File Inclusion (LFI)
# ---------------------------------------------------------------------------


async def test_file_inclusion_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/fi/?page=include.php"
    page = await exploit_agent._fetch_page(url, params=["page"])
    findings = await exploit_agent._test_lfi(page)
    assert len(findings) >= 1, (
        f"_test_lfi failed to detect LFI at {url} (file_params_present={page.has_file_param})"
    )


# ---------------------------------------------------------------------------
# 7. Unrestricted File Upload
# ---------------------------------------------------------------------------


async def test_file_upload_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/upload/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_file_upload(page)
    assert len(findings) >= 1, (
        f"_test_file_upload failed to detect unrestricted upload at {url} "
        f"(has_upload={page.has_upload})"
    )


# ---------------------------------------------------------------------------
# 8. CSRF — missing token on state-changing form
# ---------------------------------------------------------------------------


async def test_csrf_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/csrf/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_csrf(page)
    assert len(findings) >= 1, (
        f"_test_csrf failed to detect missing CSRF token at {url} (forms={len(page.forms)})"
    )


# ---------------------------------------------------------------------------
# 9. Brute Force — no lockout
# ---------------------------------------------------------------------------


async def test_brute_force_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/brute/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_brute_force(page)
    assert len(findings) >= 1, (
        f"_test_brute_force failed to detect missing lockout at {url} (forms={len(page.forms)})"
    )


# ---------------------------------------------------------------------------
# 10. Weak Session Configuration
# ---------------------------------------------------------------------------


async def test_weak_session_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/weak_id/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_weak_session(page)
    assert len(findings) >= 1, f"_test_weak_session failed to detect weak session config at {url}"


# ---------------------------------------------------------------------------
# 11. DOM-based XSS
# ---------------------------------------------------------------------------


async def test_dom_xss_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/xss_d/?default=English"
    page = await exploit_agent._fetch_page(url, params=["default"])
    findings = await exploit_agent._test_xss_dom(page)
    assert len(findings) >= 1, (
        f"_test_xss_dom failed to detect DOM XSS at {url} "
        f"(params={page.input_params}, status={page.status})"
    )


# ---------------------------------------------------------------------------
# 12. JavaScript Attacks (client-side validation bypass)
# ---------------------------------------------------------------------------


async def test_javascript_attacks_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/javascript/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_javascript_attacks(page)
    assert len(findings) >= 1, (
        f"_test_javascript_attacks failed to detect client-side security logic at {url} "
        f"(forms={len(page.forms)}, status={page.status})"
    )


# ---------------------------------------------------------------------------
# 13. Authorization Bypass (DVWA v1.10+; uses _test_idor)
# ---------------------------------------------------------------------------


async def test_authorization_bypass_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    path = "/vulnerabilities/authbypass/"
    if not _endpoint_exists(dvwa_url, path, dvwa_session):
        pytest.xfail(f"DVWA version does not have {path} (404)")

    url = f"{dvwa_url}{path}"
    page = await exploit_agent._fetch_page(url, params=["id"])
    findings = await exploit_agent._test_idor(page)
    assert len(findings) >= 1, (
        f"_test_idor failed to detect authorization bypass at {url} (params={page.input_params})"
    )


# ---------------------------------------------------------------------------
# 14. Open Redirect
# ---------------------------------------------------------------------------


async def test_open_redirect_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    path = "/vulnerabilities/open_redirect/"
    if not _endpoint_exists(dvwa_url, path, dvwa_session):
        pytest.xfail(f"DVWA version does not have {path} (404)")

    url = f"{dvwa_url}{path}?redirect=info.php"
    page = await exploit_agent._fetch_page(url, params=["redirect"])
    findings = await exploit_agent._test_open_redirect(page)
    assert len(findings) >= 1, (
        f"_test_open_redirect failed to detect open redirect at {url} "
        f"(url_params_present={page.has_url_param})"
    )


# ---------------------------------------------------------------------------
# 15. CSP / security-header failure
# ---------------------------------------------------------------------------


async def test_csp_bypass_against_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    url = f"{dvwa_url}/vulnerabilities/csp/"
    page = await exploit_agent._fetch_page(url)
    findings = await exploit_agent._test_security_headers(page)
    assert len(findings) >= 1, f"_test_security_headers failed to flag missing headers at {url}"
