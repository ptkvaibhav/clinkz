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

from clinkz.agents._url_safety import is_state_changing_url
from clinkz.agents.exploit import ExploitAgent
from clinkz.models.finding import ExploitPlan, Finding
from clinkz.models.scan import Endpoint

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
# 2b. NoSQL Injection — N/A on DVWA (PHP/MySQL stack)
# ---------------------------------------------------------------------------


async def test_nosqli_not_applicable_on_dvwa(
    dvwa_url: str,
    exploit_agent: ExploitAgent,
) -> None:
    """``_test_nosqli`` is N/A on DVWA's PHP/MySQL stack — no false emission.

    DVWA has no NoSQL backend, so operator-object probes produce no count
    widening and the lone-quote break surfaces a *SQL* error (not a NoSQL
    signal). Phase 3 therefore returns no candidate injection type and the
    methodology emits nothing. The contract here is no false positive and no
    crash — not a finding.
    """
    url = f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    page = await exploit_agent._fetch_page(url, params=["id"])
    findings = await exploit_agent._test_nosqli(page)
    assert findings == [], (
        f"_test_nosqli falsely emitted on DVWA's SQL/PHP stack at {url}: {findings}"
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


# ---------------------------------------------------------------------------
# 16. LFI through the planner → dispatch path (not just the isolated skill)
# ---------------------------------------------------------------------------


async def test_lfi_through_planner_dispatch_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    """LFI is routed to /vulnerabilities/fi/ by the planner AND confirmed on dispatch.

    Reproduces the d328200c failure end-to-end: the FI endpoint is buried among
    low-value crawl artifacts (instructions.php, view_source.php) that the old
    planner tested instead. The fix must (1) queue ``_test_lfi`` against the real
    FI endpoint via the deterministic coverage union, and (2) with no phase
    deadline, dispatch it and confirm the finding against the live target — the
    routing the isolated ``_test_lfi`` smoke test cannot exercise.
    """
    fi_path = "/vulnerabilities/fi/"
    if not _endpoint_exists(dvwa_url, fi_path, dvwa_session):
        pytest.xfail(f"DVWA version does not have {fi_path} (404)")

    fi_url = f"{dvwa_url}{fi_path}?page=include.php"
    # FI buried behind the low-value endpoints the old planner wasted time on.
    endpoints = [
        Endpoint(url=f"{dvwa_url}/instructions.php?doc=PDF", method="GET", params=["doc"]),
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/view_source.php?id=fi&security=low",
            method="GET",
            params=["id", "security"],
        ),
        Endpoint(url=fi_url, method="GET", params=["page"]),
    ]
    ranked = exploit_agent._dedupe_and_rank_endpoints(endpoints)

    # The coverage union must queue _test_lfi against the real FI endpoint even
    # when the LLM plan is empty (the planner-coverage half of the fix).
    plan = exploit_agent._merge_coverage(ExploitPlan(tasks=[]), ranked, [], [])
    assert any(t.test_method == "_test_lfi" and fi_path in t.endpoint_url for t in plan.tasks), (
        "planner did not queue _test_lfi against the FI endpoint"
    )

    # Dispatch only the LFI tasks (keeps the live run fast) with no deadline, and
    # confirm the finding lands against the FI endpoint.
    plan.tasks = [t for t in plan.tasks if t.test_method == "_test_lfi"]
    exploit_agent._deadline_ts = None
    findings = await exploit_agent._step_execute_exploits(plan, None)

    assert any(fi_path in (f.target or "") for f in findings), (
        f"LFI not confirmed via dispatch against {fi_url}; "
        f"findings={[(f.title, f.target) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Pipeline gates: SQLi / Reflected XSS / CMDi confirmed THROUGH the full
# planner -> coverage-union -> dispatch -> methodology path (not the isolated
# _test_* smoke call). These are the gates that would have caught the 76a9ead5
# misses: the isolated smoke tests passed while the pipeline confirmed nothing.
# ---------------------------------------------------------------------------


async def _confirm_through_planner(
    exploit_agent: ExploitAgent,
    dvwa_url: str,
    dvwa_session: dict[str, str],
    *,
    path: str,
    endpoint: Endpoint,
    decoys: list[Endpoint],
    test_method: str,
) -> list[Finding]:
    """Queue ``test_method`` against ``endpoint`` via the coverage union, then
    dispatch only that method and return the findings. Skips if the DVWA module
    is absent. Shared by the SQLi / XSS / CMDi pipeline gates below.
    """
    if not _endpoint_exists(dvwa_url, path, dvwa_session):
        pytest.xfail(f"DVWA version does not have {path} (404)")

    ranked = exploit_agent._dedupe_and_rank_endpoints([*decoys, endpoint])
    plan = exploit_agent._merge_coverage(ExploitPlan(tasks=[]), ranked, [], [])

    # Clean-session guard (76a9ead5 root cause): a PHPIDS/security toggle is in
    # the decoys, mimicking what the crawler discovers. The planner MUST drop it
    # so dispatch never GET-visits it and enables the WAF for the shared session
    # — which is exactly what made SQLi/XSS confirm nothing in the pipeline.
    leaked = [t.endpoint_url for t in plan.tasks if is_state_changing_url(t.endpoint_url)]
    assert not leaked, f"planner queued state-changing endpoint(s): {leaked}"

    assert any(t.test_method == test_method and path in t.endpoint_url for t in plan.tasks), (
        f"planner did not queue {test_method} against {path}"
    )

    plan.tasks = [t for t in plan.tasks if t.test_method == test_method]
    exploit_agent._deadline_ts = None
    return await exploit_agent._step_execute_exploits(plan, None)


async def test_sqli_through_planner_dispatch_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    """SQLi confirmed via planner->dispatch against /vulnerabilities/sqli/."""
    path = "/vulnerabilities/sqli/"
    findings = await _confirm_through_planner(
        exploit_agent,
        dvwa_url,
        dvwa_session,
        path=path,
        endpoint=Endpoint(
            url=f"{dvwa_url}{path}?id=1&Submit=Submit", method="GET", params=["id", "Submit"]
        ),
        decoys=[
            Endpoint(url=f"{dvwa_url}/instructions.php?doc=PDF", method="GET", params=["doc"]),
            # The PHPIDS WAF toggle the crawler discovers — must be dropped.
            Endpoint(url=f"{dvwa_url}/security.php?phpids=on", method="GET", params=["phpids"]),
        ],
        test_method="_test_sqli",
    )
    assert any(path in (f.target or "") for f in findings), (
        f"SQLi not confirmed via dispatch; findings={[(f.title, f.target) for f in findings]}"
    )


async def test_xss_reflected_through_planner_dispatch_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    """Reflected XSS confirmed via planner->dispatch against /vulnerabilities/xss_r/."""
    path = "/vulnerabilities/xss_r/"
    findings = await _confirm_through_planner(
        exploit_agent,
        dvwa_url,
        dvwa_session,
        path=path,
        endpoint=Endpoint(url=f"{dvwa_url}{path}?name=test", method="GET", params=["name"]),
        decoys=[
            Endpoint(url=f"{dvwa_url}/instructions.php?doc=PDF", method="GET", params=["doc"]),
            # The PHPIDS WAF toggle the crawler discovers — must be dropped.
            Endpoint(url=f"{dvwa_url}/security.php?phpids=on", method="GET", params=["phpids"]),
        ],
        test_method="_test_xss_reflected",
    )
    assert any(path in (f.target or "") for f in findings), (
        f"Reflected XSS not confirmed via dispatch; "
        f"findings={[(f.title, f.target) for f in findings]}"
    )


async def test_cmdi_through_planner_dispatch_against_dvwa(
    dvwa_url: str,
    dvwa_session: dict[str, str],
    exploit_agent: ExploitAgent,
) -> None:
    """CMDi confirmed via planner->dispatch against /vulnerabilities/exec/ (POST form)."""
    path = "/vulnerabilities/exec/"
    findings = await _confirm_through_planner(
        exploit_agent,
        dvwa_url,
        dvwa_session,
        path=path,
        endpoint=Endpoint(url=f"{dvwa_url}{path}", method="POST", params=["ip", "Submit"]),
        decoys=[
            Endpoint(url=f"{dvwa_url}/instructions.php?doc=PDF", method="GET", params=["doc"]),
            # The PHPIDS WAF toggle the crawler discovers — must be dropped.
            Endpoint(url=f"{dvwa_url}/security.php?phpids=on", method="GET", params=["phpids"]),
        ],
        test_method="_test_cmdi",
    )
    assert any(path in (f.target or "") for f in findings), (
        f"CMDi not confirmed via dispatch; findings={[(f.title, f.target) for f in findings]}"
    )
