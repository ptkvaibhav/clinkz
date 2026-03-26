#!/usr/bin/env python3
"""Diagnostic script — test every link in the auth chain against live DVWA.

Tests each step independently to identify where the auth handoff breaks:
  Step 1: WebAuthenticator.authenticate() directly
  Step 2: Session storage round-trip (save_session → get_sessions)
  Step 3: Session handoff (read from store → HTTP request with cookies)
  Step 4: Authenticated crawl (list vulnerability pages)
  Step 5: Exploit with session (SQLi page with and without injection)
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure clinkz is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.auth import WebAuthenticator, AuthResult
from clinkz.tools.http_client import HTTPClientTool

DVWA_BASE = "http://localhost:8080"
DVWA_LOGIN = f"{DVWA_BASE}/login.php"
USERNAME = "admin"
PASSWORD = "password"
DB_PATH = ":memory:"

# Permissive scope that covers both localhost and the Docker-internal IP
SCOPE = EngagementScope(
    name="auth-chain-test",
    targets=[
        ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
        ScopeEntry(value="172.20.0.2", type=ScopeType.IP),
    ],
    excluded=[],
)


def header(step: int, title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  Step {step}: {title}")
    print(f"{'='*60}")


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


def info(msg: str) -> None:
    print(f"  [INFO] {msg}")


async def step1_authenticate() -> AuthResult:
    """Test WebAuthenticator.authenticate() directly."""
    header(1, "Testing WebAuthenticator directly...")

    auth = WebAuthenticator(scope=SCOPE, engagement_id="test-diag")
    result = await auth.authenticate(DVWA_LOGIN, USERNAME, PASSWORD)

    info(f"success     = {result.success}")
    info(f"status_code = {result.status_code}")
    info(f"redirect_url= {result.redirect_url}")
    info(f"cookies     = {result.session_cookies}")
    info(f"error       = {result.error}")

    if result.success and result.session_cookies:
        ok("WebAuthenticator returned success with cookies")
    else:
        fail(f"WebAuthenticator failed: {result.error or 'no cookies returned'}")

    return result


async def step2_session_storage(
    state: StateStore,
    eid: str,
    auth_result: AuthResult,
) -> dict[str, str]:
    """Test session round-trip through the state store."""
    header(2, "Testing session storage...")

    # Save
    sid = await state.save_session(
        engagement_id=eid,
        agent="test-diag",
        cookies=auth_result.session_cookies,
        metadata={"login_url": DVWA_LOGIN, "username": USERNAME},
    )
    info(f"Saved session id = {sid}")

    # Read back
    sessions = await state.get_sessions(eid)
    info(f"Sessions in store = {len(sessions)}")

    if not sessions:
        fail("No sessions returned from get_sessions()")
        return {}

    stored_cookies = sessions[0]["cookies"]
    info(f"Stored cookies  = {stored_cookies}")
    info(f"Original cookies= {auth_result.session_cookies}")

    if stored_cookies == auth_result.session_cookies:
        ok("Stored cookies match original cookies")
    else:
        fail("Cookie mismatch after round-trip!")

    return stored_cookies


async def step3_session_handoff(
    cookies: dict[str, str],
) -> bool:
    """Test that session cookies grant access to an authenticated page."""
    header(3, "Testing session handoff...")

    http = HTTPClientTool(scope=SCOPE, engagement_id="test-diag")
    target_url = f"{DVWA_BASE}/vulnerabilities/sqli/"

    raw = await http.execute(
        http.validate_input(
            {
                "url": target_url,
                "method": "GET",
                "cookies": cookies,
                "follow_redirects": False,
            }
        )
    )
    parsed = http.parse_output(raw)

    info(f"URL         = {target_url}")
    info(f"status_code = {parsed.status_code}")

    # Check if we got the actual page vs a redirect to login
    body_lower = parsed.response_body.lower()
    has_form = "form" in body_lower and ("sqli" in body_lower or "id" in body_lower)
    is_redirect = parsed.status_code in (301, 302, 303, 307, 308)
    redirects_to_login = "login.php" in parsed.response_body.lower() or any(
        "login" in r.lower() for r in parsed.redirect_chain
    )

    info(f"has_form          = {has_form}")
    info(f"is_redirect       = {is_redirect}")
    info(f"redirects_to_login= {redirects_to_login}")

    if parsed.status_code == 200 and has_form and not redirects_to_login:
        ok("Got authenticated SQLi page (200 with form)")
        return True
    elif is_redirect or redirects_to_login:
        fail("Redirected to login — session cookies not accepted")
        # Show a snippet of the response for debugging
        info(f"Response body (first 300 chars): {parsed.response_body[:300]}")
        return False
    else:
        fail(f"Unexpected response: status={parsed.status_code}")
        info(f"Response body (first 300 chars): {parsed.response_body[:300]}")
        return False


async def step4_authenticated_crawl(cookies: dict[str, str]) -> int:
    """List all vulnerability pages accessible with the session."""
    header(4, "Testing authenticated crawl...")

    http = HTTPClientTool(scope=SCOPE, engagement_id="test-diag")
    vuln_index = f"{DVWA_BASE}/vulnerabilities/"

    raw = await http.execute(
        http.validate_input(
            {
                "url": vuln_index,
                "method": "GET",
                "cookies": cookies,
                "follow_redirects": False,
            }
        )
    )
    parsed = http.parse_output(raw)

    info(f"URL         = {vuln_index}")
    info(f"status_code = {parsed.status_code}")

    # Extract links from the response
    import re

    links = re.findall(r'href=["\']([^"\']*)["\']', parsed.response_body)
    # Known DVWA vulnerability directory names
    vuln_dirs = {"sqli", "xss_r", "xss_s", "xss_d", "exec", "csrf", "fi", "upload", "captcha", "brute"}
    vuln_pages = [
        l for l in links
        if "/vulnerabilities/" in l and l != "/vulnerabilities/"
        or l.rstrip("/") in vuln_dirs
    ]

    info(f"Total links found     = {len(links)}")
    info(f"Vulnerability pages   = {len(vuln_pages)}")
    for page in vuln_pages:
        info(f"  -> {page}")

    if vuln_pages:
        ok(f"Found {len(vuln_pages)} vulnerability pages")
    else:
        if parsed.status_code == 200:
            fail("Got 200 but no vulnerability links — page may be login redirect")
            info(f"Body snippet: {parsed.response_body[:300]}")
        else:
            fail(f"Could not access vulnerability index (status={parsed.status_code})")

    return len(vuln_pages)


async def step5_exploit_with_session(cookies: dict[str, str]) -> None:
    """Test SQLi page with a normal query and a SQL injection probe."""
    header(5, "Testing exploit with session...")

    http = HTTPClientTool(scope=SCOPE, engagement_id="test-diag")

    # --- Normal query ---
    normal_url = f"{DVWA_BASE}/vulnerabilities/sqli/?id=1&Submit=Submit"
    raw = await http.execute(
        http.validate_input(
            {
                "url": normal_url,
                "method": "GET",
                "cookies": cookies,
                "follow_redirects": False,
            }
        )
    )
    parsed = http.parse_output(raw)

    info(f"Normal query URL = {normal_url}")
    info(f"status_code      = {parsed.status_code}")

    body_lower = parsed.response_body.lower()
    has_user_data = any(
        kw in body_lower for kw in ("surname", "first name", "admin", "user")
    )
    info(f"has_user_data    = {has_user_data}")

    if parsed.status_code == 200 and has_user_data:
        ok("Normal query returned user data")
    elif "login.php" in body_lower:
        fail("Redirected to login — session lost")
    else:
        fail(f"No user data in response (status={parsed.status_code})")
        info(f"Body snippet: {parsed.response_body[:300]}")

    # --- SQL injection probe ---
    sqli_url = f"{DVWA_BASE}/vulnerabilities/sqli/?id='&Submit=Submit"
    raw2 = await http.execute(
        http.validate_input(
            {
                "url": sqli_url,
                "method": "GET",
                "cookies": cookies,
                "follow_redirects": False,
            }
        )
    )
    parsed2 = http.parse_output(raw2)

    info(f"SQLi probe URL   = {sqli_url}")
    info(f"status_code      = {parsed2.status_code}")

    body2_lower = parsed2.response_body.lower()
    has_sql_error = any(
        kw in body2_lower
        for kw in ("sql syntax", "mysql", "error", "warning", "you have an error")
    )
    info(f"has_sql_error    = {has_sql_error}")

    if parsed2.status_code == 200 and has_sql_error:
        ok("SQL injection probe triggered an error — SQLi confirmed")
    elif "login.php" in body2_lower:
        fail("Redirected to login — session lost on second request")
    else:
        fail(f"No SQL error in response (status={parsed2.status_code})")
        info(f"Body snippet: {parsed2.response_body[:300]}")


async def main() -> None:
    print("=" * 60)
    print("  Auth Chain Diagnostic — DVWA @ 172.20.0.2")
    print("=" * 60)

    # Step 1: authenticate
    auth_result = await step1_authenticate()

    # We need a state store for steps 2+
    async with StateStore(DB_PATH) as state:
        eid = await state.create_engagement(
            "auth-chain-test", SCOPE.model_dump()
        )

        # Step 2: session storage round-trip
        if auth_result.success:
            stored_cookies = await step2_session_storage(state, eid, auth_result)
        else:
            header(2, "Testing session storage...")
            fail("Skipped — Step 1 failed, no cookies to store")
            stored_cookies = {}

        # Use whichever cookies we have
        cookies = stored_cookies or auth_result.session_cookies

        if not cookies:
            header(3, "Testing session handoff...")
            fail("Skipped — no cookies available")
            header(4, "Testing authenticated crawl...")
            fail("Skipped — no cookies available")
            header(5, "Testing exploit with session...")
            fail("Skipped — no cookies available")
            print("\n" + "=" * 60)
            print("  RESULT: Auth chain broken at Step 1 (authentication)")
            print("=" * 60)
            return

        # Step 3: session handoff
        handoff_ok = await step3_session_handoff(cookies)

        # Step 4: authenticated crawl
        page_count = await step4_authenticated_crawl(cookies)

        # Step 5: exploit with session
        await step5_exploit_with_session(cookies)

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Step 1 (authenticate)   : {'PASS' if auth_result.success else 'FAIL'}")
    print(f"  Step 2 (session store)  : {'PASS' if stored_cookies else 'FAIL'}")
    print(f"  Step 3 (session handoff): {'PASS' if handoff_ok else 'FAIL'}")
    print(f"  Step 4 (auth crawl)     : {'PASS' if page_count > 0 else 'FAIL'}")
    print(f"  Step 5 (exploit w/sess) : (see details above)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
