"""Unit tests for crawl/probe state-change safety predicate.

Guards the regression where the Scan Agent GET-visited
``security.php?phpids=on`` and enabled DVWA's PHPIDS WAF for the whole shared
engagement session — silently blocking every later injection payload. The
predicate must flag WAF / security-level toggles and logout links while leaving
legitimate content endpoints (including ones that merely *carry* a ``security``
query value) untouched.
"""

from __future__ import annotations

import pytest

from clinkz.agents._url_safety import find_session_setter_urls, is_state_changing_url


@pytest.mark.parametrize(
    "url",
    [
        "http://t/security.php?phpids=on",
        "http://t/security.php?phpids=off",
        "http://172.20.0.2/security.php?phpids=on",
        "http://t/SECURITY.PHP?PHPIDS=ON",  # case-insensitive
        "http://t/security.php?seclev_submit=Submit&security=high",
        "http://t/security.php?seclev=high",
        "http://t/logout.php",
        "http://t/app/logout",
        "http://t/account/signout",
        "http://t/auth/logoff",
        "/security.php?phpids=on",  # relative form from a crawler
    ],
)
def test_state_changing_urls_flagged(url: str) -> None:
    assert is_state_changing_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        # The canonical DVWA vulnerable surfaces must NOT be excluded — the
        # full behind-login module set a katana crawl surfaces. A guard that
        # dropped any of these would make the authenticated crawl look empty.
        "http://t/vulnerabilities/sqli/?id=1&Submit=Submit",
        "http://t/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
        "http://t/vulnerabilities/xss_r/?name=test",
        "http://t/vulnerabilities/xss_s/",
        "http://t/vulnerabilities/xss_d/?default=English",
        "http://t/vulnerabilities/exec/",
        "http://t/vulnerabilities/fi/?page=include.php",
        "http://t/vulnerabilities/upload/",
        "http://t/vulnerabilities/csrf/",
        "http://t/vulnerabilities/brute/",
        "http://t/vulnerabilities/captcha/",
        "http://t/vulnerabilities/csp/",
        "http://t/vulnerabilities/javascript/",
        "http://t/vulnerabilities/weak_id/",
        # A legit content endpoint that merely carries a security= value — the
        # predicate keys on toggles (phpids / seclev_submit / seclev), not on a
        # bare ``security`` param, so this stays in scope.
        "http://t/vulnerabilities/view_source.php?id=fi&security=low",
        "http://t/index.php",
        "http://t/login.php",  # GET of the login form is harmless / needed
        "http://t/setup.php",  # GET shows the page; only the POST resets the DB
        "",
        "not a url",
    ],
)
def test_safe_urls_not_flagged(url: str) -> None:
    assert is_state_changing_url(url) is False


# ---------------------------------------------------------------------------
# Session-value setter reference scraping
# ---------------------------------------------------------------------------


class TestFindSessionSetterUrls:
    """The scraper must catch DVWA's onclick popUp ref and reject noise."""

    def test_dvwa_onclick_popup_ref_resolved(self) -> None:
        """DVWA SQLi high links its setter via onclick, not an href/form."""
        body = (
            '<a href="#" onclick="popUp(\'session-input.php\'); return false;">'
            "Click here to change your ID.</a>"
        )
        got = find_session_setter_urls("http://t/vulnerabilities/sqli/", body)
        assert got == ["http://t/vulnerabilities/sqli/session-input.php"]

    def test_href_and_window_open_forms(self) -> None:
        body = (
            '<a href="/app/session-input.php">set</a>'
            "<button onclick=\"window.open('session-set.php')\">x</button>"
        )
        got = find_session_setter_urls("http://t/app/page", body)
        assert "http://t/app/session-input.php" in got
        assert "http://t/app/session-set.php" in got

    @pytest.mark.parametrize(
        "body",
        [
            '<script src="/js/sessions.js"></script>',  # bundle, no set/input signal
            'sessionStorage.getItem("k")',  # not a URL token
            '<div class="session-banner">hi</div>',  # not path-shaped / not setter
            "<p>your session expired</p>",  # bare word, no quotes/path
            "",  # empty body
        ],
    )
    def test_incidental_session_refs_rejected(self, body: str) -> None:
        assert find_session_setter_urls("http://t/x/", body) == []

    def test_cross_origin_setter_dropped(self) -> None:
        body = "<a onclick=\"popUp('http://evil.example/session-input.php')\">x</a>"
        assert find_session_setter_urls("http://t/x/", body) == []

    def test_dedup_preserves_order(self) -> None:
        body = (
            "<a onclick=\"popUp('session-input.php')\">a</a>"
            "<a onclick=\"popUp('session-input.php')\">b</a>"
            '<a href="session-set.php">c</a>'
        )
        got = find_session_setter_urls("http://t/m/", body)
        assert got == ["http://t/m/session-input.php", "http://t/m/session-set.php"]
