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

from clinkz.agents._url_safety import is_state_changing_url


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
        # The canonical DVWA vulnerable surfaces must NOT be excluded.
        "http://t/vulnerabilities/sqli/?id=1&Submit=Submit",
        "http://t/vulnerabilities/xss_r/?name=test",
        "http://t/vulnerabilities/exec/",
        "http://t/vulnerabilities/fi/?page=include.php",
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
