"""The class registry must not drift from what the engine actually dispatches.

A class the Exploit Agent ranks and dispatches but the registry has never heard
of vanishes from the report's "what was NOT tested" section AND from the
permitted-technique gate — it is silently tested without authorization and
silently omitted from the deliverable. Both failures are invisible at runtime,
which is why they are asserted here.
"""

from __future__ import annotations

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS
from clinkz.models.vuln_classes import (
    DISCOVERY_CLASSES,
    UNIMPLEMENTED_CLASSES,
    VULN_CLASSES,
    ConfirmationCapability,
    classes_requiring_client_side_oracle,
    for_finding,
    for_key,
    for_method,
    limited_classes,
)


def test_every_dispatched_class_has_a_client_label() -> None:
    """The domain is the dispatch table itself, not a ranking table beside it.

    This asserted over ``_CLASS_PATH_TOKENS`` — one of the ranking signal maps,
    which happens to hold 27 of the dispatch table's 30 names. The three it does
    not hold are the three the dispatcher can run and the registry had never
    described: ``_test_log4shell`` (covered, by luck, through
    ``DISCOVERY_CLASSES``) and ``_test_tier2_technique`` /
    ``_test_tier3_technique``, which were in no registry table at all. They were
    outside the assertion's domain, so it passed while the exact failure it
    exists to prevent was live.
    """
    registered = {
        vc.test_method
        for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES, *UNIMPLEMENTED_CLASSES)
        if vc.test_method
    }
    missing = sorted(set(DISPATCHABLE_TEST_METHODS) - registered)
    assert not missing, (
        f"the Exploit Agent dispatches {missing} but the registry does not describe "
        "them; they would be invisible in the report and ungated by authorization"
    )


def test_registry_keys_are_unique() -> None:
    keys = [vc.key for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES, *UNIMPLEMENTED_CLASSES)]
    assert len(keys) == len(set(keys))


def test_every_class_carries_the_fields_a_report_needs() -> None:
    for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES, *UNIMPLEMENTED_CLASSES):
        assert vc.key and vc.label, vc
        if vc.capability is not ConfirmationCapability.NOT_IMPLEMENTED:
            assert vc.test_method, f"{vc.key} claims a capability but names no method"


def test_every_limited_class_explains_itself_in_a_sentence() -> None:
    """The limitation text is rendered verbatim to a client."""
    for vc in limited_classes():
        assert vc.limitation.strip().endswith("."), (
            f"{vc.key}'s limitation is rendered verbatim in the report and must read as a sentence"
        )
        assert len(vc.limitation) > 40, f"{vc.key}'s limitation is too terse to act on"


def test_classes_with_no_oracle_are_named_explicitly() -> None:
    """The brief's named cases: DOM-XSS / CSP, and Insecure CAPTCHA."""
    no_oracle = {vc.key for vc in classes_requiring_client_side_oracle()}
    assert "xss_dom" in no_oracle
    assert "javascript_attacks" in no_oracle

    unimplemented = {vc.key for vc in UNIMPLEMENTED_CLASSES}
    assert "insecure_captcha" in unimplemented

    # CSP enforceability is a stated limitation of the header class rather than
    # a class of its own — the header IS assessed, its bypassability is not.
    headers = for_key("security_headers")
    assert headers is not None
    assert "content-security-policy" in headers.limitation.lower()


def test_every_confirmable_class_carries_remediation() -> None:
    """A client-ready finding has to say what to DO about it."""
    for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES):
        assert vc.remediation, f"{vc.key} has no remediation guidance"
        assert len(vc.remediation) > 80, f"{vc.key}'s remediation is too thin to act on"


def test_lookups_agree_with_each_other() -> None:
    for vc in VULN_CLASSES:
        assert for_method(vc.test_method) is vc
        assert for_key(vc.key) is vc


def test_finding_titles_resolve_to_the_right_class() -> None:
    """Real emitted titles, from the Exploit Agent's own format strings."""
    cases = {
        "SQL Injection in id parameter": "sql_injection",
        "NoSQL Injection in query parameter": "nosql_injection",
        "Reflected XSS in name parameter": "xss_reflected",
        "Stored XSS via mtxMessage in form": "xss_stored",
        "Command Injection in ip parameter": "command_injection",
        "Local File Inclusion in page parameter": "lfi",
        "Open Redirect via redirect parameter (at_syntax)": "open_redirect",
        "IDOR via id parameter (horizontal)": "idor",
        "No Brute-Force Protection on http://t/login.php": "brute_force",
        "Missing Security Header CSP on http://t": "security_headers",
        "Predictable / Weak Session ID in cookie 'sid'": "weak_session",
        "Server-Side Template Injection in tpl parameter": "ssti",
        "XML External Entity (XXE) Injection - file_read": "xxe",
        "JSON Web Token (JWT) Attack - alg_none": "jwt",
        "Server-Side Request Forgery (SSRF) - blind_oob": "ssrf",
        "Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress - q": "log4shell",
    }
    for title, expected in cases.items():
        resolved = for_finding(title)
        assert resolved is not None, f"no class resolved for {title!r}"
        assert resolved.key == expected, f"{title!r} -> {resolved.key}, expected {expected}"


def test_a_specific_token_beats_a_generic_one() -> None:
    """'stored xss' must not lose to a shorter overlapping token."""
    assert for_finding("Stored XSS via comment").key == "xss_stored"
    assert for_finding("DOM-based XSS in fragment sink").key == "xss_dom"


def test_an_unrecognised_title_resolves_to_nothing() -> None:
    """A missing remediation is honest; a confidently wrong one is not."""
    assert for_finding("Something the registry has never heard of") is None


def test_the_description_is_a_fallback_not_a_co_equal_haystack() -> None:
    """A parameter NAME must never outrank the title's own class token.

    `for_finding` searched `f"{title} {description}"` as one string, so the
    longest token anywhere won. A description is
    `"Technique: <id>. Parameter: <name>."`, and the parameter name is a value
    the methodology or the target chose — not a class name.

    On the 2026-08-21 DVWA ladder that misfiled P7's flagship at all three
    exploitable levels: `client-side` (11 chars, `_test_javascript_attacks`)
    beat `dom-based` (9 chars, `_test_xss_dom`) on a DOM-XSS finding whose
    parameter is literally `(client-side fragment)`. Remediation, the chaining
    yield vocabulary and the control re-grade all then read the wrong class.
    """
    title = "DOM-based XSS — script execution witnessed in a browser"
    description = "Technique: WSTG-CLNT-01. Parameter: (client-side fragment)."

    assert for_finding(title, description).test_method == "_test_xss_dom"
    # And the title alone already resolved — the description changed the answer.
    assert for_finding(title).test_method == "_test_xss_dom"


def test_the_description_still_resolves_a_title_that_cannot() -> None:
    """Fallback, not removal: a title matching nothing still gets its class."""
    resolved = for_finding("Finding on /api/v2/orders", "Technique: SQL Injection in id.")
    assert resolved is not None
    assert resolved.key == "sql_injection"
