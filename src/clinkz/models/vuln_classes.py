"""Canonical registry of vulnerability classes — the client-facing view.

The Exploit Agent's own tables (``_CLASS_PATH_TOKENS``, ``_CLASS_PARAM_NAMES``,
``_CLASS_PRECONDITIONS``) are how a class gets *ranked and dispatched*. This
registry is how a class gets *talked about*: the human label a report prints, the
permitted-technique name a client authorizes, and — the part that matters most —
an honest statement of what this engine can and cannot prove about it.

Two things a professional deliverable must not do: silently omit a class the
client assumes was tested, and imply a class was cleared when the engine has no
oracle for it. Both are prevented by making the limitation a **field**, so the
report's "what was NOT tested" section is generated from the same registry the
planner is checked against rather than written by hand and left to rot.

:mod:`tests.test_models.test_vuln_classes` asserts this registry stays in sync
with the Exploit Agent's dispatch table, so a class added there without a client
label fails the build rather than disappearing from reports.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ConfirmationCapability(StrEnum):
    """What this engine can prove about a class.

    Attributes:
        SERVER_SIDE: The defining effect is observable in a server response, so
            a finding here is confirmable in-band.
        OUT_OF_BAND: Confirmable only via the P6 out-of-band collaborator; with
            no collaborator provisioned the class defers rather than confirms.
        CLIENT_SIDE_ORACLE_REQUIRED: The defining effect happens in a browser
            (script execution, policy enforcement). Without a client-side oracle
            this engine can report reachability but must never claim the effect.
        NOT_IMPLEMENTED: No methodology exists. Reported as untested, never as
            clean.
    """

    SERVER_SIDE = "server_side"
    OUT_OF_BAND = "out_of_band"
    CLIENT_SIDE_ORACLE_REQUIRED = "client_side_oracle_required"
    NOT_IMPLEMENTED = "not_implemented"


class VulnClass(BaseModel):
    """One vulnerability class as a client sees it.

    Attributes:
        key: Technique name a client authorizes (``sql_injection``). This is what
            :meth:`~clinkz.models.engagement.AuthorizationRecord.permits` matches.
        test_method: The Exploit Agent method that implements it, or ``""``.
        label: Human name for the report.
        capability: What the engine can prove.
        limitation: Why the class is limited, when it is. Rendered verbatim in
            the report's "what was NOT tested" section — so it has to read as a
            sentence, not a code comment.
    """

    key: str
    test_method: str
    label: str
    capability: ConfirmationCapability
    limitation: str = ""


_C = ConfirmationCapability

#: Every class the engine plans, keyed by the Exploit Agent's method name.
VULN_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="sql_injection",
        test_method="_test_sqli",
        label="SQL Injection",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="nosql_injection",
        test_method="_test_nosqli",
        label="NoSQL Injection",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="ssti",
        test_method="_test_ssti",
        label="Server-Side Template Injection",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="xxe",
        test_method="_test_xxe",
        label="XML External Entity Injection",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="jwt",
        test_method="_test_jwt",
        label="JWT / Token Forgery",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="ssrf",
        test_method="_test_ssrf",
        label="Server-Side Request Forgery",
        capability=_C.OUT_OF_BAND,
        limitation=(
            "A blind SSRF — one whose response body reveals nothing — is only "
            "confirmable through an out-of-band callback. Where no collaborator "
            "was provisioned for this engagement, blind candidates are reported "
            "as unproven leads rather than findings."
        ),
    ),
    VulnClass(
        key="xss_reflected",
        test_method="_test_xss_reflected",
        label="Reflected Cross-Site Scripting",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="xss_stored",
        test_method="_test_xss_stored",
        label="Stored Cross-Site Scripting",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="xss_dom",
        test_method="_test_xss_dom",
        label="DOM-based Cross-Site Scripting",
        capability=_C.CLIENT_SIDE_ORACLE_REQUIRED,
        limitation=(
            "DOM-based XSS executes in the browser, not in a response body. This "
            "engine has no client-side execution oracle, so it can identify a "
            "sink reachable from a controllable source but cannot witness the "
            "script running. Candidates are reported as unproven leads. A manual "
            "browser check, or a headless-browser oracle, is required to confirm."
        ),
    ),
    VulnClass(
        key="command_injection",
        test_method="_test_cmdi",
        label="OS Command Injection",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="lfi",
        test_method="_test_lfi",
        label="Local File Inclusion / Path Traversal",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="file_upload",
        test_method="_test_file_upload",
        label="Unrestricted File Upload",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Only upload branches whose effect this engine can observe may "
            "confirm; branches whose effect requires a client-side or "
            "out-of-band observation are reported as unproven leads naming both "
            "the claimed effect and the observation that would prove it."
        ),
    ),
    VulnClass(
        key="csrf",
        test_method="_test_csrf",
        label="Cross-Site Request Forgery",
        capability=_C.SERVER_SIDE,
        limitation=(
            "CSRF is confirmed by token-absence and origin-acceptance analysis. "
            "Where the only proving action would be an actual state change "
            "(a password change, a funds transfer), the production safety rails "
            "refuse to perform it and the class reports reachability only."
        ),
    ),
    VulnClass(
        key="idor",
        test_method="_test_idor",
        label="Insecure Direct Object Reference / Broken Access Control",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Requires at least two authenticated roles to prove that an "
            "authorization boundary was crossed. With a single role (or none) "
            "the class can only report candidates."
        ),
    ),
    VulnClass(
        key="brute_force",
        test_method="_test_brute_force",
        label="Weak Authentication / Credential Brute Force",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="open_redirect",
        test_method="_test_open_redirect",
        label="Open Redirect",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="security_headers",
        test_method="_test_security_headers",
        label="Security Header & Transport Hygiene",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Content-Security-Policy is assessed as a declared policy only. "
            "Whether a given policy is actually bypassable depends on how a "
            "browser resolves it against the page's real script sources, which "
            "requires a client-side oracle this engine does not have."
        ),
    ),
    VulnClass(
        key="weak_session",
        test_method="_test_weak_session",
        label="Weak Session Management",
        capability=_C.SERVER_SIDE,
    ),
    VulnClass(
        key="javascript_attacks",
        test_method="_test_javascript_attacks",
        label="Client-Side Logic Flaws",
        capability=_C.CLIENT_SIDE_ORACLE_REQUIRED,
        limitation=(
            "Confirmation requires the server to accept a value rebuilt from the "
            "page's own client-side chain while rejecting an equal-shaped "
            "control. Where that server-side acceptance cannot be observed, the "
            "class reports the client-side control's existence as reachability, "
            "never as an exploited effect."
        ),
    ),
)

#: Classes with no methodology at all. Listed so a report can say "not tested"
#: about them explicitly rather than leaving a client to assume coverage.
UNIMPLEMENTED_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="insecure_captcha",
        test_method="",
        label="Insecure CAPTCHA",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "No methodology. CAPTCHA-bypass testing requires solving or "
            "replaying a human-verification challenge, which this engine does "
            "not attempt. Not tested."
        ),
    ),
    VulnClass(
        key="business_logic",
        test_method="",
        label="Business Logic Flaws",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "No methodology. Business-logic abuse depends on what the "
            "application is FOR, which is not derivable from its HTTP surface. "
            "Requires a human tester with domain context. Not tested."
        ),
    ),
    VulnClass(
        key="race_condition",
        test_method="",
        label="Race Conditions",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "No methodology. Proving a race requires deliberately concurrent "
            "state-changing requests, which the production safety rails refuse "
            "to send. Not tested."
        ),
    ),
)

_BY_METHOD: dict[str, VulnClass] = {vc.test_method: vc for vc in VULN_CLASSES}
_BY_KEY: dict[str, VulnClass] = {vc.key: vc for vc in (*VULN_CLASSES, *UNIMPLEMENTED_CLASSES)}


def for_method(test_method: str) -> VulnClass | None:
    """Return the class implemented by *test_method*, or ``None``."""
    return _BY_METHOD.get(test_method)


def for_key(key: str) -> VulnClass | None:
    """Return the class named by a permitted-technique *key*, or ``None``."""
    return _BY_KEY.get((key or "").strip().lower())


def classes_requiring_client_side_oracle() -> tuple[VulnClass, ...]:
    """Classes this engine cannot confirm without a browser-side oracle."""
    return tuple(vc for vc in VULN_CLASSES if vc.capability is _C.CLIENT_SIDE_ORACLE_REQUIRED)


def limited_classes() -> tuple[VulnClass, ...]:
    """Every class carrying a stated limitation, implemented or not."""
    return tuple(vc for vc in (*VULN_CLASSES, *UNIMPLEMENTED_CLASSES) if vc.limitation)


__all__ = [
    "UNIMPLEMENTED_CLASSES",
    "VULN_CLASSES",
    "ConfirmationCapability",
    "VulnClass",
    "classes_requiring_client_side_oracle",
    "for_key",
    "for_method",
    "limited_classes",
]
