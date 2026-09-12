"""A dict KEY is schema; only a value is data. The guard that ate the deliverable.

What was measured
-----------------

The default-credential sweep registers each password it is about to try, so one
that WORKS is not left in an artifact in plaintext. Its catalogue contains
``test``, ``root``, ``admin`` and ``password``. Registered secrets are replaced
as SUBSTRINGS, and ``redact_structure`` was passing dict KEYS through the same
replacement. On every run where that sweep fired:

* ``test_start`` became ``[REDACTED]_start`` and ``test_end`` became
  ``[REDACTED]_end``, so ``PentestReport.model_validate(report_dict)`` failed
  with two missing required fields and **no report.json, no Markdown and no PDF
  were written at all**. Reproduced in 30 seconds against DVWA; confirmed on a
  full cal.diy engagement (``92c89d0d``) that ran for an hour, recorded 1,466
  invocations, and produced no deliverable.
* ``test_method`` became ``[REDACTED]_method`` (34 occurrences in one trace) and
  every ``_test_sqli``-style key became ``_[REDACTED]_sqli``, destroying the
  class identity that ``regrade_stored_bundles.py``, ``corpus-replay`` and the
  plan-coverage account all key on.

A guard that damages the artifact it protects protects nothing. The rule is the
one this codebase already states about IDOR attribution — *the field NAME
survives because it is schema, not data* — applied where it does the most good.

What this file does NOT cover
-----------------------------

The VALUE side of the same registration is still lossy and is registered as R14:
``/auth/forgot-password`` renders as ``/auth/forgot-[REDACTED]`` and the LFI
oracle's ``root:x:0:0:`` marker as ``[REDACTED]:x:0:0:``. That is a question
about WHICH values may be substring-registered, with a real safety trade-off on
the other side of it, and it is not this rule.
"""

from __future__ import annotations

import pytest

from clinkz.engagement.secrets import clear_secrets, redact_structure, register_secret


@pytest.fixture(autouse=True)
def _sweep_catalogue_registered() -> None:
    """The exact registration the default-credential sweep performs."""
    clear_secrets()
    for candidate in ("test", "root", "admin", "password"):
        register_secret(candidate)
    yield
    clear_secrets()


def test_a_schema_key_survives_a_registered_word_inside_it() -> None:
    """The two keys whose loss took the whole deliverable down."""
    dumped = {
        "test_start": "2026-09-12T18:20:11Z",
        "test_end": "2026-09-12T19:22:26Z",
        "not_tested": [],
        "password_field": "pwd",
    }
    out = redact_structure(dumped)
    assert set(out) == {"test_start", "test_end", "not_tested", "password_field"}, (
        "a key that merely CONTAINS a registered word is schema with an unlucky "
        "substring. Rewriting it made PentestReport.model_validate reject its own "
        "dump for two missing required fields, and no report was written at all."
    )


def test_the_class_identity_every_offline_driver_keys_on_survives() -> None:
    """``test_method`` and ``_test_*`` keys are the audit trail's identity."""
    out = redact_structure(
        {
            "kept_by_class": {"_test_sqli": 3, "_test_brute_force": 1},
            "dropped_by_class": {"_test_idor": ["http://t/a"]},
            "test_method": "_test_sqli",
        }
    )
    assert set(out["kept_by_class"]) == {"_test_sqli", "_test_brute_force"}
    assert set(out["dropped_by_class"]) == {"_test_idor"}
    assert "test_method" in out


def test_a_key_that_is_nothing_but_a_secret_is_still_redacted() -> None:
    """The fix narrows the rule; it does not remove it.

    A dict genuinely keyed BY credential material is not schema, and the whole
    key being consumed by the redaction is exactly how that is recognised.
    """
    out = redact_structure({"admin": "counted", "test_start": "kept"})
    assert "admin" not in out
    assert "[REDACTED]" in out
    assert out["[REDACTED]"] == "counted"
    assert out["test_start"] == "kept"


def test_a_key_that_is_entirely_a_token_shape_is_redacted() -> None:
    """Shape rules reach a key too, on the same end-to-end condition."""
    clear_secrets()
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    out = redact_structure({jwt: "session"})
    assert jwt not in out, "a key that is nothing but a JWT is not schema"


def test_values_keep_substring_redaction() -> None:
    """A value is DATA, and the registration exists to reach it.

    Narrowing the key rule must not narrow the value rule: a working default
    credential appearing in a response body or an argv is exactly what the
    sweep's registration is for.
    """
    out = redact_structure({"body": "username=x&password=admin", "note": "tried root"})
    assert "admin" not in out["body"]
    assert "root" not in out["note"]


def test_a_non_string_key_is_returned_unchanged() -> None:
    """Integer and tuple keys reach the walker from model dumps and must survive."""
    out = redact_structure({1: "a", (2, 3): "b"})
    assert set(out) == {1, (2, 3)}
