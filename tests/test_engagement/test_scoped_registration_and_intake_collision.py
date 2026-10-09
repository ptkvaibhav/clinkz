"""A registration is scoped to where the secret can appear; its spelling is no longer refused.

The two halves of R14's value problem, which have different sources and
therefore different fixes:

* **Lifetime.** The default-credential sweep registers catalogue words —
  ``test``, ``root``, ``admin``, ``password`` — and a registered value is
  replaced as a substring in every artifact written while it is armed. Measured
  on engagement ``92c89d0d`` (cal.diy): **711,918** replacements landed inside a
  longer string, overwhelmingly in the target's own i18n bundle where ``admin``
  appears in ordinary English prose, plus 6,227 copies of the URL
  ``/auth/forgot-password``, 64 copies of an LFI oracle's ``root:x:0:0:``
  marker, and a command-injection payload. None of that was written near a
  credential POST. A catalogue password is public **until it works**, so the
  window in which it is a secret is the attempt — and that is what the
  registration's lifetime now matches.

* **Spelling — retired by register R30.** An operator credential that spelled
  a word the engine's own models declare used to be REFUSED at intake, because
  substring redaction rewrote that schema out of every dump. Redaction is now
  decided per occurrence by provenance, which never rewrites a schema name or an
  enum leaf, so the refusal guarded nothing and came out. The tests below pin
  that those credentials are ACCEPTED, and the dump round-trip that the refusal
  existed to protect is pinned in ``test_whole_structure_transformations.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from clinkz.engagement.schema_vocabulary import (
    declared_enum_values,
    declared_field_names,
)
from clinkz.engagement.secrets import (
    clear_secrets,
    is_registered,
    load_credential_file,
    provisional_secret,
    redact,
    register_credential_set,
    register_secret,
    registered_secret_count,
    release_secret,
)
from clinkz.models.engagement import CredentialSet, RoleCredential

#: A four-character secret that is a substring of the enum VALUE ``medium``.
#: This is R14's own example: ``PentestReport`` declares ``medium_count``, so a
#: control registering the first four characters of every declared field name
#: registers this one, and ``Finding.severity`` then fails to validate.
FOUR_CHAR_COLLISION = "medi"

#: A credential whose VALUE is the word ``password`` — a declared field name on
#: ``RoleCredential`` itself, and on every JSON body the engine records.
PASSWORD_AS_VALUE = "password"


@pytest.fixture(autouse=True)
def _clean_registry() -> None:
    clear_secrets()
    yield
    clear_secrets()


def _cred_set(password: str, role: str = "admin") -> CredentialSet:
    return CredentialSet(
        credentials=[RoleCredential(role=role, username="operator@example.test", password=password)]
    )


# ---------------------------------------------------------------------------
# Intake accepts what it used to refuse (register R30)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [FOUR_CHAR_COLLISION, PASSWORD_AS_VALUE, "findings", "test_start", "admin", "root"],
)
def test_a_credential_that_spells_schema_is_accepted_and_registered(password: str) -> None:
    """``medi`` (inside the enum value ``medium``), ``password`` and ``findings``
    (declared field names) were refused at intake. Provenance redaction never
    rewrites a schema name or an enum leaf, so they register like any other.
    """
    register_credential_set(_cred_set(password))
    assert is_registered(password)


def test_an_ordinary_credential_is_accepted() -> None:
    for password in ("admin123", "ncc-1701", "Sv3n-Passphrase", "P@ssw0rd", "hunter2"):
        clear_secrets()
        register_credential_set(_cred_set(password))
        assert is_registered(password), password


def test_a_credential_too_short_to_register_is_not_registered() -> None:
    """``new`` is three characters, below ``_MIN_REDACTABLE_LEN``."""
    assert "new" in declared_enum_values()
    register_credential_set(_cred_set("new"))
    assert registered_secret_count() == 0


def test_the_credential_file_path_accepts_a_schema_spelled_password(tmp_path: Path) -> None:
    creds = tmp_path / "creds.json"
    creds.write_text(
        json.dumps(
            {"credentials": [{"role": "admin", "username": "admin", "password": "password"}]}
        ),
        encoding="utf-8",
    )
    load_credential_file(creds)
    assert is_registered("password")


# ---------------------------------------------------------------------------
# The computed vocabulary
# ---------------------------------------------------------------------------


def test_the_vocabulary_reader_finds_something() -> None:
    """A domain reader that returns nothing proves only that it is broken."""
    names = declared_field_names()
    values = declared_enum_values()
    assert len(names) > 300, f"only {len(names)} declared field names — the walk is broken"
    assert len(values) > 100, f"only {len(values)} declared enum values — the walk is broken"
    assert "password" in names and "findings" in names
    assert "medium" in values and "confirmed" in values


def test_the_vocabulary_is_computed_from_the_package_not_a_list() -> None:
    """Every model module contributes, so a new one is covered by its own commit."""
    owners = {owner for owners, _ in declared_field_names().values() for owner in owners}
    modules = {owner.rsplit(".", 1)[0] for owner in owners}
    for expected in (
        "clinkz.models.engagement",
        "clinkz.models.finding",
        "clinkz.models.report",
        "clinkz.models.scan",
        "clinkz.models.scope",
    ):
        assert expected in modules, f"{expected} declares models and is not in the vocabulary"


# ---------------------------------------------------------------------------
# Scoped registration
# ---------------------------------------------------------------------------


def test_a_guess_is_armed_inside_the_attempt_and_released_after() -> None:
    """The whole of the lifetime rule, in four lines."""
    with provisional_secret("s3kr1t-guess") as guess:
        assert guess.registered
        assert redact("body=s3kr1t-guess") == "body=[REDACTED]"
    assert not is_registered("s3kr1t-guess")
    assert redact("body=s3kr1t-guess") == "body=s3kr1t-guess"


def test_a_guess_that_works_is_kept() -> None:
    """A default password stops being public the moment it authenticates."""
    with provisional_secret("s3kr1t-guess") as guess:
        guess.keep()
    assert is_registered("s3kr1t-guess")


def test_an_exception_inside_the_attempt_still_releases() -> None:
    """The release is a ``finally``, not a line at the end of the happy path."""
    with pytest.raises(RuntimeError), provisional_secret("s3kr1t-guess"):
        raise RuntimeError("the authenticator raised")
    assert not is_registered("s3kr1t-guess")


def test_a_failed_guess_does_not_disarm_another_sources_registration() -> None:
    """The registry is COUNTED, and this is why.

    The operator's credential and the sweep's catalogue are two independent
    sources and they can register the same string. With a set, the sweep's
    release on a failed guess turns the operator's redaction off for the rest of
    the run — the second layer silently absent, which is the failure mode this
    whole module exists to prevent.
    """
    register_credential_set(_cred_set("admin123"))
    with provisional_secret("admin123"):
        assert is_registered("admin123")
    assert is_registered("admin123"), (
        "a failed guess released the OPERATOR's registration of the same value"
    )


def test_nested_provisional_registrations_release_independently() -> None:
    """Two concurrent attempts on the same catalogue word."""
    with provisional_secret("shared-word"):
        with provisional_secret("shared-word"):
            assert is_registered("shared-word")
        assert is_registered("shared-word"), "the inner release dropped both"
    assert not is_registered("shared-word")


def test_releasing_a_value_nobody_registered_is_a_no_op() -> None:
    """A caller that got ``False`` from register_secret and released anyway."""
    assert register_secret("ab") is False
    assert release_secret("ab") is False
    with provisional_secret("ab") as guess:
        assert guess.registered is False
    assert registered_secret_count() == 0


def test_the_cal_diy_shape_the_scoping_was_built_for() -> None:
    """The measured corruption, reproduced and then not reproduced.

    Three artifacts from engagement ``92c89d0d``: a URL in the deliverable, an
    LFI oracle's evidence marker, and a command-injection payload. All three
    were written far away in time from the eight credential POSTs that justified
    the registration, and all three were rewritten.
    """
    artifacts = [
        "GET /auth/forgot-password HTTP/1.1",
        "root:x:0:0:root:/root:/bin/bash",
    ]
    attempt = "POST /login username=root&password=admin"

    with provisional_secret("password"), provisional_secret("root"), provisional_secret("admin"):
        during = [redact(a) for a in artifacts]
        during_attempt = redact(attempt)
    after = [redact(a) for a in artifacts]

    assert "password=[REDACTED]" in during_attempt, (
        "the credential the attempt SENT must be redacted while it is armed — that is "
        "the whole of what the registration defends"
    )
    assert during[0] == artifacts[0], (
        "register R30: even while armed, a word inside a URL is part of another "
        "token, not the credential"
    )
    assert during[1].startswith("root:x:0:0:"), (
        "the LFI oracle's marker keeps its NAME position; the later fields are bare "
        "values no anonymous response served, so the armed window redacts them — "
        "fail closed, and only for the length of the attempt"
    )
    assert after == artifacts, (
        "an artifact written after the attempt carries no secret, and rewriting it "
        "is the 711,918-site corruption"
    )


# ---------------------------------------------------------------------------
# Through the call site, not only the seam
# ---------------------------------------------------------------------------


class _Result(SimpleNamespace):
    """What ``WebAuthenticator.authenticate`` returns, reduced to what is read."""


def _authenticator_returning(result: _Result) -> Any:
    class _Authenticator:
        def __init__(self, **_kw: object) -> None:
            pass

        async def authenticate(self, *_a: object, **_kw: object) -> _Result:
            return result

    return _Authenticator


@pytest.mark.asyncio
@pytest.mark.parametrize("succeeds", [False, True])
async def test_the_sweeps_own_call_site_arms_and_releases(
    monkeypatch: pytest.MonkeyPatch, succeeds: bool
) -> None:
    """The scoping verified where the sweep actually calls it.

    A context manager tested on its own cannot show that the call site wraps the
    request rather than a line beside it, and the failure that mattered was a
    lifetime, not a mechanism.
    """
    import clinkz.tools.auth as auth_module
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    seen: dict[str, bool] = {}

    class _Store:
        async def mark_valid(self, *_a: object, **_kw: object) -> None:
            seen["marked_valid"] = True

    result = _Result(
        success=succeeds,
        verdict=auth_module.LoginVerdict.PROVEN if succeeds else auth_module.LoginVerdict.REFUSED,
        session_cookies={"SESSION": "abc"},
        bearer_token="",
    )
    monkeypatch.setattr(auth_module, "WebAuthenticator", _authenticator_returning(result))

    agent = OrchestratorAgent.__new__(OrchestratorAgent)
    agent._logger = __import__("logging").getLogger("test")
    agent._scope = None
    agent._engagement_id = "00000000-0000-0000-0000-000000000000"
    agent._cred_store = _Store()  # type: ignore[assignment]

    outcome = await agent._attempt_login("http://app/login", "admin", "catalogue-guess", "cred-1")

    assert outcome is succeeds
    assert is_registered("catalogue-guess") is succeeds, (
        "a guess that WORKS is a live credential and stays registered; one that "
        "failed is a public default and must not rewrite the rest of the run"
    )
