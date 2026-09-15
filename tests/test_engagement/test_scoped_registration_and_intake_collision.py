"""A registration is scoped to where the secret can appear, and a colliding one is refused.

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

* **Spelling.** An operator credential that is a word the engine's own models
  declare corrupts the engine's own structures, and the two ways it does that
  both end in ``model_validate`` refusing a document. That cannot be fixed by
  scoping, because an operator credential is a secret for the whole run. It is
  refused at INTAKE instead, naming the colliding key — before a packet leaves,
  rather than at render time when a full engagement has already run.

The two are not alternatives. ``admin`` and ``root`` collide with nothing in the
vocabulary and would corrupt an English-language target anyway; a credential
spelled ``password`` is armed for the whole engagement and no scoping helps.
``test_the_catalogue_words_are_not_refused`` pins that boundary so neither half
is mistaken for the other.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from clinkz.engagement.schema_vocabulary import (
    collisions,
    declared_enum_values,
    declared_field_names,
)
from clinkz.engagement.secrets import (
    CredentialCollisionError,
    CredentialFileError,
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
# The refusal at intake
# ---------------------------------------------------------------------------


def test_the_four_character_case_is_refused_at_intake() -> None:
    """``medi`` would rewrite the enum VALUE ``medium`` and lose the deliverable.

    The 4-character floor is ``_MIN_REDACTABLE_LEN``, so this is the shortest
    credential the registry will accept at all — and it is enough. Nothing about
    it looks dangerous: it is not a field name, not an enum member, and it is
    exactly as long as the registry demands.
    """
    with pytest.raises(CredentialCollisionError) as raised:
        register_credential_set(_cred_set(FOUR_CHAR_COLLISION))

    message = str(raised.value)
    assert "SUBSTRING of a declared enum value" in message, (
        "the refusal must name the collision - but NOT the word, which would narrow "
        "the credential to that word's substrings"
    )
    assert "clinkz.models.finding.Severity" in message, "and where it is declared"
    assert "no report.json" in message, "and what registering it would cost"


def test_the_password_as_value_case_is_refused_at_intake() -> None:
    """A credential whose value is the word ``password`` deletes that field name.

    ``password`` is a declared field name, so one registration consumes the KEY
    end to end — which is the one case ``_redact_key`` still rewrites, correctly,
    because a key that is nothing but credential material is not schema. The
    consequence is that every recorded ``{"username": …, "password": …}`` body
    loses the field NAME, and a field name is schema by the same rule the IDOR
    oracle states about attribution.
    """
    with pytest.raises(CredentialCollisionError) as raised:
        register_credential_set(_cred_set(PASSWORD_AS_VALUE))

    message = str(raised.value)
    assert "EXACTLY a declared field name" in message, (
        "the refusal must name the collision - but not the word, which on THIS arm "
        "is the credential itself"
    )
    assert "clinkz.models.engagement.RoleCredential" in message


def test_the_refusal_names_the_change_that_resolves_it() -> None:
    """A refusal an operator cannot act on is an outage with better prose."""
    with pytest.raises(CredentialCollisionError) as raised:
        register_credential_set(_cred_set(FOUR_CHAR_COLLISION))
    message = str(raised.value)
    assert "The change that resolves it" in message
    assert "no flag to skip this" in message, (
        "the absence of an override is part of the contract — an override is the "
        "run that produces no report"
    )


def test_the_refusal_does_not_reprint_the_credential_it_refuses() -> None:
    """A refusal that quotes the credential is a plaintext password on stderr.

    Found by the security review of this change. The field-name predicate is
    EQUALITY, so the "colliding word" on that arm IS the operator's password,
    and the first version of the message rendered it — reopening by a different
    function exactly the window ``describe_credential_validation_error`` exists
    to close by construction.

    And stderr is not only a terminal. ``scripts/juiceshop_benchmark_run.py``
    and ``scripts/three_run_envelope.py`` capture a child ``clinkz scan``'s
    stderr into ``outputs/_juiceshop_benchmark/`` through
    ``write_redacted_text`` — and the PARENT process never calls
    ``register_credential_set``, so ``redact`` there has only the shape rules
    and a password has no shape. The disclosure gate detects through the same
    shape vocabulary, so it would have certified that companion region CLEAN
    over a file carrying the client's password.

    The property asserted is stronger than "the value is absent", because the
    value can be an ordinary English word the boilerplate itself contains: the
    message must be **independent of the credential**, so two different
    credentials colliding on the same vocabulary entry produce the same bytes.
    """

    def refusal(password: str) -> str:
        clear_secrets()
        with pytest.raises(CredentialCollisionError) as raised:
            register_credential_set(_cred_set(password))
        return str(raised.value)

    # Two different four-character credentials, both substrings of `medium`.
    assert refusal("medi") == refusal("ediu"), (
        "the refusal message varies with the credential, so it carries information "
        "about it — a reader of a captured log must learn nothing"
    )
    # And a credential that shares no word with the boilerplate is simply absent.
    assert "findings" not in refusal("findings")
    assert "hostnames" not in refusal("hostnames")


def test_the_enum_arm_does_not_narrow_the_credential_either() -> None:
    """Naming the enum word is the same disclosure one step weaker — sometimes not weaker.

    The enum predicate is containment, so printing ``'medium'`` narrows the
    credential to that word's substrings. For a four-character credential equal
    to a four-character enum value — ``high``, ``info``, ``bash`` — it discloses
    it exactly. So neither arm renders a word.
    """
    clear_secrets()
    with pytest.raises(CredentialCollisionError) as raised:
        register_credential_set(_cred_set("high"))
    message = str(raised.value)
    assert "'high'" not in message
    assert "SUBSTRING of a declared enum value" in message, (
        "what remains must still be actionable: which kind of collision, and where "
        "the colliding vocabulary is declared"
    )
    assert "clinkz.models.finding.Severity" in message


def test_a_refused_set_registers_nothing() -> None:
    """A refusal leaves the registry exactly as it found it.

    Otherwise a caller that catches the error continues with half a credential
    set armed, which is the redaction layer in a state no code path intends.
    """
    cred_set = CredentialSet(
        credentials=[
            RoleCredential(role="user", username="u@example.test", password="Sv3n-Passphrase"),
            RoleCredential(role="admin", username="a@example.test", password=FOUR_CHAR_COLLISION),
        ]
    )
    with pytest.raises(CredentialCollisionError):
        register_credential_set(cred_set)
    assert registered_secret_count() == 0, (
        "the first credential was registered before the second was refused — a "
        "partially armed registry is a state nothing else in the engine expects"
    )


def test_the_refusal_is_reachable_through_the_credential_file(tmp_path: Path) -> None:
    """Intake means the file loader, which is what the CLI calls.

    ``CredentialCollisionError`` subclasses ``CredentialFileError`` so the CLI's
    existing handler surfaces it as a setup error with exit code 2 — bad input,
    caught before the engagement opens, with nothing to retry.
    """
    path = tmp_path / "creds.json"
    path.write_text(
        json.dumps(
            {"credentials": [{"role": "admin", "username": "a@b.test", "password": "medi"}]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(CredentialFileError) as raised:
        load_credential_file(path)
    assert isinstance(raised.value, CredentialCollisionError)
    assert registered_secret_count() == 0


def test_an_ordinary_credential_is_accepted() -> None:
    """The refusal is narrow by construction, not a filter on password strength."""
    for password in ("admin123", "ncc-1701", "Sv3n-Passphrase", "P@ssw0rd", "hunter2"):
        clear_secrets()
        register_credential_set(_cred_set(password))
        assert is_registered(password), password


def test_a_credential_too_short_to_register_is_not_refused() -> None:
    """A value the registry declines cannot corrupt anything, so it collides with nothing.

    ``new`` is a declared enum value of ``FindingStatus`` and three characters
    long. Refusing it would be a refusal about a registration that never
    happens — a permanent false alarm, which invariant 77 is explicit about.
    """
    assert "new" in declared_enum_values()
    register_credential_set(_cred_set("new"))
    assert registered_secret_count() == 0, "three characters is below _MIN_REDACTABLE_LEN"


def test_the_catalogue_words_are_not_refused() -> None:
    """The boundary between the two halves, stated as a test.

    ``admin`` and ``root`` collide with no field name and no enum value in this
    tree — and they are exactly the words that rewrote an English-language
    target's prose 711,918 times. The intake refusal cannot help them and does
    not pretend to; ``provisional_secret`` is the half that does. If this test
    ever goes red because a model declared a field called ``admin``, the fix is
    the model's name, not this rule.
    """
    for word in ("admin", "root", "test"):
        assert collisions(word) == (), f"{word} now collides — see the docstring"
        clear_secrets()
        register_credential_set(_cred_set(word))
        assert is_registered(word)


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


def test_a_field_name_collides_on_equality_and_an_enum_value_on_containment() -> None:
    """The two predicates are different because the two mechanisms are.

    A key survives a registration that leaves residue — that is the key rule —
    so only an exact match consumes one. An enum VALUE is data and keeps
    substring redaction, so any substring of it is enough.
    """
    assert "findings" in declared_field_names()
    assert collisions("find") == (), (
        "a proper substring of a field name leaves residue, so the key survives — "
        "refusing it would be a refusal about a corruption that does not happen"
    )
    assert [c.kind for c in collisions("findings")] == ["field_name"]
    onfirme = collisions("onfirme")
    assert {c.kind for c in onfirme} == {"enum_value"}
    assert "confirmed" in {c.token for c in onfirme}, (
        "a substring of the enum value 'confirmed' rewrites it and the enum refuses "
        "the rewritten form"
    )


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
        "Only the organization's admin or owner can manage SSO settings",
    ]

    with provisional_secret("password"), provisional_secret("root"), provisional_secret("admin"):
        during = [redact(a) for a in artifacts]
    after = [redact(a) for a in artifacts]

    assert all("[REDACTED]" in a for a in during), (
        "an artifact written DURING the attempt must still be redacted — that is "
        "the whole of what the registration defends"
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
