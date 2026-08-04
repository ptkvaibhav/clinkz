"""The authorization gate, the window hard stop, and credential hygiene.

The hygiene test is the load-bearing one: it takes a supplied password through
every artifact writer an engagement produces and asserts the plaintext appears
in none of them.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from clinkz.engagement.gate import (
    AuthorizationRequiredError,
    EngagementWindowClosedError,
    open_engagement,
    require_authorization,
    require_window_open,
)
from clinkz.engagement.secrets import (
    REDACTION_PLACEHOLDER,
    CredentialFileError,
    clear_secrets,
    load_credential_file,
    redact,
    redact_structure,
    register_secret,
)
from clinkz.models.engagement import (
    AuthorizationRecord,
    CredentialSet,
    EngagementWindow,
    RoleCredential,
    SafetyPolicy,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.action_log import ActionLog
from tests.authorization_fixtures import TEST_AUTHORIZATION


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    """The registry is module-level; a leak between tests is a real bug."""
    clear_secrets()
    yield
    clear_secrets()


def _scope(**kwargs: object) -> EngagementScope:
    return EngagementScope(
        name="gate-test",
        targets=[ScopeEntry(value="app.test", type=ScopeType.DOMAIN)],
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def test_an_engagement_without_authorization_is_refused() -> None:
    with pytest.raises(AuthorizationRequiredError) as excinfo:
        require_authorization(_scope())
    message = str(excinfo.value)
    assert "--authorization" in message, "the refusal must say how to fix it"


def test_authorization_returns_the_record_when_present() -> None:
    scope = _scope(authorization=TEST_AUTHORIZATION)
    assert require_authorization(scope) is TEST_AUTHORIZATION


@pytest.mark.parametrize(
    "field",
    [
        "authorizing_party",
        "authorizing_role",
        "authorizing_contact",
        "authorization_reference",
        "emergency_contact",
    ],
)
def test_every_authorization_field_is_required(field: str) -> None:
    """There is no partially-populated shape of this model.

    A blank authorizing party has to fail at setup, not appear as an empty line
    in a client deliverable.
    """
    data = TEST_AUTHORIZATION.model_dump()
    data[field] = "   "
    with pytest.raises(ValueError):
        AuthorizationRecord.model_validate(data)


def test_an_empty_permitted_technique_list_is_rejected() -> None:
    data = TEST_AUTHORIZATION.model_dump()
    data["permitted_techniques"] = []
    with pytest.raises(ValueError):
        AuthorizationRecord.model_validate(data)


def test_permitted_techniques_match_by_family_and_spelling() -> None:
    record = TEST_AUTHORIZATION.model_copy(
        update={"permitted_techniques": ["SQL Injection", "xss"]}
    )
    assert record.permits("sql_injection")
    assert record.permits("xss_reflected"), "granting a family must cover its members"
    assert record.permits("xss_stored")
    assert not record.permits("command_injection")


def test_wildcard_must_be_written_down_not_implied() -> None:
    assert TEST_AUTHORIZATION.permits_all
    narrow = TEST_AUTHORIZATION.model_copy(update={"permitted_techniques": ["lfi"]})
    assert not narrow.permits_all


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


def test_no_window_is_permitted() -> None:
    require_window_open(None)


def test_a_closed_window_is_refused() -> None:
    now = datetime.now(UTC)
    window = EngagementWindow(start=now - timedelta(days=2), end=now - timedelta(days=1))
    with pytest.raises(EngagementWindowClosedError):
        require_window_open(window)


def test_a_window_that_has_not_opened_is_refused() -> None:
    now = datetime.now(UTC)
    window = EngagementWindow(start=now + timedelta(hours=1), end=now + timedelta(hours=2))
    with pytest.raises(EngagementWindowClosedError):
        require_window_open(window)


def test_an_end_before_start_is_rejected_at_construction() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError):
        EngagementWindow(start=now, end=now - timedelta(hours=1))


def test_a_naive_datetime_is_read_as_utc_not_local() -> None:
    """The hard stop must not depend on the machine the engagement runs on."""
    window = EngagementWindow(start=datetime(2026, 1, 1, 9, 0), end=datetime(2026, 1, 1, 17, 0))
    assert window.start.tzinfo is UTC
    assert window.end.tzinfo is UTC


def test_open_engagement_runs_both_refusals() -> None:
    now = datetime.now(UTC)
    scope = _scope(
        authorization=TEST_AUTHORIZATION,
        window=EngagementWindow(start=now - timedelta(hours=1), end=now + timedelta(hours=1)),
    )
    assert open_engagement(scope) is TEST_AUTHORIZATION


# ---------------------------------------------------------------------------
# Credential hygiene
# ---------------------------------------------------------------------------


def test_a_password_is_masked_by_model_dump() -> None:
    """The PRIMARY guarantee, and it is structural rather than disciplinary.

    Anything reachable from a model that gets dumped cannot carry the plaintext.
    """
    cred = RoleCredential(role="admin", username="a@b.test", password="s3cr3t-pa55word")
    dumped = json.dumps(cred.model_dump(mode="json"))
    assert "s3cr3t-pa55word" not in dumped
    assert cred.secret() == "s3cr3t-pa55word", "the plaintext must still be usable"


def test_credentials_are_not_reachable_from_the_persisted_scope() -> None:
    """The scope is model_dump()-ed into the state store; credentials are not on it."""
    scope = _scope(authorization=TEST_AUTHORIZATION)
    assert "password" not in json.dumps(scope.model_dump(mode="json")).lower()
    assert not hasattr(scope, "credentials")


def test_redaction_masks_a_registered_secret_everywhere(tmp_path: Path) -> None:
    register_secret("hunter2-correct-horse")
    assert redact("logging in with hunter2-correct-horse now") == (
        f"logging in with {REDACTION_PLACEHOLDER} now"
    )
    nested = {"a": ["hunter2-correct-horse"], "b": {"c": "x hunter2-correct-horse y"}}
    assert "hunter2-correct-horse" not in json.dumps(redact_structure(nested))


def test_a_longer_secret_is_masked_before_a_shorter_one_it_contains() -> None:
    register_secret("passw0rd")
    register_secret("passw0rd-extended")
    assert "passw0rd" not in redact("value=passw0rd-extended")


def test_a_too_short_secret_is_reported_as_unredactable() -> None:
    """Honest about the limitation instead of silently not redacting.

    Substring-replacing a two-character value would corrupt every artifact it
    appears in, so it is refused for redaction and the caller warns.
    """
    assert register_secret("ab") is False
    assert redact("ab") == "ab"
    assert register_secret("abcd") is True


def test_the_supplied_password_appears_in_no_artifact(tmp_path: Path) -> None:
    """End-to-end hygiene: a real password through every writer, found in none.

    Covers the three durable artifacts an engagement produces where a credential
    could plausibly land: the action log (request bodies), the scope that is
    persisted to the state store, and any serialized credential model.
    """
    password = "Tr0ub4dor&3-engagement"
    cred_set = CredentialSet(
        credentials=[
            RoleCredential(role="admin", username="admin@app.test", password=password),
            RoleCredential(role="anonymous"),
        ]
    )
    for secret in cred_set.secrets():
        register_secret(secret)

    # 1. The action log, including a login body that literally contains it.
    log = ActionLog("eng-hygiene", outputs_root=tmp_path)
    log.record_sent(
        method="POST",
        url=f"https://app.test/login?debug={password}",
        stage="auth",
        category="mutating_method",
        reason="login",
        body=f"username=admin%40app.test&password={password}",
    )
    log_text = (tmp_path / "eng-hygiene" / "actions.jsonl").read_text(encoding="utf-8")
    assert password not in log_text
    assert REDACTION_PLACEHOLDER in log_text

    # 2. The persisted scope.
    scope = _scope(authorization=TEST_AUTHORIZATION, safety=SafetyPolicy())
    assert password not in json.dumps(scope.model_dump(mode="json"))

    # 3. Any serialization of the credential set itself.
    assert password not in cred_set.model_dump_json()
    assert password not in json.dumps(cred_set.model_dump(mode="json"))


def test_a_git_tracked_credential_file_is_refused(tmp_path: Path, monkeypatch) -> None:
    """A credential file under version control is a leaked credential file.

    A hard error, not a warning that scrolls past.
    """
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(
        json.dumps({"credentials": [{"role": "admin", "username": "a", "password": "bbbb"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr("clinkz.engagement.secrets._is_git_tracked", lambda _p: True)
    with pytest.raises(CredentialFileError) as excinfo:
        load_credential_file(cred_file)
    assert "tracked by git" in str(excinfo.value)


def test_loading_a_credential_file_registers_its_secrets(tmp_path: Path, monkeypatch) -> None:
    cred_file = tmp_path / "creds.json"
    cred_file.write_text(
        json.dumps(
            {
                "credentials": [
                    {"role": "admin", "username": "a@b.test", "password": "loaded-secret-01"},
                    {"role": "user", "username": "u@b.test", "password": "loaded-secret-02"},
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("clinkz.engagement.secrets._is_git_tracked", lambda _p: False)
    monkeypatch.setattr("clinkz.engagement.secrets._is_inside_repo", lambda _p: False)

    cred_set = load_credential_file(cred_file)
    assert cred_set.roles == ["admin", "user"]
    assert cred_set.primary() is not None
    assert cred_set.primary().role == "admin"
    assert redact("loaded-secret-01 and loaded-secret-02") == (
        f"{REDACTION_PLACEHOLDER} and {REDACTION_PLACEHOLDER}"
    )


def test_anonymous_role_is_kept_but_not_counted_as_authenticating() -> None:
    cred_set = CredentialSet(
        credentials=[
            RoleCredential(role="anonymous"),
            RoleCredential(role="user", username="u", password="pppp"),
        ]
    )
    assert cred_set.roles == ["anonymous", "user"]
    assert [c.role for c in cred_set.authenticating] == ["user"]
    assert cred_set.primary().role == "user"
