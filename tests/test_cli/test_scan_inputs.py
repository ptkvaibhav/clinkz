"""The operator-facing input layer: what a flag means, and what it refuses.

Pure and offline. Every assertion here is about a decision made before any
engagement exists, which is exactly the set of decisions that used to be made
only by hand at a terminal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.engagement.cli_inputs import (
    AuthorizationFlags,
    ScanInputError,
    authorization_from_flags,
    classify_target,
    load_authorization_file,
    load_benchmark_profile,
    looks_like_scope_file,
    make_scope_entry,
    names_a_scope_document,
)
from clinkz.models.engagement import BENCHMARK_ACKNOWLEDGEMENT
from clinkz.models.scope import ScopeType
from tests.authorization_fixtures import TEST_AUTHORIZATION

# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://app.example.com", ScopeType.URL),
        ("http://app.example.com:8080/portal", ScopeType.URL),
        ("http://10.0.0.5:3000", ScopeType.URL),
        ("app.example.com", ScopeType.DOMAIN),
        ("localhost", ScopeType.DOMAIN),
        ("10.0.0.5", ScopeType.IP),
        ("::1", ScopeType.IP),
        ("10.10.10.0/24", ScopeType.CIDR),
        ("2001:db8::/32", ScopeType.CIDR),
    ],
)
def test_every_target_shape_classifies(value: str, expected: ScopeType) -> None:
    assert classify_target(value) is expected


def test_a_scheme_wins_over_the_address_underneath_it() -> None:
    """``http://10.0.0.1`` is a URL, not an IP.

    The port and path are part of what the operator named, and an entry typed as
    IP would drop them.
    """
    assert classify_target("http://10.0.0.1/admin") is ScopeType.URL
    assert classify_target("10.0.0.1") is ScopeType.IP


@pytest.mark.parametrize("value", ["", "   "])
def test_a_blank_target_is_refused(value: str) -> None:
    with pytest.raises(ScanInputError, match="cannot be blank"):
        classify_target(value)


def test_an_unsupported_scheme_is_refused_not_read_as_a_hostname() -> None:
    """``file:///etc/passwd`` must not become a hostname the engine then resolves."""
    with pytest.raises(ScanInputError, match="unsupported scheme"):
        classify_target("file:///etc/passwd")


def test_a_slash_bearing_value_that_is_not_a_network_is_refused() -> None:
    """A scheme-less path is a typo, and guessing at it would scan the wrong thing."""
    with pytest.raises(ScanInputError, match="CIDR"):
        classify_target("app.example.com/portal")


def test_scope_entry_carries_its_notes() -> None:
    entry = make_scope_entry("10.0.0.1", notes="production gateway")
    assert entry.value == "10.0.0.1"
    assert entry.type is ScopeType.IP
    assert entry.notes == "production gateway"


# ---------------------------------------------------------------------------
# Scope file vs inline entry
# ---------------------------------------------------------------------------


def test_an_existing_file_is_a_scope_file_and_a_hostname_is_not(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text("{}", encoding="utf-8")
    assert looks_like_scope_file(str(scope_file))
    assert not looks_like_scope_file("app.example.com")
    assert not looks_like_scope_file("https://app.example.com")


def test_a_json_name_is_read_as_a_document_whether_or_not_it_exists(tmp_path: Path) -> None:
    """The failure mode this prevents: a mistyped ``--scope scpoe.json`` classifies
    perfectly well as a HOSTNAME, and the engagement would go and scan it."""
    assert names_a_scope_document(str(tmp_path / "nope.json"))
    assert names_a_scope_document("configs/scope.json")
    assert names_a_scope_document("SCOPE.JSON")
    assert not names_a_scope_document("app.example.com")


def test_a_cidr_block_is_not_mistaken_for_a_missing_scope_file() -> None:
    """A CIDR contains '/', and a path-shaped heuristic here would refuse the
    single most ordinary way to name a network range."""
    assert not names_a_scope_document("10.10.10.0/24")

    from clinkz.cli import _assemble_scope

    scope = _assemble_scope(target="app.example.com", scope=["10.10.10.0/24"], exclude=[])
    assert [e.type for e in scope.targets] == [ScopeType.DOMAIN, ScopeType.CIDR]


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def _complete_flags(**overrides: object) -> AuthorizationFlags:
    base = {
        "party": "Dana Okafor",
        "role": "CTO",
        "contact": "dana@example.test",
        "reference": "SOW-2026-114",
        "techniques": ("*",),
        "emergency": "+1-555-0101",
    }
    base.update(overrides)
    return AuthorizationFlags(**base)  # type: ignore[arg-type]


def test_complete_flags_build_a_record() -> None:
    record = authorization_from_flags(_complete_flags())
    assert record.authorizing_party == "Dana Okafor"
    assert record.permits_all


def test_no_flags_at_all_is_not_the_same_as_partial_flags() -> None:
    assert not AuthorizationFlags().any_supplied()
    assert _complete_flags(role="", contact="").any_supplied()


def test_a_partial_record_names_every_missing_flag_at_once() -> None:
    """Discovering six missing fields one run at a time is the same refusal six
    times. The message names all of them."""
    with pytest.raises(ScanInputError) as exc:
        authorization_from_flags(AuthorizationFlags(party="Dana Okafor"))
    message = str(exc.value)
    for flag in (
        "--auth-role",
        "--auth-contact",
        "--auth-ref",
        "--auth-technique",
        "--auth-emergency",
    ):
        assert flag in message, f"{flag} was not named"
    assert "--auth-party" not in message, "a supplied field was reported missing"


def test_blank_and_whitespace_only_flags_count_as_missing() -> None:
    with pytest.raises(ScanInputError, match="--auth-role"):
        authorization_from_flags(_complete_flags(role="   "))


def test_an_empty_technique_list_is_missing_not_empty() -> None:
    with pytest.raises(ScanInputError, match="--auth-technique"):
        authorization_from_flags(_complete_flags(techniques=()))


def test_authorization_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(TEST_AUTHORIZATION.model_dump(mode="json")), encoding="utf-8")
    assert load_authorization_file(path).authorizing_party == "Test Authorizer"


def test_a_missing_authorization_file_is_named(tmp_path: Path) -> None:
    with pytest.raises(ScanInputError, match="not found"):
        load_authorization_file(tmp_path / "nope.json")


def test_an_incomplete_authorization_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"authorizing_party": "Someone"}), encoding="utf-8")
    with pytest.raises(ScanInputError, match="Invalid authorization record"):
        load_authorization_file(path)


# ---------------------------------------------------------------------------
# Benchmark profile
# ---------------------------------------------------------------------------


def test_a_complete_benchmark_profile_loads(tmp_path: Path) -> None:
    path = tmp_path / "bench.json"
    path.write_text(
        json.dumps(
            {
                "target_is_throwaway": True,
                "acknowledgement": BENCHMARK_ACKNOWLEDGEMENT,
                "permitted_categories": ["deletion"],
                "declared_by": "Test Operator",
                "declared_reference": "LAB-1",
            }
        ),
        encoding="utf-8",
    )
    profile = load_benchmark_profile(path)
    assert profile.permits_category("deletion")


def test_a_benchmark_profile_without_the_verbatim_attestation_is_refused(tmp_path: Path) -> None:
    """The attestation is the opt-in. A near-miss is not an opt-in."""
    path = tmp_path / "bench.json"
    path.write_text(
        json.dumps(
            {
                "target_is_throwaway": True,
                "acknowledgement": "this is a test box, go ahead",
                "permitted_categories": ["deletion"],
                "declared_by": "Test Operator",
                "declared_reference": "LAB-1",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScanInputError, match="verbatim"):
        load_benchmark_profile(path)


def test_a_benchmark_profile_cannot_permit_an_engagement_damaging_category(
    tmp_path: Path,
) -> None:
    """Session destruction and security-posture toggles damage the ENGAGEMENT,
    so no declaration makes them permissible."""
    path = tmp_path / "bench.json"
    path.write_text(
        json.dumps(
            {
                "target_is_throwaway": True,
                "acknowledgement": BENCHMARK_ACKNOWLEDGEMENT,
                "permitted_categories": ["session_destruction"],
                "declared_by": "Test Operator",
                "declared_reference": "LAB-1",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScanInputError, match="never be permitted"):
        load_benchmark_profile(path)
