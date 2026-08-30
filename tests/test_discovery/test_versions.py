"""Keyless gate — the version-predicate matcher, by example.

Deterministic grammar ``'*' | '=X' | '<X' | '<=X' | '>X' | '>=X' | '[X,Y)'``
(and the three other bracket combinations). Two consumers: Layer-2 capability
recall, which only ranks and never emits, and the published-CVE catalogue, whose
affected ranges decide what gets tested.

This file is the worked examples — the named cases a reader comes here to check.
The comparator's *properties* (total order, boundary side, the half-open
partition) are pinned over a generated universe in
``test_version_range_properties.py``, because a table of cases only ever asserts
the inputs its author thought of and an under-matching predicate fails silently.
"""

from __future__ import annotations

import pytest

from clinkz.discovery.versions import (
    compare_versions,
    parse_semver,
    parse_version,
    version_satisfies,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2.14.1", (2, 14, 1)),
        ("8.11", (8, 11, 0)),
        ("3", (3, 0, 0)),
        ("2.14.1-jre", (2, 14, 1)),  # build/qualifier suffix tolerated
        ("", None),
        ("dev", None),
        ("x.y.z", None),
    ],
)
def test_parse_version(raw: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(raw) == expected


def test_wildcard_matches_anything() -> None:
    assert version_satisfies("2.14.1", "*")
    assert version_satisfies("", "*")  # unobservable version still matches the widest
    assert version_satisfies("garbage", "*")


def test_exact_predicate() -> None:
    assert version_satisfies("2.14.1", "=2.14.1")
    assert version_satisfies("2.14.1", "2.14.1")  # bare X == '=X'
    assert not version_satisfies("2.14.0", "=2.14.1")
    assert not version_satisfies("2.15.0", "=2.14.1")


def test_less_than_predicates() -> None:
    assert version_satisfies("2.14.1", "<2.15.0")  # the Log4Shell vulnerable range
    assert version_satisfies("2.14.1", "<=2.14.1")
    assert not version_satisfies("2.15.0", "<2.15.0")
    assert not version_satisfies("2.16.0", "<=2.15.0")


def test_greater_than_predicates() -> None:
    assert version_satisfies("2.16.0", ">2.15.0")
    assert version_satisfies("2.15.0", ">=2.15.0")
    assert not version_satisfies("2.14.1", ">2.15.0")


def test_range_predicate() -> None:
    assert version_satisfies("2.19.1", "[2.19.0,2.19.1]")
    assert version_satisfies("2.19.0", "[2.19.0,2.19.1]")
    assert not version_satisfies("2.18.0", "[2.19.0,2.19.1]")
    assert not version_satisfies("2.20.0", "[2.19.0,2.19.1]")
    assert not version_satisfies("2.19.0", "[2.19.0]")  # malformed range → rejected


def test_unparseable_observed_fails_bounded_predicate() -> None:
    """An observed version we cannot parse satisfies only ``'*'`` (stays conservative)."""
    assert not version_satisfies("", "=2.14.1")
    assert not version_satisfies("unknown", "<2.15.0")
    assert not version_satisfies("", "[1.0.0,2.0.0]")


def test_malformed_predicate_rejected_not_widened() -> None:
    """A malformed predicate is rejected, not silently treated as the widest."""
    assert not version_satisfies("2.14.1", "<>2.14")
    assert not version_satisfies("2.14.1", "=notaversion")


# ---------------------------------------------------------------------------
# Half-open intervals — the primitive
# ---------------------------------------------------------------------------


def test_half_open_interval_excludes_the_fixed_version() -> None:
    """``[introduced, fixed)`` — the form every advisory feed states."""
    assert version_satisfies("2.0.0", "[2.0,2.15.0)")
    assert version_satisfies("2.14.1", "[2.0,2.15.0)")
    assert not version_satisfies("2.15.0", "[2.0,2.15.0)")  # the fix
    assert not version_satisfies("1.9.9", "[2.0,2.15.0)")


def test_all_four_bracket_combinations_are_read() -> None:
    assert version_satisfies("1.0.0", "[1.0.0,2.0.0]")
    assert version_satisfies("2.0.0", "[1.0.0,2.0.0]")
    assert version_satisfies("1.0.0", "[1.0.0,2.0.0)")
    assert not version_satisfies("2.0.0", "[1.0.0,2.0.0)")
    assert not version_satisfies("1.0.0", "(1.0.0,2.0.0]")
    assert version_satisfies("2.0.0", "(1.0.0,2.0.0]")
    assert not version_satisfies("1.0.0", "(1.0.0,2.0.0)")
    assert not version_satisfies("2.0.0", "(1.0.0,2.0.0)")


def test_the_single_point_entries_survive_the_move_to_the_new_form() -> None:
    """The catalogue's ``=2.4.49`` / ``=2.4.50`` in half-open form, unchanged.

    The requirement that made this rewrite safe: expressing a single affected
    release as ``[X,X.next)`` must match exactly what ``=X`` matched. 2.4.49 hits
    and 2.4.67 — the version the whatweb fingerprint actually reports on the
    live test target — still misses.
    """
    for predicate in ("=2.4.49", "[2.4.49,2.4.50)"):
        assert version_satisfies("2.4.49", predicate), predicate
        assert not version_satisfies("2.4.67", predicate), predicate
        assert not version_satisfies("2.4.48", predicate), predicate
        assert not version_satisfies("2.4.50", predicate), predicate
    for predicate in ("=2.4.50", "[2.4.50,2.4.51)"):
        assert version_satisfies("2.4.50", predicate), predicate
        assert not version_satisfies("2.4.49", predicate), predicate
        assert not version_satisfies("2.4.67", predicate), predicate


def test_the_half_open_form_adds_the_qualified_spellings_the_exact_form_missed() -> None:
    """The only difference between the two forms, and it is a recall GAIN.

    ``=2.4.49`` is exact, so a distribution build of a vulnerable Apache —
    which is how the majority of real hosts spell it — did not match. The
    half-open form does, which is the whole reason the catalogue moved.
    """
    assert not version_satisfies("2.4.49-1ubuntu3.2", "=2.4.49")
    assert version_satisfies("2.4.49-1ubuntu3.2", "[2.4.49,2.4.50)")
    assert version_satisfies("2.4.49-rc1", "[2.4.49,2.4.50)")


def test_an_open_lower_bound_is_the_way_to_exclude_prereleases() -> None:
    """The escape hatch lives in the grammar, not in a per-entry convention."""
    assert not version_satisfies("2.4.49-rc1", "(2.4.49,2.4.51)")
    assert version_satisfies("2.4.50", "(2.4.49,2.4.51)")


# ---------------------------------------------------------------------------
# Prerelease and build metadata — stated, not tolerated by accident
# ---------------------------------------------------------------------------


def test_prerelease_and_build_are_parsed_not_discarded() -> None:
    parsed = parse_semver("1.2.3-rc1+build.5")
    assert parsed is not None
    assert parsed.core == (1, 2, 3)
    assert parsed.prerelease == ("rc1",)
    assert parsed.build == "build.5"


def test_a_prerelease_ranks_below_its_release() -> None:
    assert compare_versions(parse_semver("1.2.3-rc1"), parse_semver("1.2.3")) < 0
    assert version_satisfies("1.2.3-rc1", "<1.2.3")
    assert not version_satisfies("1.2.3-rc1", "=1.2.3")


def test_build_metadata_never_changes_an_answer() -> None:
    """SemVer §10: build metadata is ignored for precedence."""
    assert compare_versions(parse_semver("1.2.3+build.5"), parse_semver("1.2.3")) == 0
    assert version_satisfies("1.2.3+build.5", "=1.2.3")
    assert not version_satisfies("1.2.3+build.5", "[1.0.0,1.2.3)")


def test_an_inclusive_lower_bound_and_its_inequality_spelling_agree() -> None:
    """``[X`` and ``>=X`` are the same bound and must normalise identically."""
    for observed in ("2.4.49", "2.4.49-rc1", "2.4.49-1ubuntu3.2"):
        assert version_satisfies(observed, ">=2.4.49"), observed
        assert version_satisfies(observed, "[2.4.49,9.9.9)"), observed
    assert not version_satisfies("2.4.49-rc1", ">2.4.49")


def test_parse_version_is_a_view_of_the_same_parse() -> None:
    """One parser, two views — so a range compare and a threshold gate agree."""
    for raw in ("2.14.1", "8.11", "3", "2.14.1-jre", "2.4.49-1ubuntu3.2", "1.2.3+build.5"):
        parsed = parse_semver(raw)
        assert parsed is not None
        assert parse_version(raw) == parsed.core, raw
    for raw in ("", "dev", "x.y.z", "v1.2.3"):
        assert parse_version(raw) is None and parse_semver(raw) is None, raw


def test_trailing_numeric_segments_are_dropped_as_before() -> None:
    """A stated tolerance, unchanged: ``2.4.49.1`` compares equal to ``2.4.49``."""
    assert parse_version("2.4.49.1") == (2, 4, 49)
    assert compare_versions(parse_semver("2.4.49.1"), parse_semver("2.4.49")) == 0
    assert version_satisfies("2.4.49.1", "[2.4.49,2.4.50)")
