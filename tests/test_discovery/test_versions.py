"""Keyless gate — the Layer-2 version-predicate matcher (design §2.4).

Deterministic grammar ``'<X' | '<=X' | '=X' | '[X,Y]' | '*'`` (plus ``'>X'`` /
``'>=X'``). A recall fires only when the observed version satisfies the fact's
predicate; conservative by construction so a wrong/absent version never widens a
bounded predicate (recall only ranks, never emits — §5).
"""

from __future__ import annotations

import pytest

from clinkz.discovery.versions import parse_version, version_satisfies


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
