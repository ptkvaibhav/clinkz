"""Keyless gate — the version comparator's PROPERTIES, over generated pairs.

A hand-written table of cases is the guard-domain law waiting to happen: it
asserts the comparator over exactly the inputs its author thought of, and the
inputs an author forgets are the ones that break it. Worse, the failure this
comparator can produce is a **silent under-match** — a predicate that misses the
affected version by one release emits nothing, and nothing is what a correct run
against a patched target also emits. No control arm in this engine can see that.

So the order and the interval boundaries are pinned as properties over a
generated universe of versions, not as examples:

* **total order** — reflexive, antisymmetric, transitive, total, and consistent
  with the equality the comparator itself reports;
* **boundary side** — for each of the four bracket forms, the two bound values
  fall on the side the bracket declares;
* **half-open partition** — ``[a,c) == [a,b) ⊎ [b,c)`` over unqualified
  versions, which is the property a decrement-by-one upper bound breaks;
* **the declared prerelease widenings**, including the one place they cost the
  partition, asserted rather than left to be discovered.

The generator is a deterministic cross product plus a seeded random batch rather
than ``hypothesis``: this suite's whole point is that CI and a developer machine
run the same thing, the repo pins its full dependency set for that reason, and a
shrinking search adds a dependency to buy randomness this file does not want.
The seed is fixed and printed into the failure message, so a failure names the
exact pair that produced it.
"""

from __future__ import annotations

import itertools
import random

import pytest

from clinkz.discovery.versions import (
    SemVer,
    compare_versions,
    parse_semver,
    version_satisfies,
)

# --- the generated universe -------------------------------------------------

_SEED = 20260830

#: Release cores. Includes the catalogue's real boundaries (the Apache pair, the
#: Log4Shell fix, the jQuery range) and a ``.95`` patch — the shape that a
#: hand-decremented upper bound silently excludes.
_CORES: tuple[tuple[int, int, int], ...] = (
    (0, 0, 0),
    (0, 0, 1),
    (0, 1, 0),
    (1, 0, 0),
    (1, 2, 0),
    (1, 2, 3),
    (1, 2, 4),
    (1, 2, 95),
    (1, 3, 0),
    (2, 0, 0),
    (2, 4, 49),
    (2, 4, 50),
    (2, 15, 0),
    (3, 4, 1),
    (3, 4, 95),
    (3, 5, 0),
)

#: Qualifier spellings this engine actually observes: SemVer prereleases, the
#: Maven-style classifier, a Debian/Ubuntu revision, build metadata, and the
#: ``-0`` lower-bound idiom advisory feeds use.
_QUALIFIERS: tuple[str, ...] = (
    "",
    "-0",
    "-1",
    "-2",
    "-alpha",
    "-alpha.1",
    "-alpha.beta",
    "-beta.2",
    "-beta.11",
    "-rc1",
    "-rc.1",
    "-jre",
    "-1ubuntu3.2",
    "+build.5",
    "-rc1+build.5",
)


def _spell(core: tuple[int, int, int], qualifier: str = "") -> str:
    return f"{core[0]}.{core[1]}.{core[2]}{qualifier}"


#: Every core × every qualifier. 240 versions ⇒ 57,600 ordered pairs.
UNIVERSE: tuple[str, ...] = tuple(
    _spell(core, qualifier) for core in _CORES for qualifier in _QUALIFIERS
)

#: The unqualified slice — the universe the half-open partition is total over.
RELEASES: tuple[str, ...] = tuple(_spell(core) for core in _CORES)


def _parsed(raw: str) -> SemVer:
    parsed = parse_semver(raw)
    assert parsed is not None, f"generator produced an unparseable version: {raw!r}"
    return parsed


PARSED_UNIVERSE: tuple[tuple[str, SemVer], ...] = tuple((raw, _parsed(raw)) for raw in UNIVERSE)


def _random_versions(count: int) -> list[str]:
    """A seeded batch beyond the fixed grid, so the grid is not the whole test."""
    rng = random.Random(_SEED)
    out: list[str] = []
    for _ in range(count):
        core = (rng.randrange(0, 4), rng.randrange(0, 20), rng.randrange(0, 120))
        qualifier = rng.choice(_QUALIFIERS)
        out.append(_spell(core, qualifier))
    return out


# --- the order --------------------------------------------------------------


def test_the_universe_is_what_the_properties_run_over() -> None:
    """A generator that silently shrank would make every property below vacuous."""
    assert len(UNIVERSE) == len(_CORES) * len(_QUALIFIERS) == 240
    assert len(set(UNIVERSE)) == len(UNIVERSE), "generated versions must be distinct spellings"


def test_comparator_is_reflexive() -> None:
    for raw, parsed in PARSED_UNIVERSE:
        assert compare_versions(parsed, parsed) == 0, raw


def test_comparator_is_total_and_antisymmetric() -> None:
    """Exactly one of <, ==, > holds for every ordered pair, both ways round."""
    for (a_raw, a), (b_raw, b) in itertools.product(PARSED_UNIVERSE, repeat=2):
        forward = compare_versions(a, b)
        backward = compare_versions(b, a)
        assert forward in (-1, 0, 1), (a_raw, b_raw, forward)
        assert forward == -backward, (
            f"antisymmetry broken: cmp({a_raw!r},{b_raw!r})={forward} but "
            f"cmp({b_raw!r},{a_raw!r})={backward}"
        )


def test_comparator_is_transitive() -> None:
    """Sampled triples — the full cross product is 13.8M and buys nothing extra."""
    rng = random.Random(_SEED)
    for _ in range(40_000):
        (a_raw, a), (b_raw, b), (c_raw, c) = (
            rng.choice(PARSED_UNIVERSE),
            rng.choice(PARSED_UNIVERSE),
            rng.choice(PARSED_UNIVERSE),
        )
        if compare_versions(a, b) <= 0 and compare_versions(b, c) <= 0:
            assert compare_versions(a, c) <= 0, (
                f"transitivity broken (seed {_SEED}): {a_raw!r} <= {b_raw!r} <= {c_raw!r} "
                f"but cmp({a_raw!r},{c_raw!r})={compare_versions(a, c)}"
            )


def test_equal_versions_are_substitutable_in_every_predicate() -> None:
    """``cmp(a,b) == 0`` must mean the two spellings answer every predicate alike.

    This is what makes build metadata's §10 exclusion real rather than declared:
    ``1.2.3+build.5`` and ``1.2.3`` compare equal, so no predicate may separate
    them.
    """
    predicates = ("=1.2.3", "<1.2.3", "<=1.2.3", ">1.2.3", ">=1.2.3", "[1.2.3,2.0.0)", "*")
    for (a_raw, a), (b_raw, b) in itertools.product(PARSED_UNIVERSE, repeat=2):
        if compare_versions(a, b) != 0:
            continue
        for predicate in predicates:
            assert version_satisfies(a_raw, predicate) == version_satisfies(b_raw, predicate), (
                f"{a_raw!r} and {b_raw!r} compare equal but disagree on {predicate!r}"
            )


def test_the_seeded_batch_obeys_the_order_too() -> None:
    """The fixed grid is not the whole test."""
    batch = [(raw, _parsed(raw)) for raw in _random_versions(400)]
    for (a_raw, a), (b_raw, b) in itertools.product(batch, repeat=2):
        assert compare_versions(a, b) == -compare_versions(b, a), (a_raw, b_raw)


# --- prerelease precedence, as declared -------------------------------------


def test_a_prerelease_ranks_below_its_own_release() -> None:
    for core in _CORES:
        release = _parsed(_spell(core))
        for qualifier in _QUALIFIERS:
            if not qualifier or qualifier.startswith("+"):
                continue
            assert compare_versions(_parsed(_spell(core, qualifier)), release) < 0, (
                f"{_spell(core, qualifier)} must rank below {_spell(core)}"
            )


def test_lowest_prerelease_is_the_floor_of_its_core() -> None:
    """``X-0`` is the minimum of ``{X} ∪ {X-anything}`` — what the lower-bound
    normalisation rests on."""
    for core in _CORES:
        floor = _parsed(_spell(core, "-0"))
        for qualifier in _QUALIFIERS:
            assert compare_versions(floor, _parsed(_spell(core, qualifier))) <= 0, (
                f"{_spell(core, '-0')} is not the floor of {_spell(core, qualifier)}"
            )


def test_prerelease_identifiers_follow_semver_precedence() -> None:
    """SemVer §11's own worked example, in order."""
    ladder = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    for lower, higher in zip(ladder, ladder[1:], strict=False):
        assert compare_versions(_parsed(lower), _parsed(higher)) < 0, f"{lower} !< {higher}"


def test_build_metadata_is_ignored_for_precedence() -> None:
    for core in _CORES:
        assert compare_versions(_parsed(_spell(core, "+build.5")), _parsed(_spell(core))) == 0
        assert (
            compare_versions(_parsed(_spell(core, "-rc1+build.5")), _parsed(_spell(core, "-rc1")))
            == 0
        )


# --- interval boundaries ----------------------------------------------------

_BRACKETS = (("[", "]"), ("[", ")"), ("(", "]"), ("(", ")"))


def _ordered_release_pairs() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for low_core, high_core in itertools.product(_CORES, repeat=2):
        if low_core < high_core:
            pairs.append((_spell(low_core), _spell(high_core)))
    return pairs


@pytest.mark.parametrize(("opener", "closer"), _BRACKETS)
def test_bound_values_fall_on_the_side_the_bracket_declares(opener: str, closer: str) -> None:
    """The boundary property, over every ordered pair the grid produces."""
    for low, high in _ordered_release_pairs():
        predicate = f"{opener}{low},{high}{closer}"
        assert version_satisfies(low, predicate) is (opener == "["), (
            f"lower bound {low!r} on the wrong side of {predicate!r}"
        )
        assert version_satisfies(high, predicate) is (closer == "]"), (
            f"upper bound {high!r} on the wrong side of {predicate!r}"
        )


def test_an_inclusive_lower_bound_admits_every_qualified_spelling_of_its_core() -> None:
    """The declared widening: a repackaging or RC of the introduced version is in.

    This is the rule that keeps ``2.4.49-1ubuntu3.2`` — a distribution build of
    a vulnerable Apache — inside ``[2.4.49,2.4.50)``. Strict SemVer §11 would
    drop it, which is a silent miss on the commonest real-world spelling.
    """
    for low_core, high_core in itertools.product(_CORES, repeat=2):
        if low_core >= high_core:
            continue
        predicate = f"{_spell(low_core)},{_spell(high_core)}"
        for qualifier in _QUALIFIERS:
            observed = _spell(low_core, qualifier)
            assert version_satisfies(observed, f"[{predicate})"), (
                f"{observed!r} must be inside [{predicate})"
            )
            assert version_satisfies(observed, f">={_spell(low_core)}"), (
                f"{observed!r} must satisfy >={_spell(low_core)} — the same bound"
            )


def test_an_open_lower_bound_is_the_escape_hatch_and_excludes_them() -> None:
    """``(X`` means strictly after every prerelease of X — the stated opt-out."""
    for low_core, high_core in itertools.product(_CORES, repeat=2):
        if low_core >= high_core:
            continue
        low, high = _spell(low_core), _spell(high_core)
        for qualifier in _QUALIFIERS:
            if qualifier in ("", "+build.5"):
                continue  # these compare EQUAL to the release, not below it
            observed = _spell(low_core, qualifier)
            assert not version_satisfies(observed, f"({low},{high})"), (
                f"{observed!r} must be outside ({low},{high})"
            )
            assert not version_satisfies(observed, f">{low}")


def test_a_prerelease_of_the_upper_bound_is_still_inside_a_half_open_range() -> None:
    """An RC of the fixed version is treated as still affected — over-match, by
    decision: the RC may or may not carry the fix, and a wrong dispatch is
    refused by an oracle while a wrong miss is silence."""
    for low_core, high_core in itertools.product(_CORES, repeat=2):
        if low_core >= high_core:
            continue
        low, high = _spell(low_core), _spell(high_core)
        assert version_satisfies(_spell(high_core, "-rc1"), f"[{low},{high})")
        assert version_satisfies(_spell(high_core, "-rc1"), f"<{high}")


# --- the half-open partition ------------------------------------------------


def test_adjacent_half_open_ranges_partition_the_releases() -> None:
    """``[a,c) == [a,b) ⊎ [b,c)`` — disjoint and covering, over releases.

    The property a decrement-by-one upper bound breaks: write ``[a,b]`` with a
    guessed ``b`` and the union stops covering, which is a version nobody tests
    and nobody hears about.
    """
    for a_core, b_core, c_core in itertools.combinations(_CORES, 3):
        a, b, c = _spell(a_core), _spell(b_core), _spell(c_core)
        for observed in RELEASES:
            whole = version_satisfies(observed, f"[{a},{c})")
            left = version_satisfies(observed, f"[{a},{b})")
            right = version_satisfies(observed, f"[{b},{c})")
            assert not (left and right), (
                f"{observed!r} is in both [{a},{b}) and [{b},{c}) — not a partition"
            )
            assert whole == (left or right), (
                f"{observed!r}: [{a},{c}) says {whole} but the halves say {left or right}"
            )


def test_the_partition_overlaps_only_on_prereleases_of_the_shared_boundary() -> None:
    """The one cost of the lower-bound normalisation, pinned rather than hidden.

    ``2.15.0-rc1`` is inside both ``[2.0,2.15.0)`` and ``[2.15.0,2.16.0)``. Both
    halves of that overlap are the over-matching direction, which is the trade
    this comparator makes everywhere; asserting it here means a future change
    that removes it has to say so.
    """
    assert version_satisfies("2.15.0-rc1", "[2.0.0,2.15.0)")
    assert version_satisfies("2.15.0-rc1", "[2.15.0,2.16.0)")
    # ... and a release is never in both.
    assert version_satisfies("2.15.0", "[2.15.0,2.16.0)")
    assert not version_satisfies("2.15.0", "[2.0.0,2.15.0)")


def test_a_high_patch_number_below_the_fix_is_inside_the_range() -> None:
    """The jQuery artifact, as a property rather than a regression note.

    ``[1.2.0,3.4.9]`` — a hand-guessed "last vulnerable version" — excludes
    ``3.4.95``. The half-open form derived from the advisory's own fixed version
    does not, and cannot, because it never names a last-vulnerable release.
    """
    for patch in (2, 9, 10, 95, 999):
        assert version_satisfies(f"3.4.{patch}", "[1.2.0,3.5.0)"), patch
    assert not version_satisfies("3.5.0", "[1.2.0,3.5.0)")


# --- refusal still refuses --------------------------------------------------


@pytest.mark.parametrize(
    "predicate",
    [
        "[1.0.0]",  # no comma
        "[1.0.0,2.0.0",  # unterminated
        "1.0.0,2.0.0)",  # no opener
        "[notaversion,2.0.0)",
        "[1.0.0,notaversion)",
        "<>1.0.0",
        "=notaversion",
    ],
)
def test_a_malformed_predicate_is_rejected_never_widened(predicate: str) -> None:
    """A predicate we cannot read must match nothing, not everything."""
    for observed in RELEASES:
        assert not version_satisfies(observed, predicate), (observed, predicate)


def test_an_unparseable_observed_version_satisfies_only_the_wildcard() -> None:
    for observed in ("", "unknown", "v1.2.3", "x.y.z"):
        assert version_satisfies(observed, "*")
        for predicate in ("=1.2.3", "<1.2.3", ">=1.2.3", "[1.0.0,2.0.0)", "(1.0.0,2.0.0]"):
            assert not version_satisfies(observed, predicate), (observed, predicate)
