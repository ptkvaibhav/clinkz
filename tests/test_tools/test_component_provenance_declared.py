"""Every component observation declares how its VERSION was obtained.

A guard whose domain is COMPUTED: it AST-walks ``src/`` for every construction
of :class:`~clinkz.models.recon.DetectedComponent` and fails on any that does
not pass ``provenance=``. A new fingerprinting wrapper — a lockfile reader, a
bundle-hash matcher, a fourth banner tool — goes red until it says which kind of
evidence it produced, without anybody editing a list inside this file.

That matters because the field decides which known-CVE matches claim the plan's
reserved slots. A producer that stays silent is not neutral: ``UNDECLARED``
ranks last, so silence costs its matches priority. The failure this prevents is
the opposite one — a producer that *should* have declared ``LOCKFILE`` and did
not, quietly demoting the strongest evidence in the run to the weakest.

The classification stays declared: this file asserts only that a declaration is
PRESENT. Whether ``nmap:service`` is a banner or something better is a judgement
the wrapper makes in its own docstring, because only the wrapper knows what it
read.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinkz.models.recon import DetectedComponent, VersionProvenance, version_provenance_rank

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "clinkz"


def _construction_sites() -> list[tuple[str, int, bool]]:
    """Every ``DetectedComponent(...)`` call under ``src/``, with a declared flag."""
    sites: list[tuple[str, int, bool]] = []
    for path in sorted(_SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover — a broken tree fails elsewhere, loudly
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name != "DetectedComponent":
                continue
            declared = any(kw.arg == "provenance" for kw in node.keywords)
            sites.append((str(path.relative_to(_SRC.parent.parent)), node.lineno, declared))
    return sites


def test_the_guard_has_a_domain_to_guard() -> None:
    """A walk that finds nothing passes vacuously — assert it found the producers."""
    sites = _construction_sites()
    assert len(sites) >= 3, (
        "the AST walk found fewer construction sites than the three fingerprinting "
        f"wrappers that are known to exist — the walk is broken, not the code: {sites}"
    )


def test_every_producer_declares_its_version_provenance() -> None:
    silent = [(path, line) for path, line, declared in _construction_sites() if not declared]
    assert not silent, (
        "these construct a DetectedComponent without declaring how its version was "
        "observed. Provenance is not inferable from the source string — a consumer "
        "parsing 'nmap:service' back out to guess the evidence kind is the "
        "getattr-with-a-default pattern that left three capabilities silently dead "
        f"here. Pass provenance= at the wrapper that knows what it read: {silent}"
    )


def test_undeclared_ranks_last_so_silence_is_never_promoted() -> None:
    """The same rule research grounding follows: an unstated claim is a weak one."""
    ranks = {p: version_provenance_rank(p.value) for p in VersionProvenance}
    assert ranks[VersionProvenance.UNDECLARED] == max(ranks.values())
    assert ranks[VersionProvenance.LOCKFILE] < ranks[VersionProvenance.BANNER]
    assert ranks[VersionProvenance.ARTIFACT_HASH] < ranks[VersionProvenance.BANNER]


@pytest.mark.parametrize("unknown", ["", "made-up", "LOCKFILE"])
def test_an_unrecognised_provenance_ranks_with_undeclared(unknown: str) -> None:
    """Read on the planning path — a new enum member nobody wired costs priority, never a crash."""
    assert version_provenance_rank(unknown) == version_provenance_rank(
        VersionProvenance.UNDECLARED.value
    )


def test_the_default_is_undeclared_not_a_guess() -> None:
    assert DetectedComponent(name="x").provenance is VersionProvenance.UNDECLARED
