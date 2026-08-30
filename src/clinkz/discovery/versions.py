"""Version predicate grammar — the comparator every affected-range claim rests on.

A deterministic, **LLM-free** matcher over the predicate grammar used by both
Layer-2 capability recall (:class:`~clinkz.discovery.models.CapabilityFact`) and
the published-CVE catalogue (:mod:`clinkz.knowledge.component_cves`)::

    '*'  |  '=X'  |  '<X'  |  '<=X'  |  '>X'  |  '>=X'
         |  '[X,Y)'  |  '[X,Y]'  |  '(X,Y)'  |  '(X,Y]'

**The half-open interval is the primitive, and it is not a convenience.**
``[introduced, fixed)`` is how every real advisory feed (NVD, OSV, GHSA, the npm
audit database) expresses affectedness, because it is the only form an advisory
author can write from what the advisory actually states: the version the fix
LANDED in. Any other form requires knowing the last version released before the
fix — a fact the advisory does not carry — and getting it wrong produces a
predicate that under-matches by one release.

That failure is invisible by construction, and it is the reason this module was
rewritten before the catalogue was allowed to grow. A predicate that
over-matches produces a lead or a dispatch, and a dispatch runs an oracle that
refuses: a wrong answer that announces itself. A predicate that under-matches
produces **silence**, and silence is what a correct run against a clean target
also looks like. This engine's entire evidence standard — every control arm,
every never-sent decoy — is built to catch a claim that should not have been
made. None of it can catch a claim that was never made. So where the two
directions are in tension, this module resolves toward the visible error, and
says at each site that it did.

The catalogue's own history has the artifact in it: ``jQuery`` CVE-2020-11022
(advisory: ``>= 1.2, < 3.5.0``) was written ``[1.2.0,3.4.9]`` — a hand-guessed
"last vulnerable version" that silently excludes ``3.4.95``. No such jQuery was
released, so nothing broke; the form was wrong the whole time, and the next
entry written that way would land on a version that does exist.

Prerelease and build metadata
-----------------------------
Handled explicitly (Semantic Versioning 2.0.0 §9–§11), not tolerated by
accident:

* **Build metadata** (``1.2.3+build.5``) is parsed and **ignored for
  precedence**, per §10. ``1.2.3+build.5`` and ``1.2.3`` are the same version.
* **A prerelease ranks below its own release** (§11): ``1.2.3-rc1 < 1.2.3``.
  Identifiers are compared dot-segment-wise, numeric segments numerically and
  below alphanumeric ones, a shorter prefix-equal list below a longer one.

  This is the direction that matters for an upper bound: ``1.2.3-rc1`` is inside
  ``[1.0.0,1.2.3)``, i.e. a release candidate of the fixed version is treated as
  still affected. That is deliberate over-match — the RC may or may not carry
  the fix, and a dispatch that is wrong gets refused by an oracle while a miss
  gets nothing.
* **An inclusive lower bound written without a prerelease admits every
  prerelease and repackaging of its core.** ``[2.4.49,2.4.50)`` contains
  ``2.4.49``, ``2.4.49-rc1`` and the distribution build ``2.4.49-1ubuntu3.2``.

  Strict §11 would exclude all three qualified spellings, and that is exactly
  the silent under-match this module exists to prevent: most versions this
  engine observes come from distribution packages, whose ``-1ubuntu3.2`` and
  ``-2+deb11u1`` revisions are *repackagings of the same upstream release*, not
  prereleases of it. Advisory feeds close this with the ``X-0`` idiom (``-0`` is
  the lowest possible prerelease); writing it per entry is a convention an
  author must remember, and a rule a human has to remember is the guard-domain
  law waiting to happen. So the **primitive** normalises its own inclusive lower
  bound to ``X-0``, and an entry that genuinely means "strictly after every
  prerelease of X" writes the **open** bound ``(X,Y)`` — the escape hatch is in
  the grammar rather than in a convention.
* ``'=X'`` is **exact and unnormalised**: ``=1.2.3`` does not match
  ``1.2.3-rc1``. A recall fact stores the version string as observed, so it
  still matches itself; a catalogue entry that means a single affected release
  writes the half-open form ``[X,X.next)``.

One consequence of the lower-bound normalisation is stated rather than hidden:
adjacent half-open ranges are a clean partition over *unqualified* versions, and
**overlap on the prereleases of their shared boundary**. ``2.15.0-rc1`` is
inside both ``[2.0,2.15.0)`` and ``[2.15.0,2.16.0)``. Both directions of that
overlap are the over-matching direction, which is the trade this module made
above and pins in
``tests/test_discovery/test_version_range_properties.py``.

Stated tolerances
-----------------
* Only the first three dot-segments form the core. Trailing **numeric** segments
  are dropped, so ``2.4.49.1`` compares equal to ``2.4.49`` (unchanged from the
  previous parser). A trailing non-numeric tail is a qualifier.
* A leading non-numeric segment is unparseable: ``v1.2.3`` is ``None``, as
  before. An unparseable *observed* version satisfies only ``'*'``; an
  unparseable *predicate* is rejected rather than silently widened.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: The release core every consumer outside this module compares on.
Version = tuple[int, int, int]

#: The widest predicate: matches any observed version (including an unobservable one).
WILDCARD_PREDICATE = "*"

#: The lowest possible prerelease identifier, per SemVer §11 (numeric identifiers
#: rank below alphanumeric ones, and ``0`` is the smallest numeric identifier).
#: An inclusive lower bound with no prerelease of its own is compared as if it
#: carried this, so a distribution repackaging (``2.4.49-1ubuntu3.2``) and a
#: release candidate (``2.4.49-rc1``) are both inside ``[2.4.49,…``.
LOWEST_PRERELEASE: tuple[str, ...] = ("0",)

#: Ordering key for one prerelease identifier (SemVer §11): numeric identifiers
#: compare numerically and rank below alphanumeric ones, which compare ASCII-wise.
_IdentKey = tuple[int, int, str]


def _identifier_key(identifier: str) -> _IdentKey:
    """Total-order key for a single dot-separated prerelease identifier."""
    if identifier.isdigit():
        return (0, int(identifier), "")
    return (1, 0, identifier)


@dataclass(frozen=True, slots=True)
class SemVer:
    """A parsed version: a release core, an optional prerelease, optional build.

    Attributes:
        core: ``(major, minor, patch)`` — the release core, and exactly what
            :func:`parse_version` returns for the same string.
        prerelease: Dot-separated prerelease identifiers, empty for a release.
        build: Build metadata as written. Recorded so a caller can say it was
            seen; **never** part of precedence (SemVer §10).
    """

    core: Version
    prerelease: tuple[str, ...] = ()
    build: str = field(default="", compare=False)

    @property
    def precedence_key(self) -> tuple[Version, int, tuple[_IdentKey, ...]]:
        """Total-order key implementing SemVer §11 precedence.

        The middle element is what makes a release outrank every prerelease of
        the same core: ``1`` for a release, ``0`` for a prerelease. Build
        metadata is absent from the key by construction.
        """
        return (
            self.core,
            0 if self.prerelease else 1,
            tuple(_identifier_key(part) for part in self.prerelease),
        )

    def with_lowest_prerelease(self) -> SemVer:
        """This version as the lowest thing sorting at its own core.

        A no-op when a prerelease is already present — an author who wrote one
        meant it. Applied to an inclusive lower bound so that every prerelease
        and repackaging of the introduced version is inside the range.
        """
        if self.prerelease:
            return self
        return SemVer(core=self.core, prerelease=LOWEST_PRERELEASE)


def compare_versions(left: SemVer, right: SemVer) -> int:
    """Three-way comparison over :class:`SemVer` — a total order.

    Returns ``-1`` / ``0`` / ``1``. Totality, antisymmetry and transitivity are
    property-tested over generated version pairs rather than a table of cases;
    see ``tests/test_discovery/test_version_range_properties.py``.
    """
    a, b = left.precedence_key, right.precedence_key
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def parse_semver(raw: str) -> SemVer | None:
    """Parse a version string into a :class:`SemVer`, or ``None``.

    Deliberately tolerant of what fingerprinters and package managers actually
    emit — ``8.11``, ``2.14.1-jre``, ``2.4.49-1ubuntu3.2``, ``1.2.3+build.5`` —
    while refusing anything whose leading segment is not numeric. See the module
    docstring's *Stated tolerances*.
    """
    if not raw:
        return None
    text = raw.strip()
    if not text:
        return None

    main, _, build = text.partition("+")
    parts = main.split(".")

    nums: list[int] = []
    qualifier = ""
    offset = 0
    for part in parts[:3]:
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            return None
        nums.append(int(digits))
        if len(digits) < len(part):
            # The core ends mid-segment: everything from here is the qualifier.
            qualifier = main[offset + len(digits) :]
            break
        offset += len(part) + 1  # the segment plus its '.'
    else:
        # Core consumed whole segments. Anything left is the 4th+ segment: a
        # purely numeric tail is dropped (2.4.49.1 == 2.4.49, unchanged from the
        # previous parser); anything else is a qualifier.
        tail = main[offset:]
        qualifier = "" if _is_numeric_tail(tail) else tail

    while len(nums) < 3:
        nums.append(0)

    prerelease = _parse_prerelease(qualifier)
    return SemVer(core=(nums[0], nums[1], nums[2]), prerelease=prerelease, build=build)


def _is_numeric_tail(tail: str) -> bool:
    """Whether a post-core tail is only further numeric dot-segments."""
    if not tail:
        return True
    return all(segment.isdigit() for segment in tail.split(".") if segment != "")


def _parse_prerelease(qualifier: str) -> tuple[str, ...]:
    """Split a qualifier tail into dot-separated prerelease identifiers."""
    text = qualifier.strip()
    if text.startswith("-"):
        text = text[1:]
    if not text:
        return ()
    return tuple(segment for segment in text.split(".") if segment != "")


def parse_version(raw: str) -> Version | None:
    """Parse ``X`` / ``X.Y`` / ``X.Y.Z`` into the 3-tuple release core.

    The shared version-parse idiom (``source_ingest._parse_semver``, the
    ``successor``-edge sorter): a leading numeric ``major[.minor[.patch]]`` is
    taken, extra numeric segments are dropped, missing segments default to
    ``0``, and a qualifier suffix (``2.14.1-jre``) is tolerated by taking the
    leading integer run.

    It is now a **view** of :func:`parse_semver` rather than a second parser, so
    the core a range comparison uses and the core a threshold gate uses cannot
    drift apart. Callers that only order releases keep comparing 3-tuples;
    callers that must place a prerelease relative to its release read
    :func:`parse_semver` and :func:`compare_versions`.
    """
    parsed = parse_semver(raw)
    return None if parsed is None else parsed.core


def predicate_point_version(predicate: str) -> str:
    """The single point version an EXACT predicate names (``'=2.14.1'`` → ``'2.14.1'``).

    Returns the version string for ``'=X'`` or a bare ``'X'`` (the shape a
    confirmed fact writes); returns ``''`` for a range / inequality / wildcard
    predicate (no single point). Used by the version-lineage (``successor``) edge
    writer to collect the concrete versions the store holds facts for.
    """
    predicate = (predicate or "").strip()
    if not predicate or predicate == WILDCARD_PREDICATE:
        return ""
    if predicate.startswith("="):
        predicate = predicate[1:].strip()
    if any(predicate.startswith(op) for op in ("<", ">", "[", "(")):
        return ""
    return predicate if parse_version(predicate) is not None else ""


#: Opening bracket → whether the lower bound is inclusive.
_LOWER_INCLUSIVE = {"[": True, "(": False}
#: Closing bracket → whether the upper bound is inclusive.
_UPPER_INCLUSIVE = {"]": True, ")": False}


def _interval_satisfied(observed: SemVer, predicate: str) -> bool:
    """Whether *observed* falls inside a bracketed interval predicate.

    ``[X,Y)`` is the canonical advisory form: ``introduced <= v < fixed``. The
    inclusive lower bound is normalised to ``X-0`` (see the module docstring) so
    a repackaging or release candidate of the introduced version is inside it;
    the **open** lower bound ``(X`` is the escape hatch that excludes them.
    """
    lower_inclusive = _LOWER_INCLUSIVE.get(predicate[0])
    upper_inclusive = _UPPER_INCLUSIVE.get(predicate[-1])
    if lower_inclusive is None or upper_inclusive is None:
        return False

    inner = predicate[1:-1]
    if "," not in inner:
        return False
    low_raw, high_raw = (part.strip() for part in inner.split(",", 1))
    low, high = parse_semver(low_raw), parse_semver(high_raw)
    if low is None or high is None:
        return False

    if lower_inclusive:
        if compare_versions(observed, low.with_lowest_prerelease()) < 0:
            return False
    elif compare_versions(observed, low) <= 0:
        return False

    if upper_inclusive:
        return compare_versions(observed, high) <= 0
    return compare_versions(observed, high) < 0


def version_satisfies(observed: str, predicate: str) -> bool:
    """Whether *observed* satisfies *predicate* over the grammar above.

    Deterministic, no LLM.

      * ``'*'`` (or empty) — always ``True`` (the unobservable-version /
        unversioned-fact case).
      * ``'=X'`` / bare ``'X'`` — exact, unnormalised: ``=1.2.3`` does not match
        ``1.2.3-rc1``.
      * ``'<X'`` / ``'<=X'`` — upper bounds, SemVer §11, so ``X-rc1`` is below
        ``X`` and inside ``<X``.
      * ``'>X'`` / ``'>=X'`` — lower bounds. ``>=X`` normalises exactly as the
        inclusive bracket does (it is the same bound), so ``>=2.4.49`` admits
        ``2.4.49-1ubuntu3.2``; ``>X`` is the strict form that does not.
      * ``'[X,Y)'`` and the three other bracket combinations — intervals.

    An unparseable *observed* satisfies only ``'*'``; an unparseable or
    malformed *predicate* is rejected (``False``) rather than silently widened.
    """
    predicate = (predicate or "").strip()
    if predicate == WILDCARD_PREDICATE or predicate == "":
        return True

    if predicate[0] in _LOWER_INCLUSIVE:
        obs = parse_semver(observed)
        if obs is None:
            return False
        return _interval_satisfied(obs, predicate)

    op = "="
    for candidate in ("<=", ">=", "<", ">", "="):
        if predicate.startswith(candidate):
            op = candidate
            predicate = predicate[len(candidate) :].strip()
            break

    bound = parse_semver(predicate)
    obs = parse_semver(observed)
    if bound is None or obs is None:
        return False
    if op == "=":
        return compare_versions(obs, bound) == 0
    if op == "<":
        return compare_versions(obs, bound) < 0
    if op == "<=":
        return compare_versions(obs, bound) <= 0
    if op == ">":
        return compare_versions(obs, bound) > 0
    # ">=" is the same bound as an inclusive bracket, and normalises identically.
    return compare_versions(obs, bound.with_lowest_prerelease()) >= 0


__all__ = [
    "LOWEST_PRERELEASE",
    "WILDCARD_PREDICATE",
    "SemVer",
    "Version",
    "compare_versions",
    "parse_semver",
    "parse_version",
    "predicate_point_version",
    "version_satisfies",
]
