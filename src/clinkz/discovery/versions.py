"""Version predicate grammar for Layer-2 capability recall (design §2.4).

A tiny **deterministic, LLM-free** matcher over the predicate grammar a
:class:`~clinkz.discovery.models.CapabilityFact` stores:

    '<X'  |  '<=X'  |  '=X'  |  '[X,Y]'  |  '*'    (plus '>X' / '>=X' for symmetry)

built on the same 3-tuple ``(major, minor, patch)`` compare idiom the source
ingestor already uses for the log4j threshold (``_LOG4J_SAFE_VERSION``). A recall
fires only when the *observed* version satisfies the fact's predicate; a version we
cannot observe is passed as ``'*'`` (widest, lowest-confidence — §7 budget risk).

Predicates and matching are intentionally conservative: a bounded predicate can be
satisfied only by a version we can actually parse, so an unparseable observed
version fails every predicate except ``'*'``. Recall only *ranks* hypotheses and
never emits (§5), so a wrong parse over- or under-recalls (bounded budget) — never a
false emission.
"""

from __future__ import annotations

Version = tuple[int, int, int]

# The widest predicate: matches any observed version (including an unobservable one).
WILDCARD_PREDICATE = "*"


def parse_version(raw: str) -> Version | None:
    """Parse ``X`` / ``X.Y`` / ``X.Y.Z`` into a 3-tuple; ``None`` if non-numeric.

    The shared version-parse idiom (previously ``source_ingest._parse_semver``): a
    leading numeric ``major[.minor[.patch]]`` is taken, extra dotted segments are
    dropped, missing segments default to ``0``. A build/qualifier suffix on the
    patch (``2.14.1-jre``) is tolerated by taking the leading integer run.
    """
    if not raw:
        return None
    parts = raw.strip().split(".")[:3]
    nums: list[int] = []
    for part in parts:
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            return None
        nums.append(int(digits))
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def predicate_point_version(predicate: str) -> str:
    """The single point version an EXACT predicate names (``'=2.14.1'`` → ``'2.14.1'``).

    Returns the version string for ``'=X'`` or a bare ``'X'`` (the shape a confirmed
    fact writes); returns ``''`` for a range / inequality / wildcard predicate (no
    single point). Used by the version-lineage (``successor``) edge writer to collect
    the concrete versions the store holds facts for.
    """
    predicate = (predicate or "").strip()
    if not predicate or predicate == WILDCARD_PREDICATE:
        return ""
    if predicate.startswith("="):
        predicate = predicate[1:].strip()
    if any(predicate.startswith(op) for op in ("<", ">", "[")):
        return ""
    return predicate if parse_version(predicate) is not None else ""


def version_satisfies(observed: str, predicate: str) -> bool:
    """Whether *observed* satisfies the *predicate* over the §2.4 grammar.

    Deterministic, no LLM. Grammar:

      * ``'*'`` — always ``True`` (the unobservable-version / unversioned fact case).
      * ``'=X'`` / bare ``'X'`` — exact tuple equality.
      * ``'<X'`` / ``'<=X'`` / ``'>X'`` / ``'>=X'`` — tuple comparison against ``X``.
      * ``'[X,Y]'`` — inclusive range ``X <= observed <= Y``.

    An unparseable *observed* satisfies only ``'*'`` (a bounded predicate needs a
    real version to compare); an unparseable/malformed *predicate* is rejected
    (``False``) rather than silently widened — recall stays conservative.
    """
    predicate = (predicate or "").strip()
    if predicate == WILDCARD_PREDICATE or predicate == "":
        return True

    if predicate.startswith("[") and predicate.endswith("]"):
        inner = predicate[1:-1]
        if "," not in inner:
            return False
        low_raw, high_raw = (part.strip() for part in inner.split(",", 1))
        low, high = parse_version(low_raw), parse_version(high_raw)
        obs = parse_version(observed)
        if low is None or high is None or obs is None:
            return False
        return low <= obs <= high

    op = "="
    for candidate in ("<=", ">=", "<", ">", "="):
        if predicate.startswith(candidate):
            op = candidate
            predicate = predicate[len(candidate) :].strip()
            break

    bound = parse_version(predicate)
    obs = parse_version(observed)
    if bound is None or obs is None:
        return False
    if op == "=":
        return obs == bound
    if op == "<":
        return obs < bound
    if op == "<=":
        return obs <= bound
    if op == ">":
        return obs > bound
    return obs >= bound  # ">="
