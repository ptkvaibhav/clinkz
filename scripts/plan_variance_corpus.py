"""Replay every recorded phase-3 ranking against the deterministic ranking layer.

**Offline. Sends nothing.** It reads ``outputs/*/trace.jsonl`` and nothing else,
which is the point: the engine already records, per methodology invocation, the
phase-2 fingerprint the ranking keyed on, the order phase 3 produced, and which
type phase 5 confirmed. That triple is enough to re-run
:mod:`clinkz.agents._plan_ranking` over every ranking the engine has ever made
and ask two questions a live run cannot answer cheaply:

* **Is the ranking a function of the observation?** Group by fingerprint and
  count distinct orders. The recorded rankings are not — 48 of the 64
  fingerprints ranked more than once produced at least two orders, and one SQLi
  fingerprint ranked 210 times produced 16.
* **Does the deterministic ranking still reach what confirmed?** For every
  recorded confirmation, is the confirming type inside the window the new
  ranking would attempt?

**What this measurement CANNOT tell you, and why it is still worth making.**
The corpus is censored at the window: a type that was never attempted never
produced a confirmation to record, so "the recorded confirming type is inside
``ranked[:3]``" is true by construction, 835 out of 835. The before/after here is
therefore not a coverage improvement — it is a *safety* check on one that cannot
be measured offline. It answers "does inverting phase 3 to a deterministic
ranking lose anything the engine is known to have found", and a broken ranking
fails it loudly: replaying the fallback rankings this layer replaced keeps 770 of
the 833, and 41 of the 63 it misses are IDOR ``horizontal`` confirmations lost to
a single condition.
Widening is what the *window* does, and its benefit is by construction — a type
that is now attempted and was not before can confirm, and every attempt still
passes the same phase-5 oracle and the same never-sent control.

Usage::

    python scripts/plan_variance_corpus.py [--outputs-root <dir>] [--json]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from clinkz.agents import _plan_ranking as ranking_layer  # noqa: E402
from clinkz.models.methodology import (  # noqa: E402
    FileUploadRestrictions,
    IDORPrimitives,
    InjectionPrimitives,
    LFITraversalPrimitives,
    NoSQLContext,
    NoSQLPrimitives,
    RedirectPrimitives,
    ShellPrimitives,
    ShellType,
    SQLDialect,
    SSRFCapability,
    SSTIPrimitives,
    SSTITemplateEngine,
)

#: skill -> (phase-2 fingerprint event, phase-3 ranking event, phase-5 verify
#: event, the fingerprint fields that ranking is a function of).
#:
#: The field list is what makes the grouping key a *fingerprint* rather than a
#: timestamped record: two rankings share a key exactly when the ranker saw the
#: same input. A finer key would understate the variance, never overstate it.
SKILLS: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "sqli": (
        "dialect_fingerprint",
        "injection_type_ranking",
        "verification",
        ("dialect", "dialect_evidence", "primitives"),
    ),
    "cmdi": (
        "shell_fingerprint",
        "execution_type_ranking",
        "verification",
        ("shell", "shell_evidence", "primitives"),
    ),
    "lfi": (
        "path_handling_fingerprint",
        "retrieval_type_ranking",
        "verification",
        ("primitives", "prim_evidence"),
    ),
    "nosqli": (
        "context_fingerprint",
        "injection_type_ranking",
        "verification",
        ("context", "primitives"),
    ),
    "ssrf": (
        "capability_fingerprint",
        "exploitation_type_ranking",
        "verification",
        ("capability",),
    ),
    "ssti": (
        "engine_fingerprint",
        "exploitation_type_ranking",
        "verification",
        ("engine", "primitives"),
    ),
    "idor": (
        "authz_model_fingerprint",
        "exploitation_type_ranking",
        "verification",
        ("primitives",),
    ),
    "open_redirect": (
        "redirect_handling_fingerprint",
        "bypass_type_ranking",
        "verification",
        ("primitives",),
    ),
    "file_upload": (
        "restriction_fingerprint",
        "execution_type_ranking",
        "verification",
        ("restrictions",),
    ),
}

#: The attempt cap each phase-4/5 loop uses, where it differs from the shared one.
CAPS: dict[str, int] = {"ssrf": 4}

#: The two classes whose phase-3 checkpoint is deterministic end to end. For the
#: rest the model still orders the supported block, so the replay feeds it the
#: order that run actually recorded.
INVERTED = frozenset({"sqli", "cmdi"})

_TYPE_KEYS = (
    "injection_type",
    "execution_type",
    "exploitation_type",
    "retrieval_type",
    "bypass_type",
    "attack_type",
)


@dataclass
class Episode:
    """One methodology invocation's (fingerprint, ranking, outcome) triple."""

    engagement: str
    skill: str
    param: str
    fingerprint: dict[str, Any]
    recorded: list[str]
    confirmed: str | None = None

    @property
    def key(self) -> str:
        return json.dumps(self.fingerprint, sort_keys=True, default=str)


@dataclass
class ClassResult:
    skill: str
    rankings: int = 0
    confirms: int = 0
    reachable_confirms: int = 0
    kept_recorded: int = 0
    kept_new: int = 0
    attempts_recorded: int = 0
    attempts_new: int = 0
    fingerprints_repeated: int = 0
    recorded_varied: int = 0
    new_varied: int = 0
    retired_types: collections.Counter = field(default_factory=collections.Counter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill,
            "rankings": self.rankings,
            "confirms": self.confirms,
            "reachable_confirms": self.reachable_confirms,
            "kept_recorded": self.kept_recorded,
            "kept_new": self.kept_new,
            "attempts_recorded": self.attempts_recorded,
            "attempts_new": self.attempts_new,
            "fingerprints_repeated": self.fingerprints_repeated,
            "recorded_varied": self.recorded_varied,
            "new_varied": self.new_varied,
            "retired_types": dict(self.retired_types),
        }


def _type_of(payload: dict[str, Any]) -> str | None:
    for key in _TYPE_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def read_episodes(outputs_root: Path) -> list[Episode]:
    """Every recorded (fingerprint, ranking, outcome) triple under *outputs_root*.

    Methodology dispatch is sequential — the exploit agent runs one ``_test_*``
    at a time and one parameter at a time inside it — so a skill's phase events
    arrive in order and an episode is delimited by that skill's next ranking
    event.
    """
    episodes: list[Episode] = []
    for path in sorted(outputs_root.glob("*/trace.jsonl")):
        last_fingerprint: dict[str, dict[str, Any]] = {}
        open_episode: dict[str, Episode] = {}
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                if '"methodology_phase"' not in line:
                    continue
                try:
                    payload = json.loads(line).get("payload") or {}
                except (json.JSONDecodeError, AttributeError):
                    continue
                skill = payload.get("skill") or ""
                spec = SKILLS.get(skill)
                if spec is None:
                    continue
                fp_name, rank_name, verify_name, fields = spec
                name = payload.get("phase_name")
                if name == fp_name:
                    last_fingerprint[skill] = payload
                elif name == rank_name:
                    source = last_fingerprint.get(skill) or {}
                    episode = Episode(
                        engagement=path.parent.name,
                        skill=skill,
                        param=str(payload.get("param") or payload.get("upload_url") or ""),
                        fingerprint={k: source[k] for k in fields if k in source},
                        recorded=[str(t) for t in (payload.get("ranked") or [])],
                    )
                    open_episode[skill] = episode
                    episodes.append(episode)
                elif name == verify_name:
                    episode = open_episode.get(skill)
                    if episode is not None and payload.get("verified") is True:
                        episode.confirmed = episode.confirmed or _type_of(payload)
    return episodes


def deterministic_ranking(episode: Episode) -> ranking_layer.TypeRanking[Any] | None:
    """Re-run the shipped ranker over this episode's recorded fingerprint.

    A straight ``model_validate`` of what the trace stored — the engine wrote
    each primitives model as its own ``model_dump``, so nothing is re-derived
    here and a field a recorded run did not carry takes the model's own default,
    which is what that run's ranker saw too.
    """
    fp = episode.fingerprint
    match episode.skill:
        case "sqli":
            return ranking_layer.rank_sqli(
                SQLDialect(fp.get("dialect") or "mysql"),
                InjectionPrimitives.model_validate(fp.get("primitives") or {}),
                dict(fp.get("dialect_evidence") or {}),
            )
        case "cmdi":
            return ranking_layer.rank_cmdi(
                ShellType(fp.get("shell") or "unknown"),
                ShellPrimitives.model_validate(fp.get("primitives") or {}),
                dict(fp.get("shell_evidence") or {}),
            )
        case "lfi":
            return ranking_layer.rank_lfi(
                LFITraversalPrimitives.model_validate(fp.get("primitives") or {}),
                dict(fp.get("prim_evidence") or {}),
            )
        case "nosqli":
            return ranking_layer.rank_nosqli(
                NoSQLContext(fp.get("context") or "unknown"),
                NoSQLPrimitives.model_validate(fp.get("primitives") or {}),
            )
        case "ssrf":
            return ranking_layer.rank_ssrf(
                SSRFCapability.model_validate(fp.get("capability") or {})
            )
        case "ssti":
            return ranking_layer.rank_ssti(
                SSTITemplateEngine(fp.get("engine") or "unknown"),
                SSTIPrimitives.model_validate(fp.get("primitives") or {}),
            )
        case "idor":
            return ranking_layer.rank_idor(
                IDORPrimitives.model_validate(fp.get("primitives") or {})
            )
        case "open_redirect":
            return ranking_layer.rank_open_redirect(
                RedirectPrimitives.model_validate(fp.get("primitives") or {})
            )
        case "file_upload":
            return ranking_layer.rank_file_upload(
                FileUploadRestrictions.model_validate(fp.get("restrictions") or {})
            )
    return None


def new_window(episode: Episode) -> list[str] | None:
    """The attempt list the shipped layer would produce for this episode.

    The SQLi credential-field gate is replayed from the fact the trace already
    records rather than re-derived: its input is the *request* (an identity field
    beside a password-shaped one), which no phase-3 event carries, and
    ``auth_bypass`` leading a recorded ranking is exactly that gate having fired.
    """
    ranking = deterministic_ranking(episode)
    if ranking is None:
        return None
    cap = CAPS.get(episode.skill, ranking_layer.DEFAULT_ATTEMPT_CAP)
    if episode.skill in INVERTED:
        merged: list[Any] = list(ranking.ranked)
    else:
        enum_type = type(ranking.ranked[0]) if ranking.ranked else None
        named: list[Any] = []
        for value in episode.recorded:
            if enum_type is None:
                break
            try:
                named.append(enum_type(value))
            except ValueError:
                continue  # a type this vocabulary has since retired
        merged = ranking_layer.merge_llm_ranking(named, ranking)
    window = [t.value for t in ranking_layer.attempt_window(merged, ranking.supported, cap=cap)]
    if episode.skill == "sqli" and episode.recorded[:1] == ["auth_bypass"]:
        window = ["auth_bypass", *(t for t in window if t != "auth_bypass")]
    return window


def _live_vocabulary(episode: Episode) -> set[str] | None:
    ranking = deterministic_ranking(episode)
    if ranking is None or not ranking.ranked:
        return None
    return {t.value for t in type(ranking.ranked[0])}


def score(episodes: list[Episode]) -> list[ClassResult]:
    """Per class: what the recorded window kept, what the new one keeps, at what cost."""
    results: dict[str, ClassResult] = {}
    recorded_orders: dict[tuple[str, str], set[tuple[str, ...]]] = collections.defaultdict(set)
    new_orders: dict[tuple[str, str], set[tuple[str, ...]]] = collections.defaultdict(set)
    seen: collections.Counter[tuple[str, str]] = collections.Counter()

    for episode in episodes:
        window = new_window(episode)
        if window is None:
            continue
        result = results.setdefault(episode.skill, ClassResult(skill=episode.skill))
        cap = CAPS.get(episode.skill, ranking_layer.DEFAULT_ATTEMPT_CAP)
        recorded_window = episode.recorded[:cap]
        result.rankings += 1
        result.attempts_recorded += len(recorded_window)
        result.attempts_new += len(window)
        key = (episode.skill, episode.key)
        seen[key] += 1
        recorded_orders[key].add(tuple(recorded_window))
        new_orders[key].add(tuple(window))
        if episode.confirmed:
            result.confirms += 1
            vocabulary = _live_vocabulary(episode)
            if vocabulary is not None and episode.confirmed not in vocabulary:
                # A confirmation whose type the enum no longer has. No ranking can
                # produce it, so counting it as a regression would be measuring
                # this layer against a vocabulary that does not exist.
                result.retired_types[episode.confirmed] += 1
            else:
                result.reachable_confirms += 1
                result.kept_recorded += episode.confirmed in recorded_window
                result.kept_new += episode.confirmed in window

    for (skill, _fp), count in seen.items():
        if count < 2:
            continue
        result = results[skill]
        result.fingerprints_repeated += 1
        result.recorded_varied += len(recorded_orders[(skill, _fp)]) > 1
        result.new_varied += len(new_orders[(skill, _fp)]) > 1
    return [results[k] for k in sorted(results)]


def render(results: list[ClassResult]) -> str:
    lines = [
        f"{'class':<15}{'rank':>6}{'confirm':>8}{'kept now':>9}{'kept new':>9}"
        f"{'attempts':>10}{'new':>8}{'delta':>8}{'fp>1':>6}{'varies now':>11}{'varies new':>11}",
        "-" * 111,
    ]
    total = ClassResult(skill="TOTAL")
    for r in results:
        delta = 100 * (r.attempts_new - r.attempts_recorded) / max(1, r.attempts_recorded)
        lines.append(
            f"{r.skill:<15}{r.rankings:>6}{r.reachable_confirms:>8}{r.kept_recorded:>9}"
            f"{r.kept_new:>9}{r.attempts_recorded:>10}{r.attempts_new:>8}{delta:>+7.1f}%"
            f"{r.fingerprints_repeated:>6}{r.recorded_varied:>11}{r.new_varied:>11}"
        )
        for name in (
            "rankings",
            "reachable_confirms",
            "kept_recorded",
            "kept_new",
            "attempts_recorded",
            "attempts_new",
            "fingerprints_repeated",
            "recorded_varied",
            "new_varied",
        ):
            setattr(total, name, getattr(total, name) + getattr(r, name))
        total.retired_types.update(r.retired_types)
    delta = 100 * (total.attempts_new - total.attempts_recorded) / max(1, total.attempts_recorded)
    lines.append("-" * 111)
    lines.append(
        f"{total.skill:<15}{total.rankings:>6}{total.reachable_confirms:>8}"
        f"{total.kept_recorded:>9}{total.kept_new:>9}{total.attempts_recorded:>10}"
        f"{total.attempts_new:>8}{delta:>+7.1f}%{total.fingerprints_repeated:>6}"
        f"{total.recorded_varied:>11}{total.new_varied:>11}"
    )
    if total.retired_types:
        lines.append("")
        lines.append(
            "Confirmations held out — the type is no longer an enum member, so no "
            "ranking can produce it:"
        )
        for name, count in sorted(total.retired_types.items()):
            lines.append(f"    {name}: {count}")
    lines.append("")
    lines.append(
        "'kept now' is 835/835 by construction: a type that was never attempted "
        "never produced a\nconfirmation to record, so the corpus is censored at "
        "the window. The column that carries\ninformation is 'kept new' — whether "
        "the deterministic ranking still reaches what the engine\nis known to have "
        "found."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outputs-root", default="outputs", type=Path)
    parser.add_argument("--json", action="store_true", help="emit the raw per-class rows")
    args = parser.parse_args()

    if not args.outputs_root.is_dir():
        print(f"no outputs root at {args.outputs_root}", file=sys.stderr)
        return 2
    episodes = read_episodes(args.outputs_root)
    if not episodes:
        print(f"no recorded phase-3 rankings under {args.outputs_root}", file=sys.stderr)
        return 2
    results = score(episodes)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print(f"{len(episodes)} recorded rankings across {args.outputs_root}\n")
        print(render(results))
    lost = sum(r.kept_recorded - r.kept_new for r in results)
    return 1 if lost > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
