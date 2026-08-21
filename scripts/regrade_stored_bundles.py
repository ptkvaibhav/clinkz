"""Re-grade every stored bundle's confirmed findings against the control rules.

Offline. Reads `outputs/<id>/report_<id>.json` off disk and sends nothing.

The question this answers is not "were those findings real". It is **"would each
one survive its own control"** — and the two come apart in a way the deliverable
cannot show. DVWA at `low` genuinely has command injection, so a `_test_cmdi`
finding there is correct; if that finding was confirmed by an oracle that would
also have confirmed on a probe running no command, it is a phantom that happened
to land on a real bug, and by the report alone it is indistinguishable from one
that was measured. That distinction is the whole point of re-grading a benchmark
we already believe we passed.

Two checks, both from `clinkz.agents._control_arm`, both pure:

* **the never-sent control** — a marker-oracle finding must carry an arm the
  oracle refused. Every stored bundle predates the arm, so every one of those
  findings is `NO_ARM`: not proof that the finding was wrong, but proof that the
  question was never asked. That number IS the answer to "did 15/12/9/0 measure
  what we thought".
* **attribution** — `expected_indicator` versus `indicator_observed` versus the
  payload, which needs nothing but the evidence already on disk and can therefore
  be graded retroactively as hard fact.

**Which control, though.** "Marker-bound" is declared per CLASS, and one class
confirms on five different channels. `_test_sqli`'s `auth_bypass` channel is a
three-arm differential whose contradiction and benign arms are DISPATCHED and
must refuse — so the juice-shop authentication bypass carried a control all
along and was graded `NO_ARM` for want of a never-sent one. Neither the class
name nor the indicator name carries that fact (`_test_nosqli` has an
`auth_bypass` channel with no shape-matched contradiction at all), so the
producer declares it on `VulnClass.control_arm` and this reads the declaration.

Verdicts: `SURVIVES` (attributable, and either the class is not marker-bound or
the channel it confirmed on dispatched its own arm), `NO_ARM` (marker-bound, no
control of any kind was run), `REFUSED` (self-refuting evidence — it would be
rejected at emission today), `UNKNOWN_CLASS` (the title resolves to no
`VulnClass`, so there is no producer declaration to read and the finding is
ungraded — which is not the same as a pass, and used to be reported as one).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_ROOT / "scripts"))

from _artifact_io import write_redacted_json  # noqa: E402

from clinkz.agents._control_arm import (  # noqa: E402
    attribution_contradiction,
    control_required,
    control_verdict_from_evidence,
    indicator_is_self_controlled,
    structured_evidence_field,
)
from clinkz.models.vuln_classes import for_finding  # noqa: E402

#: The bundles under re-grade, as (label, engagement id). The DVWA ladder in the
#: order its security control tightens, then the Juice Shop benchmark.
BUNDLES: tuple[tuple[str, str], ...] = (
    ("dvwa/low", "c5d2ba7e-69f5-40cf-8efe-1b6b23707ccd"),
    ("dvwa/medium", "de0cbf5b-d49c-4a37-9446-52be2bba9339"),
    ("dvwa/high", "6b1e10fe-6b47-4c8b-99fb-31f6bf355ae5"),
    ("dvwa/impossible", "327fd377-e120-4b77-b713-dddf7f54d2ec"),
    ("juiceshop", "5b1a93e8-028e-445e-8d3e-022a32176fac"),
    ("portfolio", "d67835f5-4b55-470b-b6de-29320db79c1d"),
)

SURVIVES = "SURVIVES"
NO_ARM = "NO_ARM"
REFUSED = "REFUSED"
UNKNOWN_CLASS = "UNKNOWN_CLASS"


@dataclass(frozen=True)
class Graded:
    """One stored finding under the rules that exist now."""

    bundle: str
    title: str
    target: str
    test_method: str
    verdict: str
    detail: str


def _evidence_field(evidence: list[str], key: str) -> str:
    """First ``key=<value>`` entry's value, matching the engine's own reader."""
    prefix = f"{key}="
    for line in evidence:
        if line.startswith(prefix):
            return line[len(prefix) :]
    return ""


def grade(bundle: str, finding: dict[str, Any]) -> Graded:
    """Grade one stored finding. Pure — no request, no state."""
    evidence = [str(e) for e in finding.get("evidence") or []]
    title = str(finding.get("title") or "")
    description = str(finding.get("description") or "")
    vuln_class = for_finding(title, description)
    test_method = vuln_class.test_method if vuln_class else ""

    reason = attribution_contradiction(
        expected_indicator=_evidence_field(evidence, "expected_indicator"),
        indicator_observed=_evidence_field(evidence, "indicator_observed"),
        payload=_evidence_field(evidence, "payload"),
    )
    if reason is not None:
        return Graded(bundle, title, str(finding.get("target") or ""), test_method, REFUSED, reason)

    if not test_method:
        # Every verdict below this line is read off the PRODUCER's declaration —
        # ``MARKER_ORACLE_CLASSES`` / ``CONTROL_EXEMPT_CLASSES`` and
        # ``VulnClass.control_arm``, all keyed by ``_test_*``. A finding whose
        # title resolves to no class reaches none of them, so there is no
        # declaration to read and no verdict to give.
        #
        # It used to fall through to SURVIVES, because ``control_required("")``
        # is False and "not marker-bound" was the branch that answered. That is
        # the consumer supplying an answer the producer never gave: the juice
        # shop bundle's "Credential material served to an unauthenticated
        # requester (authorization)" was graded SURVIVES on the strength of its
        # title matching nothing. The fix is not another title token in a lookup
        # table here — it is to say so, and to make the emit side resolvable
        # (``_make_finding`` now logs an UNCLASSIFIED FINDING for exactly this).
        return Graded(
            bundle,
            title,
            str(finding.get("target") or ""),
            "(unrecognised class)",
            UNKNOWN_CLASS,
            "title resolves to no VulnClass, so the producer's control_arm declaration "
            "cannot be read — this is ungraded, NOT a pass",
        )

    if not control_required(test_method):
        return Graded(
            bundle,
            title,
            str(finding.get("target") or ""),
            test_method,
            SURVIVES,
            "not a marker oracle — confirms on a protocol observation or a control it already ran",
        )

    verdict = control_verdict_from_evidence(evidence)
    if verdict is None:
        # Before calling it NO_ARM, ask the PRODUCER whether the channel this
        # finding actually confirmed on carries its own dispatched arm. The
        # class-level rule is keyed on ``_test_*``, which is the granularity at
        # which "this oracle matches a string in a body" is true — and one class
        # breaks it. ``_test_sqli`` confirms on five channels; four are marker
        # matches and ``auth_bypass`` is a three-arm differential whose
        # contradiction and benign arms are DISPATCHED and must refuse.
        #
        # Reading the class name alone graded the juice-shop authentication
        # bypass — a CRITICAL whose evidence records ``control(contradiction):
        # status=401 no auth artifact | benign: status=401 no auth artifact`` —
        # as a finding whose control was never asked for. Reading the indicator
        # name alone would be wrong the other way: ``_test_nosqli`` has an
        # ``auth_bypass`` channel that compares against a benign baseline with no
        # shape-matched contradiction at all. Neither string carries the fact, so
        # the producer declares it and this reads the declaration.
        #
        # The asymmetry with the live gate is deliberate and stated: the engine
        # CAN dispatch a never-sent arm for this channel and does, so
        # ``_persist_finding`` still demands one. A stored bundle can dispatch
        # nothing, so the only control available to it is the one its confirming
        # oracle already ran.
        self_controlled = indicator_is_self_controlled(
            test_method, structured_evidence_field(evidence, "indicator_type")
        )
        if self_controlled:
            return Graded(
                bundle,
                title,
                str(finding.get("target") or ""),
                test_method,
                SURVIVES,
                f"oracle dispatched its own control arm — {self_controlled}",
            )
        return Graded(
            bundle,
            title,
            str(finding.get("target") or ""),
            test_method,
            NO_ARM,
            "marker oracle, no control arm recorded — the question was never asked",
        )
    if verdict.satisfied:
        return Graded(
            bundle,
            title,
            str(finding.get("target") or ""),
            test_method,
            SURVIVES,
            f"control arm refused (decoy {verdict.decoy})",
        )
    return Graded(
        bundle,
        title,
        str(finding.get("target") or ""),
        test_method,
        REFUSED,
        f"control arm did not refuse ({verdict.status})",
    )


def _load(engagement_id: str) -> list[dict[str, Any]]:
    path = _ROOT / "outputs" / engagement_id / f"report_{engagement_id}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [f for f in (data.get("findings") or []) if isinstance(f, dict)]


def parse_bundles(pairs: list[str] | None) -> tuple[tuple[str, str], ...]:
    """``LABEL=ENGAGEMENT`` pairs, or :data:`BUNDLES` when none are given.

    The default list is the historical set — the bundles that predate the
    control arm and therefore re-grade ``NO_ARM`` by construction. Naming
    bundles explicitly is what makes the verdict a MEASUREMENT rather than a
    restatement of that fact: a run made under the current gate dispatched real
    control arms, so its findings can come back ``SURVIVES`` or ``REFUSED``, and
    those are the only two answers that carry information.
    """
    if not pairs:
        return BUNDLES
    parsed: list[tuple[str, str]] = []
    for pair in pairs:
        label, _, engagement = pair.partition("=")
        if not label.strip() or not engagement.strip():
            raise SystemExit(f"FATAL: --bundle wants LABEL=ENGAGEMENT, got {pair!r}")
        parsed.append((label.strip(), engagement.strip()))
    return tuple(parsed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        action="append",
        metavar="LABEL=ENGAGEMENT",
        help=(
            "Grade this bundle instead of the stored default set. Repeatable. "
            "Sends nothing either way."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_ROOT / "outputs" / "_regrade" / "control_regrade.json",
        help="Where to write the JSON verdict (default: outputs/_regrade/control_regrade.json).",
    )
    args = parser.parse_args(argv)
    bundles = parse_bundles(args.bundle)

    graded: list[Graded] = []
    missing: list[str] = []
    for label, engagement_id in bundles:
        findings = _load(engagement_id)
        if not findings:
            missing.append(f"{label} ({engagement_id})")
            continue
        graded.extend(grade(label, f) for f in findings)

    # Per (bundle, class) survival — the table this exists to produce.
    per_class: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for g in graded:
        per_class[(g.bundle, g.test_method or "(unrecognised)")][g.verdict] += 1

    print("PER-CLASS SURVIVAL — stored bundles under the control rules\n")
    header = (
        f"{'bundle':<18} {'class':<26} {'n':>3} {'SURVIVES':>9} {'NO_ARM':>7} "
        f"{'REFUSED':>8} {'UNKNOWN':>8}"
    )
    print(header)
    print("-" * len(header))
    for (bundle, cls), counts in sorted(per_class.items()):
        total = sum(counts.values())
        print(
            f"{bundle:<18} {cls:<26} {total:>3} "
            f"{counts[SURVIVES]:>9} {counts[NO_ARM]:>7} {counts[REFUSED]:>8} "
            f"{counts[UNKNOWN_CLASS]:>8}"
        )

    print("\nPER-BUNDLE TOTALS\n")
    per_bundle: dict[str, Counter[str]] = defaultdict(Counter)
    for g in graded:
        per_bundle[g.bundle][g.verdict] += 1
    for label, _ in bundles:
        counts = per_bundle.get(label)
        if counts is None:
            continue
        total = sum(counts.values())
        print(
            f"  {label:<18} confirmed={total:<3} survives={counts[SURVIVES]:<3} "
            f"no_arm={counts[NO_ARM]:<3} refused={counts[REFUSED]:<3} "
            f"unknown_class={counts[UNKNOWN_CLASS]}"
        )

    ungraded = [g for g in graded if g.verdict == UNKNOWN_CLASS]
    if ungraded:
        print("\nUNGRADED — title resolves to no VulnClass (NOT a pass)\n")
        for g in ungraded:
            print(f"  [{g.bundle}] {g.title} @ {g.target}")
            print(f"      {g.detail}")

    refused = [g for g in graded if g.verdict == REFUSED]
    if refused:
        print("\nREFUSED TODAY — self-refuting evidence in the stored bundle\n")
        for g in refused:
            print(f"  [{g.bundle}] {g.title} @ {g.target}")
            print(f"      {g.detail}")

    if missing:
        print("\nBUNDLES NOT ON DISK (not graded, not counted):")
        for m in missing:
            print(f"  - {m}")

    out = args.out
    write_redacted_json(
        out,
        {
            "bundles": [
                {"label": lbl, "engagement": eid}
                for lbl, eid in bundles
                if lbl in per_bundle or f"{lbl} ({eid})" not in missing
            ],
            "missing": missing,
            "per_class": [
                {
                    "bundle": bundle,
                    "class": cls,
                    "confirmed": sum(counts.values()),
                    "survives": counts[SURVIVES],
                    "no_arm": counts[NO_ARM],
                    "refused": counts[REFUSED],
                    "unknown_class": counts[UNKNOWN_CLASS],
                }
                for (bundle, cls), counts in sorted(per_class.items())
            ],
            "ungraded": [
                {
                    "bundle": g.bundle,
                    "title": g.title,
                    "target": g.target,
                    "detail": g.detail,
                }
                for g in ungraded
            ],
            "refused": [
                {
                    "bundle": g.bundle,
                    "title": g.title,
                    "target": g.target,
                    "class": g.test_method,
                    "detail": g.detail,
                }
                for g in refused
            ],
        },
    )
    print(f"\nWritten: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
