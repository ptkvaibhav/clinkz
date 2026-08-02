"""Render the Phase-3 ladder result from the raw artifacts of each run.

The consistency runner writes one JSON per level; this reads those, re-derives
every VALIDATION assertion **from the reports themselves** rather than trusting
the runner's own summary, and prints the per-level stable set plus each residual
flake with the trace evidence needed to isolate it.

Usage::

    python scripts/d1_phase3_summary.py low medium high
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from d1_consistency_runner import (  # noqa: E402
    OUTPUTS,
    RESULTS_DIR,
    audit,
    read_report,
)


def _phase_events(engagement: str, skill: str) -> list[dict[str, Any]]:
    """Every methodology-phase event a skill wrote in one engagement's trace."""
    path = OUTPUTS / engagement / "trace.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                payload = json.loads(line).get("payload") or {}
            except json.JSONDecodeError:
                continue
            if payload.get("skill") == skill:
                events.append(payload)
    return events


def _level(level: str) -> None:
    path = RESULTS_DIR / f"{level}_consistency.json"
    if not path.exists():
        print(f"\n### {level.upper()} — no result file at {path}")
        return
    runs = json.loads(path.read_text(encoding="utf-8"))
    completed = [r for r in runs if r.get("engagement")]
    print(f"\n{'=' * 78}\n### {level.upper()} — N={len(runs)}\n{'=' * 78}")

    # Re-derive the audit from raw rather than trusting the stored summary.
    rederived: list[dict[str, Any]] = []
    for record in completed:
        engagement = record["engagement"]
        fresh = audit(read_report(engagement), engagement)
        rederived.append({**record, **fresh})
        agree = set(fresh["confirmed"]) == set(record.get("confirmed", []))
        print(
            f"  run {record['run']}: {engagement} "
            f"confirmed={len(fresh['confirmed'])} leads={len(fresh['leads'])} "
            f"hash_unchanged={record['admin_hash_unchanged']} "
            f"violations={len(fresh['violations'])} "
            f"rederived_matches_stored={agree}"
        )

    if not rederived:
        print("  no completed runs")
        return
    sets = [set(r["confirmed"]) for r in rederived]
    stable = set.intersection(*sets)
    flaky = set.union(*sets) - stable
    print(f"\n  STABLE across all {len(sets)} runs: {len(stable)}")
    for key in sorted(stable):
        print(f"    = {key}")
    print(f"\n  FLAKY: {len(flaky)}")
    for key in sorted(flaky):
        present = [r["run"] for r in rederived if key in set(r["confirmed"])]
        print(f"    ! {key}  -> runs {present}")

    violations = [v for r in rederived for v in r["violations"]]
    print(f"\n  VALIDATION violations (re-derived from raw): {len(violations)}")
    for violation in violations:
        print(f"    X {violation}")

    # The two classes this batch changed, per run, straight from the trace.
    for skill, phases in (
        ("xss_reflected", ("finding_emission", "emission_suppressed")),
        ("file_upload", ("branch_effect_not_witnessed", "verification")),
    ):
        print(f"\n  {skill} outcomes per run:")
        for record in rederived:
            events = _phase_events(record["engagement"], skill)
            interesting = [e for e in events if e.get("phase_name") in phases]
            print(f"    run {record['run']}: {len(events)} events")
            for event in interesting:
                summary = str(event.get("payload_summary"))[:150]
                print(f"        {event.get('phase_name')}: {summary}")

    print("\n  ARTIFACTS:")
    for record in rederived:
        engagement = record["engagement"]
        print(f"    run {record['run']}  outputs/{engagement}/report_{engagement}.json")
        print(f"              outputs/{engagement}/report_{engagement}.md")
        print(f"              outputs/{engagement}/trace.jsonl")


def main() -> int:
    levels = sys.argv[1:] or ["low"]
    for level in levels:
        _level(level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
