"""DVWA security ladder — all four levels in one pass, header invariance as the gate.

Why this exists alongside ``d1_consistency_runner.py``. That runner repeats ONE
level and diffs the finding sets across runs; its oracle is run-to-run
reproducibility. This one walks the LADDER — low, medium, high, impossible — in a
single pass, and its primary oracle is a different and stronger claim:

    **All four levels serve byte-identical response headers, so all four levels
    must emit byte-identical header findings.**

DVWA's ``security`` cookie changes which module code runs. It does not change
Apache's or PHP's response headers: the same ``Server``, the same
``X-Powered-By``, the same nine header names at every level. WSTG-CONF-07 is a
pure function of that observed set (``_deterministic_security_headers_analysis``
— no LLM is reachable from it), so a divergence between levels cannot be a
property of the target and is a defect in the engine by construction.

That assertion replaces exploitation-set counts as the primary gate. Counts move
for honest reasons — a crawl surfaces a different endpoint, a level genuinely
patches a module — and a gate that moves for honest reasons cannot discriminate.
A byte-comparison over an input we have already proven identical can.

Secondary gates, each of which the ladder still checks per level:

  * **impossible emits zero exploitation findings** — the honesty control group.
    A confirm at ``impossible`` is a phantom by construction.
  * **admin's stored password hash is unchanged** — the run damaged nothing.
  * **zero auth-bypass findings at every level** — D8's suppression side.
  * the disclosure gate certified the bundle, and the contribution ledger's
    alarms are reported rather than summarised away.

Usage::

    python scripts/dvwa_ladder_run.py \\
        --authorization <auth.json> --benchmark-profile <bp.json>
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from _artifact_io import write_redacted_json, write_redacted_text
from d1_consistency_runner import (
    ALARM_COVERAGE_VERDICTS,
    DVWA_BASE,
    admin_password_hash,
    audit,
    module_path_key,
    newest_engagement_dirs,
    read_report,
    reset_and_set_level,
)
from regrade_stored_bundles import NO_ARM, REFUSED, SURVIVES, grade

LEVELS = ("low", "medium", "high", "impossible")
OUTPUTS = Path("outputs")
RESULTS_DIR = Path("outputs/_dvwa_ladder")

#: The two title shapes ``_test_security_headers`` emits, mapped to the row kind.
#:
#: Keyed on the TITLE rather than on ``technique``, for the unglamorous reason
#: that a rendered report finding has no ``technique`` field at all — the emitter
#: stamps ``WSTG-CONF-07`` internally and ``report_<id>.json`` does not carry it,
#: so the first version of this gate filtered on ``None`` and scored every level
#: at zero header findings while seven sat in the report. These prefixes are
#: written by ``_persist_finding``'s own f-strings, so they are as much the
#: emitter's declaration as the id would have been; a third shape appearing is a
#: change in the emitter and is surfaced rather than skipped.
_HEADER_TITLE_KINDS: dict[str, str] = {
    "Missing Security Header ": "missing",
    "Weak Security Header ": "weak",
}


def _header_row(finding: dict[str, Any]) -> str | None:
    """``"<missing|weak> <Header> [<severity>]"``, or ``None`` if not a header row."""
    title = finding.get("title", "")
    for prefix, kind in _HEADER_TITLE_KINDS.items():
        if title.startswith(prefix):
            header = title[len(prefix) :].split(" on ")[0].strip()
            return f"{kind} {header} [{finding.get('severity')}]"
    if "Security Header" in title:  # a shape this gate does not know
        return f"UNRECOGNISED-TITLE-SHAPE {title} [{finding.get('severity')}]"
    return None


def header_set(report: dict[str, Any]) -> list[str]:
    """This level's header findings, normalised for a byte-comparison.

    The origin is dropped: it is the same host at every level by construction,
    and leaving it in would make the comparison sensitive to which URL the crawl
    happened to reach first rather than to the header evaluation.

    Sorted, because the assertion is about the SET the evaluator produced, and
    emission order is a function of dict iteration over the observed headers.
    """
    return sorted(row for f in report.get("findings", []) if (row := _header_row(f)))


def exploitation_findings(report: dict[str, Any]) -> list[str]:
    """Confirmed findings that are not posture assessments.

    The "impossible emits zero" gate is about EXPLOITATION, and a missing
    ``X-Frame-Options`` is as true at impossible as at low — counting it would
    make the control group fail for the one reason that is not a phantom.
    """
    return sorted(
        module_path_key(f)
        for f in report.get("findings", [])
        if f.get("status") == "confirmed" and _header_row(f) is None
    )


def auth_bypass_findings(report: dict[str, Any]) -> list[str]:
    """Every auth-bypass emission. Expected empty at every level."""
    return sorted(
        module_path_key(f)
        for f in report.get("findings", [])
        if "authentication bypass" in str(f.get("title", "")).lower()
        or "auth bypass" in str(f.get("title", "")).lower()
    )


def control_survival(report: dict[str, Any], level: str) -> dict[str, Any]:
    """Grade every confirmed finding against the control arm it actually carried.

    This is the gate the ladder gained when the never-sent control shipped, and
    it is the reason re-running the ladder is a MEASUREMENT rather than a
    repetition. Every stored bundle predates the arm, so the offline re-grade
    scores every marker-oracle finding ``NO_ARM`` — "the question was never
    asked". That is a true statement about the record and a vacuous one about
    the engine: it cannot distinguish a finding that would survive its control
    from one the control would refuse.

    A run made under the current gate dispatches real arms, so each finding here
    comes back ``SURVIVES`` (the arm refused, as it must) or ``REFUSED`` (the arm
    did not — a phantom that has been sitting in the record). ``NO_ARM``
    surviving a fresh run is itself a defect: it means a marker-bound class
    emitted without dispatching the control ``_persist_finding`` demands.

    Graded per CLASS, because the class is the granularity at which "this oracle
    matches a string in a body" is true, and per LEVEL, because DVWA's ladder is
    the one place a phantom is cheap to spot: a finding that confirms identically
    at every level of a security-graded control is a phantom by construction.
    """
    rows = [grade(level, f) for f in report.get("findings", []) if f.get("status") == "confirmed"]
    per_class: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        per_class[row.test_method or "(unrecognised)"][row.verdict] += 1
    return {
        "confirmed_graded": len(rows),
        "survives": sum(1 for r in rows if r.verdict == SURVIVES),
        "no_arm": sum(1 for r in rows if r.verdict == NO_ARM),
        "refused": sum(1 for r in rows if r.verdict == REFUSED),
        "per_class": {
            cls: {
                "n": sum(counts.values()),
                SURVIVES: counts[SURVIVES],
                NO_ARM: counts[NO_ARM],
                REFUSED: counts[REFUSED],
            }
            for cls, counts in sorted(per_class.items())
        },
        # The two verdicts that need a human: a phantom, and a class that
        # emitted without the arm the live gate is supposed to require.
        "refused_detail": [
            {"title": r.title, "target": r.target, "class": r.test_method, "why": r.detail}
            for r in rows
            if r.verdict == REFUSED
        ],
        "no_arm_detail": [
            {"title": r.title, "target": r.target, "class": r.test_method, "why": r.detail}
            for r in rows
            if r.verdict == NO_ARM
        ],
    }


def observed_headers(engagement: str) -> dict[str, Any]:
    """The ORIGIN ROOT's header set, as phase 2 captured it.

    The gate's premise is that all four levels observed the same headers, and a
    premise is an observation rather than an assumption — if two levels genuinely
    served different headers then identical findings would be the defect, and
    this is the only field that can say so.

    Which observation, though, is the whole question. Phase 2 runs per page and a
    run makes 1-24 of them, so "the last one in the trace" is a function of crawl
    order: low ended on ``/setup.php`` (9 headers) and high on ``/phpinfo.php``
    (10 — phpinfo is chunked, so Apache adds ``Transfer-Encoding``). Reported that
    way the premise looked broken while the target was completely consistent.

    A header finding is addressed to the ORIGIN — that is what rule 4 of the gate
    means by reporting a header missing for the origin when only a deep page sets
    it — so the origin ROOT is the observation the findings are about, and the
    per-page sets are recorded alongside rather than collapsed into it.
    """
    trace = OUTPUTS / engagement / "trace.jsonl"
    if not trace.is_file():
        return {}
    seen: list[tuple[str, dict[str, str]]] = []
    for line in trace.read_text(encoding="utf-8", errors="replace").splitlines():
        if "security_headers" not in line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = event.get("payload") or {}
        if payload.get("skill") != "security_headers" or payload.get("phase_number") != 2:
            continue
        headers = payload.get("headers")
        if isinstance(headers, dict) and headers:
            seen.append(
                (payload.get("url", ""), {str(k).lower(): str(v) for k, v in headers.items()})
            )
    if not seen:
        return {}

    def is_root(url: str) -> bool:
        from urllib.parse import urlparse

        return urlparse(url).path in ("", "/")

    url, headers = next((o for o in seen if is_root(o[0])), seen[0])
    return {
        "url": url,
        "is_origin_root": is_root(url),
        "header_names": sorted(headers),
        "server": headers.get("server", ""),
        "x_powered_by": headers.get("x-powered-by", ""),
        "pages_observed": len(seen),
    }


def run_pipeline(
    level: str,
    authorization: Path,
    benchmark: Path,
    *,
    scope: Path | None = None,
    token_cap: int | None = None,
) -> tuple[str | None, int, float]:
    """Run the real end-to-end pipeline for one level; return (id, rc, seconds).

    ``scope`` carries the :class:`EngagementWindow`. It is a scope-file field
    rather than an authorization-record one, so a ladder that passes only
    ``--authorization`` runs unbounded in time and the report says so — which is
    the honest rendering of an undeclared window, not a substitute for one.

    ``token_cap`` bounds the LLM spend and HALTS THE RUN CLEANLY at the cap with
    its report still written, so a bound that bites is a shorter engagement
    rather than a lost one.
    """
    before = newest_engagement_dirs()
    started = time.time()
    argv = [
        sys.executable,
        "-m",
        "clinkz",
        "scan",
        "--target",
        DVWA_BASE,
        "--authorization",
        str(authorization),
        "--benchmark-profile",
        str(benchmark),
    ]
    if scope is not None:
        argv += ["--scope", str(scope)]
    if token_cap:
        argv += ["--token-cap", str(token_cap)]
    proc = subprocess.run(  # noqa: S603 — list-form, fixed argv
        argv,
        capture_output=True,
        text=True,
        timeout=7200,
        env={**os.environ},
    )
    elapsed = time.time() - started
    write_redacted_text(
        RESULTS_DIR / f"{level}_stdout.txt",
        proc.stdout + "\n=== STDERR ===\n" + proc.stderr,
    )
    new = newest_engagement_dirs() - before
    engagement = max(new, key=lambda n: (OUTPUTS / n).stat().st_mtime) if new else None
    return engagement, proc.returncode, elapsed


def grade_engagement(level: str, engagement: str, **extra: Any) -> dict[str, Any]:
    """Every per-level fact the gates need, read from one finished engagement.

    Split out from the run loop so a completed ladder can be re-graded from the
    bundles on disk. That is not a convenience: the reports ARE the primary
    artifact, and a defect in this file's extraction must be fixable without
    spending another three hours against the target to re-derive numbers the
    reports already hold.
    """
    report = read_report(engagement)
    record: dict[str, Any] = {"level": level, "engagement": engagement, **extra}
    record.update(audit(report, engagement))
    record["header_set"] = header_set(report)
    record["exploitation"] = exploitation_findings(report)
    record["auth_bypass"] = auth_bypass_findings(report)
    record["control"] = control_survival(report, level)
    # A non-SURVIVES verdict on a FRESH bundle is a defect rather than a fact
    # about the record's age: the live gate dispatches the arm, so REFUSED means
    # a phantom reached a report and NO_ARM means a marker-bound class emitted
    # without one. Recorded as violations here, where every other per-level fact
    # is derived, so the secondary-gate counts are not stale by the time they
    # print and the `--regrade` path gets them for free.
    for row in record["control"]["refused_detail"]:
        record.setdefault("violations", []).append(
            f"CONTROL REFUSED (phantom): {row['title']} @ {row['target']} — {row['why']}"
        )
    for row in record["control"]["no_arm_detail"]:
        record.setdefault("violations", []).append(
            f"CONTROL MISSING: {row['title']} @ {row['target']} — marker-bound class "
            f"({row['class']}) emitted without dispatching its arm"
        )
    record["observed_headers"] = observed_headers(engagement)
    record["total_findings"] = len(report.get("findings", []))
    record["by_severity"] = {
        sev: sum(1 for f in report.get("findings", []) if f.get("severity") == sev)
        for sev in ("critical", "high", "medium", "low", "info")
    }
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--benchmark-profile", type=Path, dest="benchmark")
    parser.add_argument(
        "--scope",
        type=Path,
        help=(
            "Scope file carrying the EngagementWindow. Without one the run is "
            "unbounded in time and the report renders that fact."
        ),
    )
    parser.add_argument(
        "--token-cap",
        type=int,
        dest="token_cap",
        help="Per-level LLM token ceiling. Halts cleanly at the cap; report still written.",
    )
    parser.add_argument(
        "--levels",
        nargs="+",
        default=list(LEVELS),
        choices=list(LEVELS),
        help="Levels to walk, in order. Defaults to the full ladder.",
    )
    parser.add_argument(
        "--regrade",
        nargs="+",
        metavar="LEVEL=ENGAGEMENT",
        help=(
            "Re-grade finished engagements from their bundles instead of running "
            "anything. Sends nothing and starts no container."
        ),
    )
    args = parser.parse_args()

    if args.regrade:
        runs = []
        for pair in args.regrade:
            level, _, engagement = pair.partition("=")
            if not engagement:
                raise SystemExit(f"FATAL: --regrade wants LEVEL=ENGAGEMENT, got {pair!r}")
            runs.append(grade_engagement(level, engagement, returncode=None, seconds=None))
        return report_gates(runs, write=False)

    if not args.authorization or not args.benchmark:
        raise SystemExit("FATAL: --authorization and --benchmark-profile are required")
    for path in (args.authorization, args.benchmark):
        if not path.is_file():
            raise SystemExit(f"FATAL: no such file: {path}")

    runs: list[dict[str, Any]] = []
    for level in args.levels:
        print(f"\n{'=' * 78}\nLEVEL {level}\n{'=' * 78}", flush=True)
        reset_and_set_level(level)
        hash_before = admin_password_hash()
        print(f"  level pinned; admin hash baseline {hash_before[:10]}…", flush=True)

        engagement, rc, elapsed = run_pipeline(
            level,
            args.authorization,
            args.benchmark,
            scope=args.scope,
            token_cap=args.token_cap,
        )
        hash_after = admin_password_hash()

        record: dict[str, Any] = {
            "level": level,
            "engagement": engagement,
            "returncode": rc,
            "seconds": round(elapsed, 1),
            "admin_hash_unchanged": hash_after == hash_before,
        }
        if engagement is None:
            record["error"] = "no engagement directory was produced"
        else:
            record.update(grade_engagement(level, engagement))
        if not record["admin_hash_unchanged"]:
            record.setdefault("violations", []).append(
                "TARGET DAMAGED: admin password hash changed during the run"
            )
        runs.append(record)
        print(
            f"  engagement={engagement} rc={rc} {record['seconds']}s "
            f"headers={len(record.get('header_set', []))} "
            f"exploitation={len(record.get('exploitation', []))} "
            f"auth_bypass={len(record.get('auth_bypass', []))} "
            f"hash_unchanged={record['admin_hash_unchanged']} "
            f"ledger_alarms={len(record.get('ledger_alarms', []))}",
            flush=True,
        )

    return report_gates(runs, write=True)


def report_gates(runs: list[dict[str, Any]], *, write: bool) -> int:
    """Print the primary and secondary gates over a graded ladder."""
    if write:
        write_redacted_json(RESULTS_DIR / "ladder.json", runs)

    # --- the primary gate ---------------------------------------------------
    completed = [r for r in runs if r.get("engagement")]
    print(f"\n{'=' * 78}\nHEADER INVARIANCE — the primary gate\n{'=' * 78}")
    for record in completed:
        print(f"\n  {record['level']}  ({len(record['header_set'])} header findings)")
        for row in record["header_set"]:
            print(f"    {row}")
        obs = record.get("observed_headers") or {}
        if obs:
            print(
                f"    [origin root {obs.get('url')}: "
                f"{len(obs.get('header_names', []))} headers "
                f"({', '.join(obs.get('header_names', []))}), "
                f"server={obs.get('server')!r}, x-powered-by={obs.get('x_powered_by')!r}; "
                f"{obs.get('pages_observed')} pages observed in all]"
            )

    # The premise, asserted rather than assumed: the findings can only be
    # required to match if the observation they are a function of matched.
    roots = {r["level"]: (r.get("observed_headers") or {}).get("header_names") for r in completed}
    distinct = {tuple(v or []) for v in roots.values()}
    print(
        f"\n  PREMISE: origin-root header sets are "
        f"{'IDENTICAL' if len(distinct) == 1 else 'DIVERGENT'} across {len(completed)} levels"
    )

    verdict = "IDENTICAL"
    if len(completed) < 2:
        verdict = "NOT ASSERTABLE (fewer than two levels completed)"
    else:
        baseline = completed[0]
        for record in completed[1:]:
            if record["header_set"] == baseline["header_set"]:
                continue
            verdict = "DIVERGENT"
            only_base = sorted(set(baseline["header_set"]) - set(record["header_set"]))
            only_this = sorted(set(record["header_set"]) - set(baseline["header_set"]))
            print(f"\n  DIVERGENCE {baseline['level']} vs {record['level']}:")
            for row in only_base:
                print(f"    only in {baseline['level']}: {row}")
            for row in only_this:
                print(f"    only in {record['level']}: {row}")
    print(f"\n  VERDICT: header findings are {verdict} across {len(completed)} levels")

    # --- secondary gates ----------------------------------------------------
    print(f"\n{'=' * 78}\nSECONDARY GATES\n{'=' * 78}")
    for record in completed:
        impossible_clean = (
            "n/a" if record["level"] != "impossible" else str(not record["exploitation"])
        )
        print(
            f"  {record['level']:<11} rc={record.get('returncode')} "
            f"hash_unchanged={record.get('admin_hash_unchanged')} "
            f"auth_bypass={len(record['auth_bypass'])} "
            f"exploitation={len(record['exploitation'])} "
            f"impossible_zero={impossible_clean} "
            f"violations={len(record.get('violations', []))}"
        )
        for alarm in record.get("ledger_alarms", []):
            print(f"      ledger: {alarm}")
        for violation in record.get("violations", []):
            print(f"      VIOLATION: {violation}")

    # --- control survival ----------------------------------------------------
    # The gate the ladder gained with the never-sent control. On a stored bundle
    # every marker-oracle finding grades NO_ARM because the arm did not exist
    # when it ran; on a run made under the current gate the arm was dispatched,
    # so each finding resolves to SURVIVES or REFUSED and the table finally says
    # something. Both non-SURVIVES verdicts are defects HERE and are counted:
    # REFUSED is a phantom that reached a report, and NO_ARM is a marker-bound
    # class that emitted without the control `_persist_finding` demands.
    print(f"\n{'=' * 78}")
    print("CONTROL SURVIVAL — would each finding survive its own control?")
    print("=" * 78)
    header = f"  {'level':<11} {'class':<28} {'n':>3} {'SURVIVES':>9} {'NO_ARM':>7} {'REFUSED':>8}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for record in completed:
        control = record.get("control") or {}
        per_class = control.get("per_class") or {}
        if not per_class:
            print(f"  {record['level']:<11} (no confirmed findings to grade)")
            continue
        for cls, counts in per_class.items():
            print(
                f"  {record['level']:<11} {cls:<28} {counts['n']:>3} "
                f"{counts[SURVIVES]:>9} {counts[NO_ARM]:>7} {counts[REFUSED]:>8}"
            )
        print(
            f"  {record['level']:<11} {'— level total —':<28} "
            f"{control['confirmed_graded']:>3} {control['survives']:>9} "
            f"{control['no_arm']:>7} {control['refused']:>8}"
        )

    for record in completed:
        control = record.get("control") or {}
        for row in control.get("refused_detail", []):
            print(f"\n  PHANTOM [{record['level']}] {row['title']} @ {row['target']}")
            print(f"      class={row['class']}  {row['why']}")
        for row in control.get("no_arm_detail", []):
            print(f"\n  NO ARM  [{record['level']}] {row['title']} @ {row['target']}")
            print(f"      class={row['class']}  {row['why']}")

    # --- class coverage ------------------------------------------------------
    # Every dispatchable class accounted for, per level. Ranking inversions
    # answer "was the order right among the tasks that existed"; this answers
    # the question that outlives them — did the class run at all, and if not,
    # was that correct or a hole.
    print(f"\n{'=' * 78}")
    print("CLASS COVERAGE — did every applicable class reach an endpoint?")
    print("=" * 78)
    for record in completed:
        coverage = record.get("class_coverage") or {}
        if not coverage:
            print(f"  {record['level']:<11} (no coverage account — no trace on disk)")
            continue
        print(
            f"\n  {record['level']}: {coverage['reached_an_endpoint']}"
            f"/{coverage['classes_accounted']} classes reached an endpoint"
            + ("" if coverage.get("kept_breakdown_present") else "  [trace has no kept_by_class]")
        )
        for verdict, classes in sorted((coverage.get("by_verdict") or {}).items()):
            marker = "ALARM " if verdict in ALARM_COVERAGE_VERDICTS else "      "
            print(f"    {marker}{verdict} ({len(classes)}): {', '.join(classes)}")
        for alarm in coverage.get("alarms", []):
            print(f"      COVERAGE ALARM: {alarm}")

    failed = verdict == "DIVERGENT" or any(r.get("violations") for r in runs)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
