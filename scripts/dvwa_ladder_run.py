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
from pathlib import Path
from typing import Any

from _artifact_io import write_redacted_json, write_redacted_text
from d1_consistency_runner import (
    DVWA_BASE,
    admin_password_hash,
    audit,
    module_path_key,
    newest_engagement_dirs,
    read_report,
    reset_and_set_level,
)

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


def run_pipeline(level: str, authorization: Path, benchmark: Path) -> tuple[str | None, int, float]:
    """Run the real end-to-end pipeline for one level; return (id, rc, seconds)."""
    before = newest_engagement_dirs()
    started = time.time()
    proc = subprocess.run(  # noqa: S603 — list-form, fixed argv
        [
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
        ],
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

        engagement, rc, elapsed = run_pipeline(level, args.authorization, args.benchmark)
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

    failed = verdict == "DIVERGENT" or any(r.get("violations") for r in runs)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
