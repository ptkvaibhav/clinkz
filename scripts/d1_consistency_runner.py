"""D1 Phase-3 consistency runner — repeat the pipeline and diff the finding sets.

A deterministic skill is a CONTRACT: if the vulnerability is present and the
skill runs, it MUST be found. So the oracle here is a **diff across runs**, not a
judgement — a module present in some runs and absent in others is a defect even
when the totals match.

Per run, in order:

  1. pin the security level by recreating the container (DVWA seeds a session's
     cookie from ``DEFAULT_SECURITY_LEVEL``, and the engagement authenticates in
     its own session) and reset the data rows via ``setup.php`` create_db, so
     every run starts from the same level AND the same state,
  2. verify a FRESH session sees that level — the same thing the engagement sees,
  3. record ``admin``'s password hash as this run's baseline,
  4. run the real end-to-end pipeline (``clinkz scan``),
  5. re-read the hash and assert it is UNCHANGED — a run that damaged the target
     is disqualified whatever it found,
  6. collect the confirmed-finding set, the leads, and the FP annotations.

Usage::

    python scripts/d1_consistency_runner.py --level low --runs 3
    python scripts/d1_consistency_runner.py --level high --runs 1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests

DVWA_BASE = "http://localhost:8080"
DVWA_DB_CONTAINER = "clinkz-dvwa-db"
OUTPUTS = Path("outputs")
RESULTS_DIR = Path("outputs/_d1_consistency")


# ---------------------------------------------------------------------------
# Target state: reset, level, and the damage check
# ---------------------------------------------------------------------------


def _token(body: str) -> str | None:
    match = re.search(r"user_token'\s*value='([^']+)'", body) or re.search(
        r'name="user_token"\s+value="([^"]+)"', body
    )
    return match.group(1) if match else None


def reset_and_set_level(level: str) -> None:
    """Reset DVWA to a known level AND a known data state.

    The level is a container-level property, not a session one: DVWA seeds each
    new session's ``security`` cookie from ``DEFAULT_SECURITY_LEVEL`` on first
    page load, and the pipeline authenticates in its own session. Setting the
    cookie from here would pin OUR session and leave the engagement's at the
    container default — so the level switch is a forced recreate, exactly as
    ``docker/docker-compose.yml`` documents.
    """
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker/docker-compose.yml",
            "up",
            "-d",
            "--force-recreate",
            "dvwa",
        ],
        env={**os.environ, "DVWA_SECURITY_LEVEL": level},
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )

    # Wait for the recreated container to serve, then reset the data rows so
    # every run starts from the same guestbook/users state.
    for _ in range(60):
        try:
            if requests.get(f"{DVWA_BASE}/login.php", timeout=5).status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    else:
        raise SystemExit("FATAL: DVWA did not come back up after the level switch")

    session = requests.Session()
    session.post(
        f"{DVWA_BASE}/setup.php",
        data={"create_db": "Create / Reset Database"},
        timeout=120,
    )
    body = session.get(f"{DVWA_BASE}/login.php", timeout=30).text
    data = {"username": "admin", "password": "password", "Login": "Login"}
    if (tok := _token(body)) is not None:
        data["user_token"] = tok
    session.post(f"{DVWA_BASE}/login.php", data=data, timeout=30)

    # Verify the level actually took, in a FRESH session — the same thing the
    # engagement will see.
    probe = requests.Session()
    probe.get(f"{DVWA_BASE}/login.php", timeout=30)
    actual = probe.cookies.get("security")
    if actual != level:
        raise SystemExit(f"FATAL: a fresh session sees security={actual!r}, wanted {level!r}")


def admin_password_hash() -> str:
    """Read ``admin``'s stored hash straight from the DVWA database."""
    proc = subprocess.run(
        [
            "docker",
            "exec",
            DVWA_DB_CONTAINER,
            "mysql",
            "-udvwa",
            "-pp@ssw0rd",
            "-N",
            "-B",
            "-e",
            "SELECT password FROM dvwa.users WHERE user='admin';",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    value = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    if not value:
        raise SystemExit(f"FATAL: could not read admin hash: {proc.stderr.strip()[:200]}")
    return value[-1].strip()


# ---------------------------------------------------------------------------
# The pipeline run
# ---------------------------------------------------------------------------


def newest_engagement_dirs() -> set[str]:
    """Engagement directories only — a dir is one when it holds its own report.

    The runner writes its results under ``outputs/`` too, so "any new directory"
    would pick up the harness's own output as the engagement.
    """
    if not OUTPUTS.exists():
        return set()
    return {
        p.name for p in OUTPUTS.iterdir() if p.is_dir() and (p / f"report_{p.name}.json").is_file()
    }


def run_pipeline(level: str, index: int) -> tuple[str | None, int, float]:
    """Run the real end-to-end pipeline; return (engagement_id, rc, seconds)."""
    before = newest_engagement_dirs()
    started = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "clinkz", "scan", "--target", DVWA_BASE],
        capture_output=True,
        text=True,
        timeout=7200,
    )
    elapsed = time.time() - started
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{level}_run{index}_stdout.txt").write_text(
        proc.stdout + "\n=== STDERR ===\n" + proc.stderr, encoding="utf-8", errors="replace"
    )
    new = newest_engagement_dirs() - before
    engagement = None
    if new:
        engagement = max(new, key=lambda name: (OUTPUTS / name).stat().st_mtime)
    return engagement, proc.returncode, elapsed


# ---------------------------------------------------------------------------
# Raw assertions over the report
# ---------------------------------------------------------------------------

_FP_MARKERS = (
    "false positive",
    "false-positive",
    "likely fp",
    "suspected fp",
    "possible false",
)


def read_report(engagement: str) -> dict[str, Any]:
    path = OUTPUTS / engagement / f"report_{engagement}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def finding_key(finding: dict[str, Any]) -> str:
    """Identity of a finding for the cross-run diff: title + target."""
    return f"{finding.get('title', '')} @ {finding.get('target', '')}"


def audit(report: dict[str, Any]) -> dict[str, Any]:
    """Every VALIDATION assertion the brief asks for, evaluated from raw."""
    findings = report.get("findings", [])
    leads = report.get("unproven_leads", [])
    violations: list[str] = []

    for finding in findings:
        blob = " ".join(
            [finding.get("title", ""), finding.get("description", "")]
            + list(finding.get("evidence", []))
        ).lower()
        for marker in _FP_MARKERS:
            if marker in blob:
                violations.append(f"FP-annotated finding emitted: {finding_key(finding)}")
                break
        # An observation that only restates its own rationale is a mechanism
        # description; it must never reach `findings`.
        rationale = ""
        response = ""
        for line in finding.get("evidence", []):
            if line.startswith("rationale="):
                rationale = line[len("rationale=") :].strip()
            elif line.startswith("Response: "):
                response = line[len("Response: ") :]
        if len(rationale) >= 120 and rationale[:120] in response:
            violations.append(f"evidence restates its own rationale: {finding_key(finding)}")

    for lead in leads:
        why = lead.get("why_unconfirmed", "")
        missing = lead.get("missing_observation", "")
        if why == "suspected_false_positive_no_deterministic_signal":
            violations.append(f"demotion names no deterministic contradiction: {lead.get('claim')}")
        if not missing.strip():
            violations.append(f"demotion states no missing observation: {lead.get('claim')}")

    return {
        "confirmed": sorted(finding_key(f) for f in findings if f.get("status") == "confirmed"),
        "all_findings": sorted(finding_key(f) for f in findings),
        "severities": sorted(f"{finding_key(f)} [{f.get('severity')}]" for f in findings),
        "leads": sorted(f"{lead.get('why_unconfirmed')}: {lead.get('claim')}" for lead in leads),
        "research_leads": len(report.get("research_leads", [])),
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", required=True, choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    runs: list[dict[str, Any]] = []
    for index in range(1, args.runs + 1):
        print(f"\n{'=' * 78}\nRUN {index}/{args.runs}  level={args.level}\n{'=' * 78}", flush=True)
        reset_and_set_level(args.level)
        hash_before = admin_password_hash()
        print(f"  reset done; admin hash baseline recorded ({hash_before[:8]}…)", flush=True)

        engagement, rc, elapsed = run_pipeline(args.level, index)
        hash_after = admin_password_hash()
        damaged = hash_after != hash_before

        record: dict[str, Any] = {
            "run": index,
            "level": args.level,
            "engagement": engagement,
            "returncode": rc,
            "seconds": round(elapsed, 1),
            "admin_hash_unchanged": not damaged,
        }
        if engagement is None:
            record["error"] = "no engagement directory was produced"
        else:
            record.update(audit(read_report(engagement)))
        if damaged:
            record.setdefault("violations", []).append(
                "TARGET DAMAGED: admin password hash changed during the run"
            )
        runs.append(record)
        print(
            f"  engagement={engagement} rc={rc} {record['seconds']}s "
            f"confirmed={len(record.get('confirmed', []))} "
            f"leads={len(record.get('leads', []))} "
            f"hash_unchanged={record['admin_hash_unchanged']}",
            flush=True,
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"{args.level}_consistency.json"
    out.write_text(json.dumps(runs, indent=2), encoding="utf-8")

    # --- the cross-run diff ------------------------------------------------
    print(f"\n{'=' * 78}\nCONSISTENCY — level={args.level}, N={len(runs)}\n{'=' * 78}")
    sets = [set(r.get("confirmed", [])) for r in runs if r.get("engagement")]
    if not sets:
        print("no completed runs")
        return 1
    stable = set.intersection(*sets)
    everything = set.union(*sets)
    flaky = everything - stable
    for record in runs:
        print(
            f"  run {record['run']}: {record.get('engagement')} "
            f"confirmed={len(record.get('confirmed', []))} "
            f"hash_unchanged={record['admin_hash_unchanged']} "
            f"violations={len(record.get('violations', []))}"
        )
    print(f"\n  STABLE across all {len(sets)} runs: {len(stable)}")
    for key in sorted(stable):
        print(f"    = {key}")
    print(f"\n  FLAKY (present in some runs, absent in others): {len(flaky)}")
    for key in sorted(flaky):
        present = [r["run"] for r in runs if key in set(r.get("confirmed", []))]
        print(f"    ! {key}  -> present in runs {present}")
    violations = [v for r in runs for v in r.get("violations", [])]
    print(f"\n  VALIDATION violations across all runs: {len(violations)}")
    for violation in violations:
        print(f"    X {violation}")
    print(f"\n  written: {out}")
    return 0 if not flaky and not violations else 1


if __name__ == "__main__":
    sys.exit(main())
