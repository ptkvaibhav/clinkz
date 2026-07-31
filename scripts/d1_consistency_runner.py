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
from urllib.parse import urlparse

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


def _strip_query(url: str) -> str:
    """``scheme://host/path`` — the module's address, without its arguments."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url


_URL_IN_TEXT = re.compile(r"https?://[^\s,)\]]+")


def module_path_key(finding: dict[str, Any]) -> str:
    """Identity for the cross-run diff: the MODULE and the PATH it fired on.

    ``title @ target`` counts a query-string difference as a different finding.
    Batch 4 measured that directly: the open-redirect module fired in all three
    LOW runs, but the crawl surfaced ``…/low.php?redirect=info.php?id=1`` in one
    run and ``?id=2`` in the others, so a stable module read as two flaky ones.
    Same handler, same bypass type, same proof — one finding.

    Query strings are dropped from the target AND from any URL embedded in the
    title (several titles carry the endpoint inline). Everything else in the
    title is kept, so the five distinct missing-header findings on one origin
    stay five keys rather than collapsing into one.
    """
    title = _URL_IN_TEXT.sub(lambda m: _strip_query(m.group()), finding.get("title", ""))
    return f"{title} @ {_strip_query(finding.get('target', ''))}"


# Which ``_test_*`` class a finding came from, read off the technique id its
# emitter stamps. Used only by the G18 assertion below, which has to ask "did
# THIS class fire?" of a report that records techniques rather than methods.
_TECHNIQUE_TO_CLASS: dict[str, str] = {
    "WSTG-INPV-05": "_test_sqli",
    "WSTG-INPV-05 (NoSQL)": "_test_nosqli",
    "WSTG-INPV-01": "_test_xss_reflected",
    "WSTG-INPV-02": "_test_xss_stored",
    "WSTG-CLNT-01": "_test_xss_dom",
    "WSTG-INPV-11": "_test_lfi",
    "WSTG-INPV-12": "_test_cmdi",
    "WSTG-INPV-07 (XXE)": "_test_xxe",
    "WSTG-INPV-18 (SSTI)": "_test_ssti",
    "WSTG-INPV-19": "_test_ssrf",
    "WSTG-INPV-19 (SSRF)": "_test_ssrf",
    "WSTG-BUSL-08": "_test_file_upload",
    "WSTG-SESS-05": "_test_csrf",
    "WSTG-SESS-02": "_test_weak_session",
    "WSTG-ATHN-03": "_test_brute_force",
    "WSTG-ATHN-09 (JWT)": "_test_jwt",
    "WSTG-ATHZ-01": "_test_lfi",
    "WSTG-ATHZ-04": "_test_idor",
    "WSTG-CLNT-04": "_test_open_redirect",
    "WSTG-CLNT-11": "_test_javascript_attacks",
    "WSTG-CONF-07": "_test_security_headers",
}

_TECHNIQUE_RE = re.compile(r"Technique:\s*(.+?)\.\s*Parameter:")


def classes_that_fired(report: dict[str, Any]) -> set[str]:
    """The ``_test_*`` classes that emitted at least one finding this run."""
    fired: set[str] = set()
    for finding in report.get("findings", []):
        match = _TECHNIQUE_RE.search(finding.get("description", ""))
        if match:
            klass = _TECHNIQUE_TO_CLASS.get(match.group(1).strip())
            if klass:
                fired.add(klass)
    return fired


def dropped_primary_targets(engagement: str) -> list[dict[str, Any]]:
    """Plan tasks the cap dropped ON THE CLASS'S OWN PRIMARY TARGET (grade 0).

    Read from the engagement's own trace, which records the per-class dropped
    list and the relevance grade each entry was dropped at. Grade 0 means the
    class's attack surface — a parameter of the shape it attacks, or the
    precondition it measures — was OBSERVED on that endpoint. Dropping one of
    those is the ordering failing, not the budget: it is the exact shape that
    cost D1 its weak-session and HIGH SQLi findings.

    Only the LAST truncation record per stage is read; the union stage is the
    plan that actually dispatched.
    """
    path = OUTPUTS / engagement / "trace.jsonl"
    if not path.exists():
        return []
    latest: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                payload = json.loads(line).get("payload") or {}
            except json.JSONDecodeError:
                continue
            if payload.get("phase_name") == "truncation":
                latest[payload.get("stage", "?")] = payload
    record = latest.get("union") or latest.get("deterministic")
    if not record:
        return []
    dropped: list[dict[str, Any]] = []
    grades = record.get("dropped_grades_by_class", {})
    for klass, urls in (record.get("dropped_by_class") or {}).items():
        for url, grade in zip(urls, grades.get(klass, []), strict=False):
            if grade == 0:
                dropped.append({"test_method": klass, "endpoint_url": url, "grade": grade})
    return dropped


def audit(report: dict[str, Any], engagement: str) -> dict[str, Any]:
    """Every VALIDATION assertion the brief asks for, evaluated from raw."""
    findings = report.get("findings", [])
    leads = report.get("unproven_leads", [])
    violations: list[str] = []

    # G17: a non-confirming strength must never carry a confirmed status. The
    # batch-4 HIGH run emitted `verified=True strength=likely` as a confirmed
    # medium; nothing weaker than a raw scan of the emitted evidence will do.
    for finding in findings:
        for line in finding.get("evidence", []):
            match = re.search(r"\bstrength=([\w-]+)", line)
            if match and match.group(1) == "likely":
                violations.append(f"likely->confirmed emitted: {finding_key(finding)}")
                break

    # G18: a task dropped on a class's OWN primary target, for a class that then
    # emitted nothing, is the ranking failing rather than the budget.
    fired = classes_that_fired(report)
    dropped_primary = dropped_primary_targets(engagement)
    for entry in dropped_primary:
        if entry["test_method"] not in fired:
            violations.append(
                f"RANKING: {entry['test_method']} primary target dropped "
                f"({entry['endpoint_url']}) and the class emitted nothing"
            )

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
        # The diff key: MODULE + PATH, so a query-string difference in the URL
        # the crawl happened to surface is not counted as a different finding.
        "confirmed": sorted(module_path_key(f) for f in findings if f.get("status") == "confirmed"),
        "confirmed_by_title_and_target": sorted(
            finding_key(f) for f in findings if f.get("status") == "confirmed"
        ),
        "all_findings": sorted(module_path_key(f) for f in findings),
        "severities": sorted(f"{module_path_key(f)} [{f.get('severity')}]" for f in findings),
        "leads": sorted(f"{lead.get('why_unconfirmed')}: {lead.get('claim')}" for lead in leads),
        "research_leads": len(report.get("research_leads", [])),
        "classes_fired": sorted(fired),
        "dropped_primary_targets": dropped_primary,
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
            record.update(audit(read_report(engagement), engagement))
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
