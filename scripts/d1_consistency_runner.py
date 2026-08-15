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
from urllib.parse import parse_qs, urlparse

import requests
from _artifact_io import write_redacted_json, write_redacted_text

from clinkz.agents import exploit
from clinkz.agents.exploit import (
    _CLASS_PARAM_NAMES,
    _CLASS_PARAM_PREDICATE_NAMES,
    _CLASS_PATH_TOKENS,
    _CLASS_PRECONDITIONS,
    _param_name_tokens,
)

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


def admin_password_hash(attempts: int = 10, delay: float = 2.0) -> str:
    """Read ``admin``'s stored hash straight from the DVWA database.

    Retried, because the read races the reset that precedes it. ``setup.php``'s
    create_db DROPS and repopulates ``users``, and the POST can return while PHP
    is still rebuilding, so a single point-in-time SELECT can legitimately see
    zero rows and kill a two-hour ladder before its first run. That is exactly
    what happened to the first HIGH attempt: empty stdout, empty stderr, and the
    same query returned the expected hash moments later.

    The retry does not weaken the damage check — it still reads the real stored
    hash, and a row that never appears is still FATAL.
    """
    last_error = ""
    for attempt in range(attempts):
        proc = subprocess.run(  # noqa: S603 — list-form, fixed argv
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
            check=False,
        )
        value = [line for line in proc.stdout.strip().splitlines() if line.strip()]
        if value:
            return value[-1].strip()
        last_error = proc.stderr.strip()[:200]
        if attempt < attempts - 1:
            time.sleep(delay)
    raise SystemExit(
        f"FATAL: could not read admin hash after {attempts} attempts "
        f"over {attempts * delay:.0f}s: {last_error!r}"
    )


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


def run_pipeline(level: str, index: int, authorization: Path) -> tuple[str | None, int, float]:
    """Run the real end-to-end pipeline; return (engagement_id, rc, seconds).

    The authorization record is a REQUIRED operator input — ``clinkz scan``
    refuses to start without one and there is no flag that skips it — so the
    harness supplies a path rather than carrying a record of its own. No
    benchmark profile: the client-safe destructive refusals stay in force, which
    is what makes the admin-password-hash damage check below mean anything.
    """
    before = newest_engagement_dirs()
    started = time.time()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "clinkz",
            "scan",
            "--target",
            DVWA_BASE,
            "--authorization",
            str(authorization),
        ],
        capture_output=True,
        text=True,
        timeout=7200,
    )
    elapsed = time.time() - started
    # Captured stdout of a whole engagement, through the engine's redaction
    # chokepoint: whatever the run printed, this file keeps.
    write_redacted_text(
        RESULTS_DIR / f"{level}_run{index}_stdout.txt",
        proc.stdout + "\n=== STDERR ===\n" + proc.stderr,
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


_STRUCTURED_EVIDENCE_TOKEN = re.compile(r"^[A-Za-z_][\w.-]*=\S*$")


def evidence_strength(evidence: list[str]) -> str:
    """The ``strength=`` value the ENGINE stamped into *evidence*, or ``""``.

    Only entries made entirely of whitespace-separated ``key=value`` tokens are
    read. A finding's evidence begins ``["Request: …", "Response: …"]``, and the
    ``Response:`` entry holds raw unescaped bytes from the target, ahead of the
    engine's own verdict line — so a bare search for ``strength=`` reads what
    the TARGET said before what the engine measured. A host echoing the literal
    ``strength=likely`` beside its reflection would otherwise fabricate an audit
    violation here, and (before the matching fix in ``exploit.py``) suppress a
    genuine finding in the engine itself.
    """
    for entry in evidence:
        tokens = entry.split()
        if not tokens or not all(_STRUCTURED_EVIDENCE_TOKEN.match(t) for t in tokens):
            continue
        for token in tokens:
            key, _, value = token.partition("=")
            if key == "strength":
                return value
    return ""


def _strip_query(url: str) -> str:
    """``scheme://host/path`` — the module's address, without its arguments.

    An empty path normalises to ``/``: an origin-level finding's target came
    back as ``http://host`` in one run and ``http://host/`` in the next, which
    split one stable finding into two flaky keys.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return url
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


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


def _names_the_class_surface(test_method: str, url: str) -> bool:
    """Does *url* carry this class's OWN vocabulary — a path token or a param?

    ``_endpoint_class_relevance`` returns grade 0 on ``param_match OR
    precondition_match``, and for the form classes the precondition is the bare
    string ``"form"``. On an application where nearly every page posts something
    — DVWA is one — that makes grade 0 mean "has a form" rather than "this
    class's surface", and every form-bearing page in the tail becomes a
    "primary target" this assertion would report as a RANKING failure.

    It did: one HIGH run reported ``_test_brute_force`` dropping
    ``/vulnerabilities/upload/#``, ``_test_csrf`` dropping
    ``/vulnerabilities/exec/#`` and ``_test_javascript_attacks`` dropping
    ``/vulnerabilities/xss_r/#`` — none of which is that class's target, and all
    three classes were dispatched to their real ones in the same run. Reporting
    ordinary tail truncation as an ordering defect is the same confusion the
    RANKING check exists to prevent, pointed the other way.

    So for a class whose preconditions include the generic ``"form"``, a grade-0
    drop must ALSO be named by that class's own vocabulary to count. Classes with
    a specific precondition (``site_root``, ``session_setter``,
    ``file_server_path``, ``xml_body``) keep the original, stricter reading —
    narrowing this check any further than the defect requires would blunt the
    assertion that caught the batch-4 weak-session and HIGH-SQLi misses.

    The drop is still returned to the caller either way, marked, so nothing is
    hidden — it just is not counted as a violation.
    """
    if "form" not in _CLASS_PRECONDITIONS.get(test_method, ()):
        return True
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    for token in _CLASS_PATH_TOKENS.get(test_method, ()):
        if token in path:
            return True
    params = list(parse_qs(parsed.query))
    names = _CLASS_PARAM_NAMES.get(test_method)
    if names:
        tokens: set[str] = set()
        for raw in params:
            tokens |= _param_name_tokens(raw)
        if tokens & names:
            return True
    # The shape predicates (id-like, file-like, url-like) are the OTHER half of
    # ``param_match`` in the engine — omitting them here would have excused a
    # genuine drop on, say, ``/vulnerabilities/sqli/?id=1``, which is the exact
    # miss this assertion was written for.
    predicate_name = _CLASS_PARAM_PREDICATE_NAMES.get(test_method)
    if predicate_name is not None:
        predicate = getattr(exploit, predicate_name)
        if any(predicate(p.lower()) for p in params):
            return True
    return False


def dropped_primary_targets(engagement: str) -> list[dict[str, Any]]:
    """Plan tasks the cap dropped ON THE CLASS'S OWN PRIMARY TARGET (grade 0).

    Read from the engagement's own trace, which records the per-class dropped
    list and the relevance grade each entry was dropped at. Grade 0 means the
    class's attack surface — a parameter of the shape it attacks, or the
    precondition it measures — was OBSERVED on that endpoint. Dropping one of
    those is the ordering failing, not the budget: it is the exact shape that
    cost D1 its weak-session and HIGH SQLi findings.

    Entries whose grade 0 came only from a generic precondition are returned
    with ``names_class_surface=False`` — see :func:`_names_the_class_surface` —
    and :func:`audit` does not count those as violations.

    Only the LAST truncation record per stage is read, and ONLY the union stage
    counts — that is the plan that actually dispatched. The deterministic stage
    is the union's *source*: it drops ~500 candidates by design, so reading it
    as the plan reports every class's tail as a coverage failure. (It reported
    exactly one such spurious violation before this was fixed.) The union stage
    always writes a record, including when it truncated nothing, so an absent
    one means the union never ran rather than that nothing was dropped.
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
    record = latest.get("union")
    if not record:
        return []
    dropped: list[dict[str, Any]] = []
    grades = record.get("dropped_grades_by_class", {})
    for klass, urls in (record.get("dropped_by_class") or {}).items():
        for url, grade in zip(urls, grades.get(klass, []), strict=False):
            if grade == 0:
                dropped.append(
                    {
                        "test_method": klass,
                        "endpoint_url": url,
                        "grade": grade,
                        "names_class_surface": _names_the_class_surface(klass, url),
                    }
                )
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
        if evidence_strength(finding.get("evidence", [])) == "likely":
            violations.append(f"likely->confirmed emitted: {finding_key(finding)}")

    # G18: a task dropped on a class's OWN primary target, for a class that then
    # emitted nothing, is the ranking failing rather than the budget.
    fired = classes_that_fired(report)
    dropped_primary = dropped_primary_targets(engagement)
    for entry in dropped_primary:
        if entry["test_method"] in fired or not entry.get("names_class_surface"):
            continue
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

    # The disclosure gate's own verdict, re-read off disk rather than taken from
    # the run's summary. A bundle that carries credential material is a failed
    # run whatever it found.
    disclosure = read_artifact_scan(engagement)
    if disclosure.get("present") and not disclosure.get("clean"):
        violations.append(
            f"ARTIFACT SCAN FAILED: {disclosure.get('findings', '?')} credential shape(s) "
            f"in the bundle"
        )
    elif not disclosure.get("present"):
        violations.append("no artifact_scan.json in the bundle — the disclosure gate did not run")

    # Every component invoked that contributed nothing. Not a violation: a
    # degraded component is a coverage fact the operator must SEE, and the run
    # is still honest about what it proved.
    ledger = report.get("component_ledger") or {}

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
        "artifact_scan": disclosure,
        "ledger_alarms": [
            f"{a.get('component')} [{a.get('kind')}]: {','.join(a.get('alarms') or [])} "
            f"(invocations={a.get('invocations')}, contributed={a.get('items_contributed')})"
            for a in (ledger.get("alarms") or [])
        ],
        "ledger_never_invoked": list(ledger.get("never_invoked") or []),
        "violations": violations,
    }


def read_artifact_scan(engagement: str) -> dict[str, Any]:
    """The disclosure gate's verdict for this bundle, read off disk.

    Read from the artifact rather than the run summary on purpose: the gate
    exists because a guarantee asserted by the logic that produced it is not
    checked at all, and a harness that took the runner's word for it would
    reintroduce exactly that.
    """
    path = OUTPUTS / engagement / "artifact_scan.json"
    if not path.is_file():
        return {"present": False}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"present": True, "clean": False, "error": str(exc)}
    # ``clean`` is a computed PROPERTY on the report model, so it is absent from
    # the serialised document; reading it with .get() returned None and reported
    # every clean bundle as a failure. Re-derive it the way the model does —
    # definite findings fail, and the entropy `suspicions` list is advisory only
    # and deliberately does not.
    findings = raw.get("findings") or []
    return {
        "present": True,
        "clean": not findings,
        "findings": len(findings),
        "suspicions": len(raw.get("suspicions") or []),
        "files_scanned": raw.get("files_scanned"),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", required=True, choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument(
        "--authorization",
        required=True,
        type=Path,
        help="Path to the authorization record JSON. `clinkz scan` refuses without one.",
    )
    args = parser.parse_args()

    if not args.authorization.is_file():
        raise SystemExit(f"FATAL: no authorization record at {args.authorization}")

    runs: list[dict[str, Any]] = []
    for index in range(1, args.runs + 1):
        print(f"\n{'=' * 78}\nRUN {index}/{args.runs}  level={args.level}\n{'=' * 78}", flush=True)
        reset_and_set_level(args.level)
        hash_before = admin_password_hash()
        print(f"  reset done; admin hash baseline recorded ({hash_before[:8]}…)", flush=True)

        engagement, rc, elapsed = run_pipeline(args.level, index, args.authorization)
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
        scan = record.get("artifact_scan") or {}
        print(
            f"  engagement={engagement} rc={rc} {record['seconds']}s "
            f"confirmed={len(record.get('confirmed', []))} "
            f"leads={len(record.get('leads', []))} "
            f"hash_unchanged={record['admin_hash_unchanged']} "
            f"artifact_scan={'clean' if scan.get('clean') else scan.get('present', 'absent')} "
            f"ledger_alarms={len(record.get('ledger_alarms', []))}",
            flush=True,
        )

    out = RESULTS_DIR / f"{args.level}_consistency.json"
    write_redacted_json(out, runs)

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

    # Degradation is reported loudly and separately. It is not a violation — a
    # component that contributed nothing did not make the run dishonest — but it
    # is the difference between "the target has no such surface" and "the thing
    # that looks for it never ran", and only one of those is a result.
    print("\n  COMPONENT DEGRADATION (invoked, contributed nothing)")
    any_alarm = False
    for record in runs:
        alarms = record.get("ledger_alarms") or []
        if alarms:
            any_alarm = True
            print(f"    run {record['run']} ({record.get('engagement')}):")
            for alarm in alarms:
                print(f"      ! {alarm}")
    if not any_alarm:
        print("    none — every invoked component contributed at least one item")

    print(f"\n  written: {out}")
    return 0 if not flaky and not violations else 1


if __name__ == "__main__":
    sys.exit(main())
