"""Per-module DVWA coverage across the security ladder, re-derived from raw.

The consistency runner answers "is this level's finding set stable?". This
answers the other question the ladder exists to settle: **for each module the
target actually ships, was it found at every level, at some, or at none** — and
for each hit, the evidence line that proves it.

Everything here is read back from the engagement reports on disk, never from a
runner's summary of them. The module list is enumerated from the RUNNING
container when one is reachable, so it cannot silently drift from what the image
ships; the recorded list is the fallback, and which one was used is printed.

Two rules the output obeys, both from the brief:

  * **A finding at ``impossible`` is the headline**, outranking every count in
    the run. The impossible level is the honesty control: a module that confirms
    identically at every level of a security-graded control is a phantom by
    construction, and one that confirms at impossible alone is a loophole in our
    oracle rather than a catch.
  * **``captcha`` is a documented permanent non-finding** — no reCAPTCHA keys
    are configured, so the module is not live even for a human. It is reported
    and excluded from the coverage denominator rather than counted as a miss.

Usage::

    python scripts/d1_module_matrix.py low medium high impossible
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from d1_consistency_runner import RESULTS_DIR, read_report  # noqa: E402

#: The vulnerability modules ghcr.io/digininja/dvwa ships, enumerated from the
#: running container on 2026-08-13. Used only when the container cannot be
#: reached; :func:`discover_modules` prefers the live list.
RECORDED_MODULES: tuple[str, ...] = (
    "api",
    "authbypass",
    "bac",
    "brute",
    "captcha",
    "cryptography",
    "csp",
    "csrf",
    "exec",
    "fi",
    "javascript",
    "open_redirect",
    "sqli",
    "sqli_blind",
    "upload",
    "weak_id",
    "xss_d",
    "xss_r",
    "xss_s",
)

#: Directory entries under ``vulnerabilities/`` that are not modules.
_NOT_A_MODULE = re.compile(r"\.(css|js|php)$")

#: Modules that cannot produce a finding on this instance for a reason that is
#: nothing to do with the engine. Reported, and held out of the denominator.
PERMANENT_NON_FINDINGS: dict[str, str] = {
    "captcha": (
        "no reCAPTCHA keys are configured on this instance, so the module is not "
        "live even for a human operator — there is nothing to exploit"
    ),
}

LEVELS: tuple[str, ...] = ("low", "medium", "high", "impossible")

_MODULE_IN_URL = re.compile(r"/vulnerabilities/([a-z_]+)/", re.IGNORECASE)


def discover_modules(container: str = "clinkz-dvwa") -> tuple[list[str], str]:
    """The module list, from the live container when reachable.

    Returns:
        ``(modules, source)`` where *source* is ``"container"`` or ``"recorded"``.
    """
    try:
        proc = subprocess.run(  # noqa: S603 — list-form, fixed argv
            ["docker", "exec", container, "sh", "-lc", "ls -1 /var/www/html/vulnerabilities/"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return list(RECORDED_MODULES), "recorded"
    if proc.returncode != 0:
        return list(RECORDED_MODULES), "recorded"
    found = [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip() and not _NOT_A_MODULE.search(line.strip())
    ]
    return (sorted(found), "container") if found else (list(RECORDED_MODULES), "recorded")


def module_of(text: str) -> str | None:
    """The DVWA module a URL (or a title carrying one) names."""
    match = _MODULE_IN_URL.search(text or "")
    return match.group(1).lower() if match else None


#: Titles of classes that are properties of the ORIGIN, not of a module. The
#: header methodology samples whatever URL it was pointed at, so a missing-header
#: finding reported at ``/vulnerabilities/api/`` is a fact about the site, not a
#: vulnerability in the api module. Counting it as module coverage would credit
#: this engine with finding a module it never attacked.
_ORIGIN_CLASS_TITLE = re.compile(r"^(Missing|Weak) Security Header\b", re.IGNORECASE)


def finding_module(finding: dict[str, Any]) -> str | None:
    """Which DVWA module a finding fired on, or ``None`` for an origin finding.

    Read ONLY from ``target`` / ``affected_url`` — fields the ENGINE sets. The
    earlier version also searched the description and the evidence entries, and
    evidence entries hold raw response bytes: a page that merely LINKS to
    ``/vulnerabilities/api/`` would attribute an unrelated finding to the api
    module. A coverage matrix assembled from strings the target controls is the
    target grading itself.
    """
    if _ORIGIN_CLASS_TITLE.match(str(finding.get("title") or "")):
        return None
    for field in ("target", "affected_url"):
        found = module_of(str(finding.get(field) or ""))
        if found:
            return found
    return None


def _poc_line(finding: dict[str, Any]) -> str:
    """The shortest line of this finding's own evidence that PROVES it.

    Prefers the engine's structured verdict entry (``key=value`` tokens, which is
    where the oracle records what it measured) over the raw request/response
    dump, because the raw dump is bytes the target chose.
    """
    for entry in finding.get("evidence", []) or []:
        text = str(entry)
        tokens = text.split()
        if tokens and all(re.match(r"^[A-Za-z_][\w.-]*=\S*$", t) for t in tokens):
            return text[:300]
    for entry in finding.get("evidence", []) or []:
        text = str(entry).replace("\n", " ")
        if text.startswith("Request:"):
            return text[:300]
    return (str(finding.get("description") or "").replace("\n", " "))[:300]


def load_level(level: str) -> list[dict[str, Any]]:
    """Every completed run recorded for *level*."""
    path = RESULTS_DIR / f"{level}_consistency.json"
    if not path.is_file():
        return []
    return [r for r in json.loads(path.read_text(encoding="utf-8")) if r.get("engagement")]


def per_run_modules(engagement: str) -> dict[str, list[dict[str, Any]]]:
    """``module -> [finding, ...]`` for one engagement, confirmed findings only."""
    report = read_report(engagement)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for finding in report.get("findings", []):
        module = finding_module(finding) or "_origin"
        buckets.setdefault(module, []).append(finding)
    return buckets


def main() -> int:
    levels = [a for a in sys.argv[1:] if a in LEVELS] or list(LEVELS)
    modules, source = discover_modules()
    print(f"module list source: {source} ({len(modules)} modules)")

    # level -> run index -> module -> findings
    ladder: dict[str, list[dict[str, list[dict[str, Any]]]]] = {}
    engagements: dict[str, list[str]] = {}
    for level in levels:
        runs = load_level(level)
        engagements[level] = [r["engagement"] for r in runs]
        ladder[level] = [per_run_modules(r["engagement"]) for r in runs]

    print("\n" + "=" * 100)
    print("PER-MODULE COVERAGE ACROSS THE SECURITY LADDER")
    print("=" * 100)
    header = f"{'module':<16}" + "".join(f"{lvl:>14}" for lvl in levels) + "   verdict"
    print(header)
    print("-" * 100)

    summary: dict[str, dict[str, Any]] = {}
    for module in modules:
        cells: list[str] = []
        hit_levels: list[str] = []
        for level in levels:
            runs = ladder.get(level) or []
            if not runs:
                cells.append(f"{'no data':>14}")
                continue
            hits = sum(1 for run in runs if run.get(module))
            cells.append(f"{f'{hits}/{len(runs)}':>14}")
            if hits:
                hit_levels.append(level)

        exploit_levels = [lvl for lvl in hit_levels if lvl != "impossible"]
        graded = [lvl for lvl in levels if lvl != "impossible" and ladder.get(lvl)]
        if module in PERMANENT_NON_FINDINGS:
            verdict = "N/A (documented)"
        elif "impossible" in hit_levels:
            verdict = "!! FOUND AT IMPOSSIBLE"
        elif exploit_levels and len(exploit_levels) == len(graded):
            verdict = "found at all levels"
        elif exploit_levels:
            verdict = "found at " + "/".join(exploit_levels)
        else:
            verdict = "found at none"
        summary[module] = {
            "levels_found": hit_levels,
            "verdict": verdict,
            "per_level": {
                lvl: sum(1 for run in (ladder.get(lvl) or []) if run.get(module)) for lvl in levels
            },
            "runs_per_level": {lvl: len(ladder.get(lvl) or []) for lvl in levels},
        }
        print(f"{module:<16}" + "".join(cells) + f"   {verdict}")

    # --- the headline control ------------------------------------------------
    #
    # The control is about EXPLOITATION. An origin-level configuration
    # observation ("this server sets no X-Frame-Options") is true at every
    # security level, because the level grades the vulnerable modules and not
    # the server's response headers — so counting one as a finding-at-impossible
    # would raise a loophole alarm about a fact that is simply correct. The two
    # are separated here and both are printed; only the module-scoped set can
    # indict the oracle.
    print("\n" + "=" * 100)
    print("HONESTY CONTROL — findings at security level IMPOSSIBLE")
    print("=" * 100)
    impossible_runs = ladder.get("impossible") or []
    total_impossible = 0
    origin_at_impossible = 0
    for index, run in enumerate(impossible_runs, 1):
        for module, findings in sorted(run.items()):
            if module == "_origin":
                origin_at_impossible += len(findings)
                for finding in findings:
                    print(f"  (origin, not exploitation) run {index}: {finding.get('title')}")
                continue
            for finding in findings:
                total_impossible += 1
                print(f"  !! run {index} [{module}] {finding.get('title')}")
                print(f"       {_poc_line(finding)}")
    if not impossible_runs:
        print("  no impossible-level data yet")
    elif total_impossible == 0:
        print(
            f"\n  0 EXPLOITATION findings at impossible across {len(impossible_runs)} run(s) "
            f"— the control HOLDS.\n"
            f"  ({origin_at_impossible} origin-level configuration observation(s) above: true at "
            f"every level,\n   because the security level grades the modules and not the server's "
            f"response headers.)"
        )
    else:
        print(
            f"\n  !! {total_impossible} EXPLOITATION finding(s) at impossible. Each is a "
            f"methodology loophole\n     and OUTRANKS every other number in this run."
        )

    # --- evidence for each module that was found -----------------------------
    print("\n" + "=" * 100)
    print("PROOF LINE PER MODULE FOUND (first run of the lowest level it fired at)")
    print("=" * 100)
    for module in modules:
        info = summary.get(module) or {}
        for level in info.get("levels_found") or []:
            runs = ladder.get(level) or []
            for run in runs:
                findings = run.get(module) or []
                if findings:
                    print(f"\n{module}  [{level}]  {findings[0].get('title')}")
                    print(f"  severity: {findings[0].get('severity')}")
                    print(f"  proof   : {_poc_line(findings[0])}")
                    break
            break

    # --- findings not attributable to a module -------------------------------
    print("\n" + "=" * 100)
    print("FINDINGS NOT SCOPED TO A MODULE (origin-level: headers, cookies, TLS, ...)")
    print("=" * 100)
    for level in levels:
        runs = ladder.get(level) or []
        if not runs:
            continue
        origin = runs[0].get("_origin") or []
        print(f"  {level}: {len(origin)} in run 1")
        for finding in origin:
            print(f"    - {finding.get('title')} [{finding.get('severity')}]")

    out = RESULTS_DIR / "module_matrix.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "module_list_source": source,
                "modules": modules,
                "levels": levels,
                "engagements": engagements,
                "permanent_non_findings": PERMANENT_NON_FINDINGS,
                "summary": summary,
                "impossible_findings": total_impossible,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nwritten: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
