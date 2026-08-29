"""N identical Juice Shop benchmark runs, and the two guards that make them a measurement.

The variance envelope exists to answer one question — *how much does this engine's
result move between identical runs?* — and it can only answer it out of runs that
actually happened. The 2026-08-25 envelope did not: run 1 (``9317e813``)
dispatched 188 methodology tasks, and runs 2 (``f7dbe627``) and 3 (``2e21a200``)
dispatched **zero**, because the Anthropic account ran out of credit partway
through the batch. Two of the three bundles are void, and neither says so where a
reader would look: ``2e21a200``'s ``provider_degradation`` block reports
``provider_degraded: false, baseline_eligible: true`` while its own
``model_stamp`` records that nothing served recon, scan **or** exploit.

Worse, the void run was then folded into the benchmark floor. A run whose LLM
providers are exhausted dispatches nothing, which is indistinguishable — from the
harness's position — from the zero-dispatch run that DEFINES the floor. So the
"what authenticating and crawling trip on their own" baseline that
``solved_by_testing`` is measured against was taken from a run in which three
phases were dead.

Both guards below are about that hour, and neither is a heuristic:

**Before the batch — a terminal account state stops it.**
:func:`~clinkz.llm.providers.preflight_providers` already spends one cheap call
per detected key and classifies the answer;
:class:`~clinkz.llm.providers.ProviderAccountError` — a depleted credit balance
or a revoked key — comes back as ``KeyStatus.INVALID``, which is what
``primary_usable`` is False on. That condition is a property of the ACCOUNT: it
will hold for the second run and the third. The Orchestrator logs it and carries
on, which is right for a single engagement an operator is watching and wrong for
an unattended batch, so the batch refuses to start. Nothing new is probed here —
the vocabulary exists, and a second probe would be a second thing to keep in
step.

**After each run — an outage means the run is not recorded, and the batch stops.**
``model_stamp`` is the witness that survives into a stored bundle: it is written
from the trace at the moment a dispatch raises, whether or not a degradation
register was installed to catch it. A run whose stamp names an unserved stage is
excluded from the envelope entirely rather than recorded with a caveat — an
average over one real run and two dead ones is not a wider envelope, it is a
wrong number — and the batch aborts, because the account condition that produced
it does not clear between runs.

**A bundle with no stamp is excluded too, and that is the same guard, not a
stricter one.** The guard used to read ``exhausted_stages(report.get(...) or [])``
and an absent stamp came back as the empty list — indistinguishable from a run
every stage of which was served, and produced by exactly the outage the guard
watches for. :func:`~clinkz.llm.degradation.stamp_exhaustion` returns ``None``
there instead, and ``None`` is void.

Usage::

    python scripts/three_run_envelope.py \\
        --authorization <auth.json> --benchmark-profile <bp.json> \\
        --creds <creds.json> [--scope <scope.json>] [--runs 3]

Exit codes mirror the CLI's contract:
``0`` every run recorded · ``1`` a recorded run exited non-zero · ``2`` bad input ·
``3`` refused before testing (terminal account state, nothing sent) ·
``4`` aborted mid-batch — a run's model stamp reported an unserved stage, its
bundle carries no stamp to read, or it produced no bundle at all. All three
stop the batch: the conditions that cause them
(a depleted account, a dirty scoreboard) hold for the next run too, and "2 of 3
attempted, and here is why" is a legible artifact where a silently missing third
run is not.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _artifact_io import redacted, write_redacted_json, write_redacted_text  # noqa: E402
from d1_consistency_runner import OUTPUTS, newest_engagement_dirs, read_report  # noqa: E402
from juiceshop_benchmark_run import RESULTS_DIR  # noqa: E402

from clinkz.llm.degradation import stamp_exhaustion  # noqa: E402
from clinkz.llm.providers import KeyStatus, ProviderPreflight, preflight_providers  # noqa: E402

#: Where each run's preserved artifacts and the envelope summary land. The
#: benchmark harness overwrites ``reconciliation.json`` and
#: ``scoreboard_after.json`` on every run — that is how run 1's scoreboard
#: snapshot was lost — so the envelope keeps its own copy per run.
ENVELOPE_DIR = RESULTS_DIR / "envelope"

#: Artifacts copied out of the shared results directory after each run. Re-read
#: and re-written through the redaction chokepoint rather than copied, so there
#: is one write path in this file and the driver-write guard can see it.
PRESERVED_JSON = ("reconciliation.json", "scoreboard_after.json", "scoreboard_before.json")
PRESERVED_TEXT = ("engagement_stdout.txt",)

#: Numbers compared across recorded runs. Each is read from the run's own
#: reconciliation rather than recomputed here: two readers of one fact drift.
ENVELOPE_METRICS = (
    "solved_total",
    "solved_by_testing_count",
    "methodology_dispatches",
    "findings_emitted",
)


def preflight_gate() -> tuple[ProviderPreflight | None, str]:
    """Guard 1. Spend one probe per key; report a terminal account state.

    Returns:
        ``(preflight, refusal)``. *refusal* is empty when the batch may start.
        A preflight of ``None`` with a refusal means the probe itself could not
        run — no key at all, which is also a reason not to start.
    """
    try:
        preflight = asyncio.run(preflight_providers())
    except Exception as exc:  # noqa: BLE001 — every outcome here is a refusal reason
        return None, f"provider pre-flight could not run: {type(exc).__name__}: {exc}"

    if preflight.primary_usable:
        return preflight, ""

    refused = [v for v in preflight.validations if v.provider == preflight.primary and not v.passed]
    detail = "; ".join(v.describe() for v in refused) or "no validation recorded"
    if preflight.primary not in preflight.available:
        return preflight, (
            f"the priority-1 provider {preflight.primary!r} has no key in this "
            f"environment (available: {sorted(preflight.available) or 'none'})"
        )
    status = refused[0].status if refused else KeyStatus.UNKNOWN
    return preflight, (
        f"the priority-1 provider {preflight.primary!r} answered {status.value} — {detail}. "
        f"That is an ACCOUNT condition, not a busy minute: it will hold for every run in "
        f"this batch, and a batch that starts anyway produces void bundles"
    )


def run_once(
    index: int,
    *,
    authorization: Path,
    benchmark: Path,
    creds: Path,
    scope: Path | None,
    token_cap: int | None,
) -> dict[str, Any]:
    """One benchmark run, plus what the envelope needs to judge it.

    The engagement is identified by diffing the bundle directories rather than
    by reading the harness's reconciliation: a run that reached the target and
    then failed to reconcile still produced a bundle, and that bundle is exactly
    the one worth reading.
    """
    before = newest_engagement_dirs()
    started = time.time()
    argv = [
        sys.executable,
        str(Path(__file__).resolve().parent / "juiceshop_benchmark_run.py"),
        "--authorization",
        str(authorization),
        "--benchmark-profile",
        str(benchmark),
        "--creds",
        str(creds),
    ]
    if scope is not None:
        argv += ["--scope", str(scope)]
    if token_cap:
        argv += ["--token-cap", str(token_cap)]
    proc = subprocess.run(  # noqa: S603 — list-form, operator-supplied paths
        argv, capture_output=True, text=True, timeout=14400
    )
    elapsed = time.time() - started
    new = newest_engagement_dirs() - before
    engagement = max(new, key=lambda n: (OUTPUTS / n).stat().st_mtime) if new else ""

    run_dir = ENVELOPE_DIR / f"run_{index}"
    write_redacted_text(
        run_dir / "harness_stdout.txt", proc.stdout + "\n=== STDERR ===\n" + proc.stderr
    )
    for name in PRESERVED_JSON:
        source = RESULTS_DIR / name
        if source.is_file():
            write_redacted_json(run_dir / name, json.loads(source.read_text(encoding="utf-8")))
    for name in PRESERVED_TEXT:
        source = RESULTS_DIR / name
        if source.is_file():
            write_redacted_text(run_dir / name, source.read_text(encoding="utf-8"))

    row: dict[str, Any] = {
        "run": index,
        "engagement": engagement,
        "returncode": proc.returncode,
        "seconds": round(elapsed, 1),
        "artifacts": str(run_dir),
    }
    if not engagement:
        # ``None``, not ``[]``: no bundle means no claim about which stages were
        # served. The void_reason decides this row either way, but a reader that
        # takes the field at face value must not find a clean measurement here.
        row["exhausted_stages"] = None
        row["void_reason"] = (
            "the run produced no engagement bundle, so there is nothing to record or read"
        )
        return row

    report = read_report(engagement)
    row["exhausted_stages"] = stamp_exhaustion(report)
    reconciliation = run_dir / "reconciliation.json"
    if reconciliation.is_file():
        recorded = json.loads(reconciliation.read_text(encoding="utf-8"))
        row["credential_set"] = recorded.get("credential_set")
        row["metrics"] = envelope_metrics(recorded)
    return row


def envelope_metrics(recorded: dict[str, Any]) -> dict[str, Any]:
    """The four compared numbers, read off one run's reconciliation.

    A metric the reconciliation did not record is ``None``, which
    :func:`variance` then excludes. That rule is the function's whole contract
    and three of the four kept it by doing nothing — ``recorded.get(key)`` is
    ``None`` on a missing key already.

    ``findings_emitted`` is a list, and ``len(recorded.get(...) or [])`` broke the
    rule in the one place it took an expression to keep: a reconciliation missing
    the key yielded ``0``, which is not ``None``, so it survived the filter and
    widened the envelope downward as a real observation of a run with no
    findings. A recorded empty list still says ``0`` — that IS a measurement, and
    the two are what ``isinstance`` separates.

    Args:
        recorded: One run's parsed ``reconciliation.json``.

    Returns:
        ``{metric: value_or_None}`` over :data:`ENVELOPE_METRICS`.
    """
    emitted = recorded.get("findings_emitted")
    return {
        "solved_total": recorded.get("solved_total"),
        "solved_by_testing_count": recorded.get("solved_by_testing_count"),
        "methodology_dispatches": recorded.get("methodology_dispatches"),
        "findings_emitted": len(emitted) if isinstance(emitted, list) else None,
    }


def variance(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Spread of each metric across the RECORDED runs.

    Void runs are absent from *rows* by construction — the point of the second
    guard — so this never averages a real run against a dead one. A metric no
    run reported is ``null``, not zero.
    """
    out: dict[str, Any] = {}
    for metric in ENVELOPE_METRICS:
        values = [
            row["metrics"][metric]
            for row in rows
            if isinstance(row.get("metrics"), dict) and row["metrics"].get(metric) is not None
        ]
        out[metric] = (
            {"values": values, "min": min(values), "max": max(values), "runs": len(values)}
            if values
            else {"values": [], "min": None, "max": None, "runs": 0}
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--benchmark-profile", required=True, type=Path, dest="benchmark")
    parser.add_argument("--creds", required=True, type=Path)
    parser.add_argument("--scope", type=Path, help="Scope file carrying the EngagementWindow.")
    parser.add_argument("--runs", type=int, default=3, help="Identical runs to attempt.")
    parser.add_argument("--token-cap", type=int, dest="token_cap", help="Per-run LLM token cap.")
    args = parser.parse_args()

    for path in (args.authorization, args.benchmark, args.creds):
        if not path.is_file():
            print(f"FATAL: no such file: {path}")
            return 2
    if args.scope is not None and not args.scope.is_file():
        print(f"FATAL: no such file: {args.scope}")
        return 2
    if args.runs < 1:
        print("FATAL: --runs must be at least 1")
        return 2

    print("=" * 96)
    print("GUARD 1 — provider pre-flight (a terminal account state stops the batch)")
    print("=" * 96)
    preflight, refusal = preflight_gate()
    if preflight is not None:
        print(f"  declared priority : {', '.join(preflight.priority)}")
        print(f"  keys available    : {', '.join(sorted(preflight.available)) or 'none'}")
        for validation in preflight.validations:
            # A validation's ``detail`` is ``str(exc)[:200]`` from a provider SDK,
            # and some SDKs quote the key back in the message. The key is
            # registered for redaction BEFORE the probe runs (that ordering is
            # `preflight_providers`' own reason for existing), so routing the line
            # through the redactor closes it. The engine logs this same string
            # unredacted; a driver's stdout is what ends up under `tee`.
            print(f"  probe             : {redacted(validation.describe())}")
    if refusal:
        print(f"\nREFUSED before testing: {redacted(refusal)}")
        print("Nothing was sent. Restore the account and re-run.")
        return 3
    print("  verdict           : primary usable — starting the batch\n")

    recorded: list[dict[str, Any]] = []
    attempted: list[dict[str, Any]] = []
    aborted = ""
    for index in range(1, args.runs + 1):
        print("=" * 96)
        print(f"RUN {index} of {args.runs}")
        print("=" * 96)
        row = run_once(
            index,
            authorization=args.authorization,
            benchmark=args.benchmark,
            creds=args.creds,
            scope=args.scope,
            token_cap=args.token_cap,
        )
        attempted.append(row)
        print(
            f"  engagement {row['engagement'][:8] or '(none)'} exited {row['returncode']} "
            f"in {row['seconds']}s; artifacts under {row['artifacts']}"
        )

        # ``None`` is the third answer and it is NOT clean: a bundle with no
        # model stamp cannot say whether every stage was served, and an absent
        # stamp is what an outage mid-run leaves behind. Read as an empty list
        # it passed this guard, which is the shape that let the 2026-08-25
        # batch keep going after the balance ran out.
        starved = row.get("exhausted_stages")
        if starved is None or starved or row.get("void_reason"):
            reason = row.get("void_reason") or (
                "its bundle carries no model stamp, so whether every LLM stage was "
                "served is INDETERMINATE"
                if starved is None
                else f"its model stamp reports that nothing served {', '.join(starved)}"
            )
            row["recorded"] = False
            row["void_reason"] = reason
            aborted = (
                f"run {index} is VOID and was NOT recorded: {reason}. An LLM outage is an "
                f"account condition that does not clear between runs — the 2026-08-25 "
                f"envelope lost runs 2 and 3 to one — so the batch stops here rather than "
                f"producing more bundles nobody may use."
            )
            print(f"\n  NOT RECORDED: {reason}")
            break

        row["recorded"] = True
        recorded.append(row)
        print(f"  recorded. credential set {row.get('credential_set') or '(not recorded)'}")

    summary = {
        "_what": (
            "A variance envelope over identical Juice Shop runs. A run is RECORDED only "
            "when its own model stamp SAYS every LLM stage was served; a run whose stamp "
            "names an unserved stage is void, and so is one carrying no stamp at all - an "
            "absent stamp is indeterminate, and it is what a mid-run outage leaves behind. "
            "A void run is listed with its reason and is absent from the variance, because "
            "an average over one real run and two dead ones is a wrong number, not a wider "
            "envelope."
        ),
        "runs_requested": args.runs,
        "runs_attempted": len(attempted),
        "runs_recorded": len(recorded),
        "aborted": bool(aborted),
        "abort_reason": aborted,
        "provider_preflight": preflight.to_dict() if preflight is not None else None,
        "attempts": attempted,
        "variance": variance(recorded),
    }
    write_redacted_json(ENVELOPE_DIR / "envelope.json", summary)

    print("\n" + "=" * 96)
    print("ENVELOPE")
    print("=" * 96)
    print(f"  attempted : {len(attempted)}   recorded : {len(recorded)}")
    for metric, spread in summary["variance"].items():
        print(
            f"  {metric:26s}: {spread['values']} "
            f"(min {spread['min']}, max {spread['max']}, over {spread['runs']} run(s))"
        )
    if aborted:
        print(f"\nABORTED: {aborted}")
    print(f"\nwritten: {ENVELOPE_DIR / 'envelope.json'}")

    if aborted:
        return 4
    if any(row["returncode"] != 0 for row in recorded):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
