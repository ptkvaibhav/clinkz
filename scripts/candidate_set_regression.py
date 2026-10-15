"""Compare a later engagement bundle against a baseline by plan SET (register R29).

Every ``(test_method, endpoint_url)`` the baseline CONFIRMED must be in the
later run's dispatched plan. Offline: reads two ``outputs/<id>/`` directories,
sends nothing, writes nothing.

Usage::

    python scripts/candidate_set_regression.py <baseline_id> <later_id> [--outputs DIR]

Exit codes: 0 every confirmed pair was planned · 1 REGRESSION (each lost pair is
named, with ``truncated`` or ``absent``) · 2 NOT DETERMINED (a bundle predates
the plan-set trace records; this is not a pass).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from clinkz.observability.candidate_regression import Verdict, compare_bundles

_EXIT = {Verdict.PASS: 0, Verdict.REGRESSION: 1, Verdict.NOT_DETERMINED: 2}


def main(argv: list[str] | None = None) -> int:
    """Run the comparison and print one line per baseline-confirmed pair."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("baseline")
    parser.add_argument("later")
    parser.add_argument("--outputs", default="outputs", type=Path)
    args = parser.parse_args(argv)

    result = compare_bundles(args.outputs / args.baseline, args.outputs / args.later)
    print(f"verdict: {result.verdict.value.upper()}")
    if result.reason:
        print(f"reason: {result.reason}")
    for outcome in result.outcomes:
        print(f"  {outcome.state.value:9s} {outcome.test_method} {outcome.endpoint_url}")
    return _EXIT[result.verdict]


if __name__ == "__main__":
    sys.exit(main())
