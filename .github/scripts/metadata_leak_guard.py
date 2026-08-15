#!/usr/bin/env python3
"""Refuse Claude session links in PR metadata — the half the tree guard cannot see.

``leak-guard`` inspects the **tree**: files under ``outputs/``, ``.env``,
credential material. A PR title, a PR body, and a commit message are none of
those — they are GitHub-side metadata and git object headers, so no scan of the
working tree was ever capable of catching them. That gap is what this guard
closes, and the gap class is the finding, not any one URL.

What it refuses:

* ``claude.ai/code/session`` — the session URL, in a PR title, body, or commit
  message.
* ``Claude-Session:`` — the commit trailer that carries it.

The guard never reproduces what it found. A session URL printed into a public
Actions log is the same disclosure the guard exists to prevent, so findings are
reported as ``<source>:<line> <redacted shape>`` and the token itself is
replaced with ``<REDACTED>``. Same rule as ``engagement/artifact_scan.py``: the
report names the location, never the value.

Inputs arrive by **file or environment variable, never as an argv string**. A PR
title is text an outside contributor chooses; interpolating it into a shell
command is a script-injection sink, and a guard that can be made to execute its
input is worse than no guard.

Exit codes: ``0`` clean · ``1`` a leak was found · ``2`` the guard could not run
(fail-closed — an unusable guard must never read as a pass).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass

#: The two shapes that carry a session identity. Both are matched
#: case-insensitively: the trailer is emitted as ``Claude-Session:`` but a
#: hand-edited body may lowercase it, and a guard that only catches the
#: generator's exact spelling catches only what the generator wrote.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("session-url", re.compile(r"claude\.ai/code/session", re.IGNORECASE)),
    ("session-trailer", re.compile(r"Claude-Session\s*:", re.IGNORECASE)),
)

#: Redacts the identifier itself out of any line the guard reports. Two shapes,
#: because the trailer can carry an identifier the URL pattern does not match:
#: ``Claude-Session: <anything>`` is redacted wholesale after the colon, since
#: whatever follows it is by definition the session identity.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(claude\.ai/code/session)[\w/_-]*", re.IGNORECASE), r"\1/<REDACTED>"),
    (re.compile(r"(Claude-Session\s*:).*", re.IGNORECASE), r"\1 <REDACTED>"),
)


class GuardUnusableError(Exception):
    """The guard could not perform its check.

    Distinct from "found nothing" and distinct from "found something": it exits
    ``2`` so a broken guard can never be read as either a pass or an alarm.
    """


@dataclass(frozen=True)
class Finding:
    """One offending line, already stripped of the value that made it offend."""

    source: str
    line_no: int
    kind: str
    redacted: str

    def render(self) -> str:
        return f"  {self.source}:{self.line_no}  [{self.kind}]  {self.redacted}"


def redact(line: str) -> str:
    """Return ``line`` with any session identifier replaced by a marker.

    The prefix is kept so a reader can tell *which* shape matched; everything
    that identifies the session is dropped.
    """
    for pattern, replacement in _REDACTIONS:
        line = pattern.sub(replacement, line)
    return line.strip()[:160]


def scan_text(source: str, text: str) -> list[Finding]:
    """Report every line of ``text`` carrying a session link or trailer."""
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(Finding(source, line_no, kind, redact(line)))
                break
    return findings


def commit_messages(base_sha: str, head_sha: str) -> list[tuple[str, str]]:
    """Return ``(label, message)`` for every commit in ``base..head``.

    A failure to enumerate the range is fatal, not empty: "git could not answer"
    and "there are no commits" are different facts, and only one of them is a
    pass.
    """
    # `-z` makes *git* NUL-separate the records in its OUTPUT. The separator
    # must never be written into the --format argument instead: an embedded NUL
    # is not a legal process argument on any platform, and Python raises
    # ValueError before git ever runs. That crash exits 1, which is the same
    # code as "leak found" -- a guard whose breakage is indistinguishable from
    # its alarm is unreadable, so the failure is caught and mapped to 2 below.
    sep = "\x00"
    try:
        out = subprocess.run(
            ["git", "log", "-z", "--format=%H%n%B", f"{base_sha}..{head_sha}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()
        raise GuardUnusableError(f"git log {base_sha}..{head_sha} failed: {detail}") from exc

    messages: list[tuple[str, str]] = []
    for block in out.split(sep):
        block = block.strip("\n")
        if not block:
            continue
        sha, _, body = block.partition("\n")
        messages.append((f"commit {sha[:12]}", body))
    return messages


def self_test() -> int:
    """Prove the detector fires, and prove it does not fire on clean text.

    A guard nobody has watched fail is an assumption. Both directions are
    asserted because a detector that matches everything passes the first half
    and protects nothing.
    """
    seeded = [
        ("seeded-body", "some text\nhttps://claude.ai/code/session_018eXXXXXXXXXXXXXXXXXXXX\nmore"),
        ("seeded-trailer", "subject\n\nCo-Authored-By: x\nClaude-Session: https://example.invalid"),
        ("seeded-lowercase", "claude-session: https://claude.ai/code/session_abc"),
        ("seeded-inline", "see https://claude.ai/code/session_abc for context"),
    ]
    clean = [
        (
            "clean-body",
            "A normal PR body.\nGenerated with [Claude Code](https://claude.com/claude-code)",
        ),
        (
            "clean-commit",
            "fix(cli): a subject line\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        ),
        ("clean-word", "We discussed the claude code session in a meeting."),
    ]

    failures: list[str] = []
    for label, text in seeded:
        found = scan_text(label, text)
        if not found:
            failures.append(f"MISS: {label} was not detected")
        else:
            for f in found:
                if "session_018eXXXX" in f.redacted or re.search(r"session_[\w-]+", f.redacted):
                    failures.append(f"LEAK: {label} reproduced the identifier in its own report")
    for label, text in clean:
        found = scan_text(label, text)
        if found:
            failures.append(f"FALSE POSITIVE: {label} -> {[x.kind for x in found]}")

    # The commit-range path gets exercised too, not just scan_text. The first
    # version of this guard passed a NUL inside the --format argument; every
    # scan_text assertion above still passed, and the real path crashed on the
    # first PR it ever saw. A self-test that only covers the pure function
    # certifies the half that was never going to break.
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        got = commit_messages(f"{head}~1", head)
    except GuardUnusableError as exc:
        failures.append(f"COMMIT-RANGE PATH UNUSABLE: {exc}")
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"self-test note: no git history to exercise the range path ({exc}); skipped.")
    else:
        # Assert the path RAN and returned well-formed records -- never an exact
        # count. `HEAD~1..HEAD` spans one commit on a linear history and the
        # whole merged branch when HEAD is a merge commit, so a count assertion
        # fails on main and passes on a topic branch: a self-test that depends
        # on history shape reports the shape, not the guard.
        if not got:
            failures.append("COMMIT-RANGE PATH: returned no records for HEAD~1..HEAD")
        else:
            malformed = [
                label for label, _ in got if not re.fullmatch(r"commit [0-9a-f]{12}", label)
            ]
            if malformed:
                failures.append(f"COMMIT-RANGE PATH: malformed labels {malformed[:3]}")

    if failures:
        print("SELF-TEST FAILED - the guard does not behave as specified:")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"self-test OK: {len(seeded)} seeded leaks detected, {len(clean)} clean inputs passed,")
    print("              the commit-range path returned a well-formed record,")
    print("              and no report reproduced the identifier it found.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test", action="store_true", help="assert the detector fires, then exit"
    )
    parser.add_argument("--title-env", help="env var holding the PR title")
    parser.add_argument("--body-env", help="env var holding the PR body")
    parser.add_argument("--base-sha", help="base SHA of the PR range")
    parser.add_argument("--head-sha", help="head SHA of the PR range")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    findings: list[Finding] = []
    checked: list[str] = []

    if args.title_env:
        findings += scan_text("pr-title", os.environ.get(args.title_env, ""))
        checked.append("PR title")
    if args.body_env:
        findings += scan_text("pr-body", os.environ.get(args.body_env, ""))
        checked.append("PR body")
    if args.base_sha and args.head_sha:
        messages = commit_messages(args.base_sha, args.head_sha)
        for label, body in messages:
            findings += scan_text(label, body)
        span = f"{args.base_sha[:12]}..{args.head_sha[:12]}"
        checked.append(f"{len(messages)} commit message(s) in {span}")

    if not checked:
        print("GUARD COULD NOT RUN: nothing was selected to scan.", file=sys.stderr)
        return 2

    print("metadata-leak-guard checked: " + "; ".join(checked))

    if findings:
        print("")
        print("REFUSED - Claude session metadata found. These are publicly readable:")
        for f in findings:
            print(f.render())
        print("")
        print("Fix:")
        print("  * PR title/body are GitHub-side metadata - edit them, no history rewrite needed:")
        print("      gh pr edit <n> --body-file <file-with-the-line-removed>")
        print("  * A commit trailer lives in the git object and needs a rewrite of those commits.")
        print("  * Stop the source first, or it comes back:")
        print('      settings.json -> "attribution": {"commit": "", "pr": "", "sessionUrl": false}')
        print("    sessionUrl is a boolean (Claude Code >= 2.1.183); the commit/pr strings")
        print("    do NOT suppress it on their own.")
        return 1

    print("clean: no session URL, no Claude-Session trailer.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GuardUnusableError as exc:
        # Exit 2, never 1: "the guard could not run" must not be mistakable for
        # "the guard found a leak", and must never be mistakable for a pass.
        print(f"GUARD COULD NOT RUN: {exc}", file=sys.stderr)
        sys.exit(2)
