#!/usr/bin/env python3
"""One-command clone bootstrap: activate this repo's enforcement hooks.

    python scripts/bootstrap.py

``core.hooksPath`` is per-clone **local** config — it is never committed, and a
fresh clone has no ``.git/hooks/pre-commit`` either. Until this runs, the local
guard layer is completely inert: ``git add -f outputs/leak.json && git commit``
succeeds and the leak lands in HEAD. That is not hypothetical — 44 run artifacts
once reached a public repo that way and needed a full history rewrite to purge,
and every re-clone after that purge started out unprotected again.

Run this as the FIRST step after cloning. It is idempotent, verifies the setting
afterwards, and needs nothing but git and the standard library (so it runs before
the virtualenv exists).

The local layer this activates is still skippable with ``--no-verify``. The
fail-closed layer is the ``leak-guard`` job in ``.github/workflows/ci.yml``,
which runs server-side on every PR and cannot be skipped by any local config.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_HOOKS_PATH = ".githooks"
_EXPECTED_HOOK = "pre-commit"


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False)


def main() -> int:
    toplevel = _git("rev-parse", "--show-toplevel")
    if toplevel.returncode != 0:
        sys.stderr.write("bootstrap: not inside a git repository — run this from the clone.\n")
        return 1
    root = Path(toplevel.stdout.strip())

    hook = root / _HOOKS_PATH / _EXPECTED_HOOK
    if not hook.is_file():
        sys.stderr.write(f"bootstrap: expected hook not found: {hook}\n")
        return 1

    configured = _git("config", "--local", "core.hooksPath").stdout.strip()
    if configured != _HOOKS_PATH:
        if _git("config", "--local", "core.hooksPath", _HOOKS_PATH).returncode != 0:
            sys.stderr.write("bootstrap: failed to set core.hooksPath.\n")
            return 1

    verified = _git("config", "--local", "core.hooksPath").stdout.strip()
    if verified != _HOOKS_PATH:
        sys.stderr.write(
            f"bootstrap: core.hooksPath is {verified!r}, expected {_HOOKS_PATH!r} — "
            "this clone is NOT protected.\n"
        )
        return 1

    print(f"bootstrap: core.hooksPath = {verified} (enforcement hooks active for this clone)")
    print("  pre-commit guards: outputs/, credentials + .env, ruff check + format")
    print("  fail-closed layer: the leak-guard CI job -- never use --no-verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
