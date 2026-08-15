#!/usr/bin/env python3
"""Resolve and verify the full dependency set CI installs.

Why this exists
---------------
``pyproject.toml`` pins ``typer``/``click``/``rich`` exactly, because tests read
what those three *render*. That closed one instance of a class and not the class:
every other requirement is an open ``>=`` bound, so the resolver is free to pick
a different build on CI than on a developer machine, on any day, without a line
of this repository changing. The observed instance was a CLI stack — local
``typer 0.24.1 / click 8.3.1 / rich 14.3.3`` against CI's
``0.27.1 / 8.4.2 / 15.0.0`` — and pinning those three by name leaves the same
door open for ``pydantic``, ``aiohttp``, ``anthropic`` and the ~60 transitive
packages behind them.

A lockfile records the whole resolved set. ``--check`` fails the build when the
environment does not match it, so a resolver drift is a red build with a diff
rather than a mystery test failure somewhere downstream.

Platform
--------
The lock targets the environment CI installs into (Linux, CPython 3.12), because
that is the environment the assertion runs in. ``--generate`` resolves for that
target explicitly rather than freezing whatever is installed here, so it can be
regenerated from any developer machine and produce the same file.

**``--platform`` is not as strong as it looks.** It constrains which wheel TAGS
are acceptable; it does not set ``sys_platform`` for environment-marker
evaluation. So a dependency declared ``colorama; sys_platform == "win32"`` still
enters a Linux-targeted resolve, because its wheel is ``py3-none-any`` and the
marker was never consulted. The first CI run of this check caught exactly that,
as a one-line ``MISSING colorama==0.4.6 is locked but not installed``.

:data:`MARKER_EXCLUDED` carries those packages. It is a short list rather than a
marker evaluator on purpose: **the CI ``--check`` is the authority**, and a
package that belongs on this list announces itself there as a single, named,
self-explaining line. A marker evaluator would be more code with the same safety
net behind it.

Usage
-----
    python scripts/lockfile.py --generate    # rewrite requirements-ci.lock
    python scripts/lockfile.py --check       # compare the live environment
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
LOCKFILE = ROOT / "requirements-ci.lock"

#: The environment CI resolves for. Kept beside the workflow that installs it;
#: `ci.yml` pins `python-version: "3.12"` on `ubuntu-latest`.
PYTHON_VERSION = "3.12"
PLATFORMS = ("manylinux2014_x86_64", "any")

#: Provided by the runner image, not by this project. Their versions are a
#: property of the runner and locking them would make the check fail on every
#: GitHub image bump for no benefit.
ENVIRONMENT_PACKAGES = frozenset({"pip", "setuptools", "wheel", "pkg-resources"})

#: Pulled in under an environment marker that is FALSE on the CI target, but
#: which a ``--platform``-targeted resolve still selects because the marker is
#: never evaluated (see the module docstring). Excluded from the lock so it
#: describes what CI actually installs.
MARKER_EXCLUDED = frozenset(
    {
        "colorama",  # click/pytest: sys_platform == "win32"
        "pywin32",  # sys_platform == "win32"
        "pywin32-ctypes",  # sys_platform == "win32"
        "exceptiongroup",  # python_version < "3.11"; CI is 3.12
        "tomli",  # python_version < "3.11"; CI is 3.12
    }
)

HEADER = """\
# GENERATED — do not edit by hand. Regenerate with:
#     python scripts/lockfile.py --generate
#
# The complete dependency set CI installs, resolved for CPython {py} on Linux.
# `--check` runs in CI and fails on any drift between this file and the
# environment `pip install -e ".[dev]"` actually produced. See scripts/lockfile.py
# for why pinning three packages in pyproject.toml did not close this class.
"""


def normalise(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return name.lower().replace("_", "-").replace(".", "-")


def direct_requirements() -> list[str]:
    """Every requirement CI installs: the project's own plus the dev extra."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    return [*project["dependencies"], *project["optional-dependencies"]["dev"]]


def resolve() -> dict[str, str]:
    """Resolve the direct requirements for CI's platform, without installing."""
    report = ROOT / ".lockfile-report.json"
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--quiet",
        "--report",
        str(report),
        "--python-version",
        PYTHON_VERSION,
        "--only-binary=:all:",
        *(arg for platform in PLATFORMS for arg in ("--platform", platform)),
        *direct_requirements(),
    ]
    try:
        subprocess.run(cmd, check=True, cwd=ROOT)
        data = json.loads(report.read_text(encoding="utf-8"))
    finally:
        report.unlink(missing_ok=True)

    resolved: dict[str, str] = {}
    for item in data.get("install", []):
        meta = item.get("metadata", {})
        name, version = meta.get("name"), meta.get("version")
        if not name or not version:
            continue
        key = normalise(name)
        if key in ENVIRONMENT_PACKAGES or key in MARKER_EXCLUDED:
            continue
        resolved[key] = version
    return resolved


def read_lock() -> dict[str, str]:
    """Parse the committed lockfile into ``{name: version}``."""
    if not LOCKFILE.is_file():
        return {}
    out: dict[str, str] = {}
    for line in LOCKFILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, version = line.partition("==")
        out[normalise(name)] = version
    return out


def installed() -> dict[str, str]:
    """What is actually importable in this environment, minus the project itself."""
    from importlib.metadata import distributions

    out: dict[str, str] = {}
    for dist in distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        key = normalise(name)
        # MARKER_EXCLUDED is skipped on BOTH sides: on a Windows developer
        # machine colorama genuinely IS installed, and reporting it as an EXTRA
        # would be the check complaining about a correct environment.
        if key in ENVIRONMENT_PACKAGES or key in MARKER_EXCLUDED or key == "clinkz":
            continue
        out[key] = dist.version
    return out


def generate() -> int:
    resolved = resolve()
    body = "".join(f"{name}=={version}\n" for name, version in sorted(resolved.items()))
    LOCKFILE.write_text(HEADER.format(py=PYTHON_VERSION) + body, encoding="utf-8")
    print(f"wrote {LOCKFILE.relative_to(ROOT)} — {len(resolved)} packages")
    return 0


def check() -> int:
    locked = read_lock()
    if not locked:
        print(f"FAIL: {LOCKFILE.name} is missing or empty. Run --generate.", file=sys.stderr)
        return 1

    live = installed()
    problems: list[str] = []

    for name, version in sorted(locked.items()):
        if name not in live:
            problems.append(f"  MISSING  {name}=={version} is locked but not installed")
        elif live[name] != version:
            problems.append(f"  DRIFT    {name}: locked {version}, installed {live[name]}")

    # An unlocked extra is drift too: it means the resolver pulled something the
    # lock does not describe, which is the same reproducibility hole from the
    # other direction.
    for name, version in sorted(live.items()):
        if name not in locked:
            problems.append(f"  EXTRA    {name}=={version} is installed but not locked")

    if problems:
        print(f"Dependency set does not match {LOCKFILE.name}:\n", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "\nIf the change is intended, regenerate and commit the lockfile:"
            "\n    python scripts/lockfile.py --generate",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(locked)} packages match {LOCKFILE.name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="rewrite the lockfile")
    group.add_argument("--check", action="store_true", help="verify the live environment")
    args = parser.parse_args()
    return generate() if args.generate else check()


if __name__ == "__main__":
    raise SystemExit(main())
