"""Isolation for tests that drive the CLI in-process.

``clinkz scan --out`` and ``--db`` assign to the process-global
:data:`clinkz.config.settings`. That is correct for the real entry point — a CLI
invocation IS the process, and it exits — but a :class:`~typer.testing.CliRunner`
test runs inside the same interpreter as every other test, so an unrestored
assignment silently redirects a LATER suite's artifacts.

It is not hypothetical: adding these tests moved
``test_report_and_dryrun.py``'s action-log assertion from green to red, because
a resume test had pointed the outputs root at its own ``tmp_path`` and left it
there. Restoring here keeps the leak from reaching anything downstream, and
keeps the CLI's mutation honest rather than papered over with a copy of settings
the real command would not use.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from clinkz.config import settings


@pytest.fixture(autouse=True)
def _restore_global_settings() -> Iterator[None]:
    """Snapshot and restore every settings field the CLI is allowed to assign."""
    saved = {
        "outputs_root": settings.outputs_root,
        "db_path": settings.db_path,
    }
    try:
        yield
    finally:
        for field, value in saved.items():
            setattr(settings, field, value)
