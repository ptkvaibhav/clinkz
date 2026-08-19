"""The suite never writes into the repository's own ``outputs/``.

``outputs/`` is not scratch space. It is the COMPANION region
:func:`~clinkz.engagement.artifact_scan.scan_artifact_tree` sweeps when an
operator asks "may I share this bundle" — the region that exists precisely
because a guard's ROOT is part of its verdict. A test byproduct sitting there is
therefore scanned as though it were engagement material, and a test that ever
handles a real credential lands it inside a swept region.

Before ``_redirect_outputs_root`` in :mod:`tests.conftest`, a keyless run of this
suite created **25** directories under the real ``outputs/`` — every test that
reached a writer without passing ``outputs_root=`` explicitly, because the
default root is the RELATIVE path ``outputs`` and pytest does not change the
working directory.

These tests are the reason the fixture cannot be quietly deleted: the first
asserts the redirect is in force, and the second asserts it is in force for a
test that does not ask for it, which is the whole point of ``autouse``.
"""

from __future__ import annotations

from pathlib import Path

from clinkz.config import outputs_root, settings

#: The checkout's own outputs directory — what the redirect exists to protect.
REPO_OUTPUTS = (Path(__file__).resolve().parent.parent / "outputs").resolve()


def test_the_configured_root_is_not_the_repositorys_outputs_directory() -> None:
    """Resolved through :func:`clinkz.config.outputs_root`, as every writer does."""
    resolved = Path(outputs_root()).resolve()
    assert resolved != REPO_OUTPUTS, (
        f"the outputs root resolves to the repository's own {REPO_OUTPUTS} — "
        "tests/conftest.py::_redirect_outputs_root is not in force, and this run "
        "is writing engagement artifacts into the disclosure gate's companion region"
    )
    assert REPO_OUTPUTS not in resolved.parents, (
        f"the outputs root {resolved} sits INSIDE the repository's {REPO_OUTPUTS}; "
        "redirecting to a subdirectory still lands byproducts in the swept region"
    )


def test_a_writer_that_is_given_no_root_lands_under_the_redirect(tmp_path: Path) -> None:
    """The default-argument path, which is the one that leaked.

    Constructed with no ``outputs_root=``, so it resolves the configured root at
    call time — the same resolution an engagement writer performs. ``tmp_path``
    is requested only to keep the writer's engagement id distinct; the assertion
    is about where the writer chose to put it.
    """
    from clinkz.observability.trace import TraceWriter

    writer = TraceWriter("outputs-isolation-probe")
    try:
        written = writer.path.resolve()
    finally:
        writer.close()

    assert REPO_OUTPUTS not in written.parents, (
        f"a writer with no explicit root wrote to {written}, inside the repository's {REPO_OUTPUTS}"
    )
    assert Path(settings.outputs_root).resolve() in written.parents
