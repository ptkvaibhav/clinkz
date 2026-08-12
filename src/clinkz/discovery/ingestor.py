"""Source-ingestor interface + deterministic language dispatch (slice A1).

The discovery engine's four downstream layers (catalog → intent → reachability →
hypothesis) and the whole Layer-2 loop (recall / write-back / relations) are keyed
on the language-agnostic :class:`~clinkz.discovery.models.SourceModel`, so the ONE
language-specific seam is which ingestor produces that model. This module names that
seam as a minimal :class:`SourceIngestor` protocol and picks the right implementation
for a source tree, so the engine works on non-Java targets without any change to the
layers above the ingestor.

:class:`~clinkz.discovery.source_ingest.JavaSourceIngestor` and
:class:`~clinkz.discovery.js_source_ingest.JsSourceIngestor` both satisfy the protocol
*structurally* (each exposes a single ``ingest_path``) — the extraction is pure: the
Java ingestor is unchanged, so a Java tree ingests byte-identically through the
dispatch as it did through the old hard-wired call.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from clinkz.discovery.js_source_ingest import JsSourceIngestor
from clinkz.discovery.models import SourceModel
from clinkz.discovery.source_ingest import JavaSourceIngestor

# Root-level build manifests that mark a Java project (checked before a file walk).
_JAVA_MANIFESTS: tuple[str, ...] = ("pom.xml", "build.gradle", "build.gradle.kts")
_JAVA_SUFFIX = ".java"
_JS_SUFFIXES: frozenset[str] = frozenset({".js", ".mjs", ".cjs", ".ts"})
# Directories excluded from the extension probe — huge / irrelevant to language choice.
_PROBE_SKIP_DIRS: frozenset[str] = frozenset({"node_modules", ".git", "dist", "build", "out"})


@runtime_checkable
class SourceIngestor(Protocol):
    """A source-tree → :class:`SourceModel` ingestor (the one language-specific seam).

    The sole contract the discovery engine depends on: a deterministic, bounded,
    read-only projection of an ingestable source tree into the language-agnostic
    :class:`SourceModel`. Implementations are pattern-based and never execute the
    source (design §2.2).
    """

    def ingest_path(self, root: str | Path) -> SourceModel:
        """Ingest the source tree (or single file) at *root* into a SourceModel."""
        ...


def _first_matching_file(root: Path, pattern: str) -> bool:
    """Whether at least one non-skipped file matches *pattern* under *root* (bounded).

    Uses a lazy ``rglob`` so it stops at the first hit; skips dependency / build dirs
    so a JS project's ``node_modules`` (which may vendor ``.java``) never mis-detects.
    """

    def _candidates() -> Iterator[Path]:
        for path in root.rglob(pattern):
            if any(part in _PROBE_SKIP_DIRS for part in path.parts):
                continue
            yield path

    return next(_candidates(), None) is not None


def _looks_java(root: Path) -> bool:
    """Deterministic Java-project signal: a root build manifest or any ``*.java``."""
    if any((root / name).exists() for name in _JAVA_MANIFESTS):
        return True
    return _first_matching_file(root, "*.java")


def _looks_js(root: Path) -> bool:
    """Deterministic JS/TS-project signal: a root ``package.json`` or any JS/TS source."""
    if (root / "package.json").exists():
        return True
    return any(_first_matching_file(root, f"*{suffix}") for suffix in _JS_SUFFIXES)


@dataclass(frozen=True)
class IngestorSelection:
    """Which ingestor a source tree selected, and whether anything MATCHED.

    The distinction the bare :func:`select_ingestor` cannot express. That
    function returns the Java ingestor both when a Java tree was recognised and
    when nothing was recognised at all, so a gray-box run over a Python or Go
    checkout produced an empty :class:`SourceModel` that is byte-identical to a
    Java tree with no sinks in it. The engagement then reports black-box results
    while the operator believes their ``--source`` was read.

    Args:
        ingestor: The ingestor to run. Populated even on a miss (it is the
            historical Java fallback), so callers that only want to ingest are
            unaffected.
        matched: Whether a language was actually detected.
        language: The detected language (``java`` / ``javascript``), or ``""``.
        reason: Operator-facing explanation, rendered in the report when
            *matched* is ``False``.
    """

    ingestor: SourceIngestor
    matched: bool
    language: str
    reason: str


def detect_ingestor(root: str | Path) -> IngestorSelection:
    """Detect the source language at *root* and report whether it matched.

    Deterministic and read-only — the same signals :func:`select_ingestor` has
    always used, with the "nothing matched" case named instead of folded into
    the Java fallback.

    Args:
        root: The source tree (or single file) named by ``--source``.

    Returns:
        An :class:`IngestorSelection`. On a miss ``ingestor`` is still the Java
        fallback, so behaviour for a caller that ignores ``matched`` is
        unchanged.
    """
    root = Path(root)
    if not root.exists():
        return IngestorSelection(
            ingestor=JavaSourceIngestor(),
            matched=False,
            language="",
            reason=f"the source path does not exist: {root}",
        )
    if root.is_file():
        if root.suffix == _JAVA_SUFFIX:
            return IngestorSelection(JavaSourceIngestor(), True, "java", "")
        if root.suffix in _JS_SUFFIXES:
            return IngestorSelection(JsSourceIngestor(), True, "javascript", "")
        return IngestorSelection(
            ingestor=JavaSourceIngestor(),
            matched=False,
            language="",
            reason=(
                f"'{root.name}' is not a source file this engine can ingest "
                f"(supported: {_JAVA_SUFFIX}, {', '.join(sorted(_JS_SUFFIXES))})"
            ),
        )
    if _looks_java(root):
        return IngestorSelection(JavaSourceIngestor(), True, "java", "")
    if _looks_js(root):
        return IngestorSelection(JsSourceIngestor(), True, "javascript", "")
    return IngestorSelection(
        ingestor=JavaSourceIngestor(),
        matched=False,
        language="",
        reason=(
            f"no Java or JavaScript/TypeScript project was detected under {root} "
            "(looked for pom.xml / build.gradle / *.java, and package.json / "
            "*.js / *.mjs / *.cjs / *.ts). Those are the only two languages this "
            "engine has a source ingestor for"
        ),
    )


def select_ingestor(root: str | Path) -> SourceIngestor:
    """Return the ingestor for the project language at *root* (deterministic).

    Java signals win ties, preserving the pre-dispatch behaviour for every existing
    Java target; a JS/TS project (``package.json`` or JS/TS sources) selects the JS
    ingestor; when neither is detected the default is the Java ingestor — the
    unchanged fallback, so a non-source or empty ``source_dir`` behaves exactly as it
    did when the call was hard-wired.

    Callers that need to know whether anything actually matched — so the run can
    say "your source tree was not ingested" rather than silently returning
    black-box results — should use :func:`detect_ingestor` instead.
    """
    return detect_ingestor(root).ingestor
