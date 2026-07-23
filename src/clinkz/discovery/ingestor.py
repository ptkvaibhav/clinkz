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


def select_ingestor(root: str | Path) -> SourceIngestor:
    """Return the ingestor for the project language at *root* (deterministic).

    Java signals win ties, preserving the pre-dispatch behaviour for every existing
    Java target; a JS/TS project (``package.json`` or JS/TS sources) selects the JS
    ingestor; when neither is detected the default is the Java ingestor — the
    unchanged fallback, so a non-source or empty ``source_dir`` behaves exactly as it
    did when the call was hard-wired.
    """
    root = Path(root)
    if root.is_file():
        if root.suffix == _JAVA_SUFFIX:
            return JavaSourceIngestor()
        if root.suffix in _JS_SUFFIXES:
            return JsSourceIngestor()
        return JavaSourceIngestor()
    if _looks_java(root):
        return JavaSourceIngestor()
    if _looks_js(root):
        return JsSourceIngestor()
    return JavaSourceIngestor()
