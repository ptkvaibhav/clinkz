"""The active benchmark profile — absent by default, and the one seam it changes.

Arranged exactly like :func:`clinkz.safety.governor.get_active_governor`: the
module-level profile is ``None`` unless an engagement installed one, and every
consultation of it is a no-op in that state. So a direct methodology invocation —
a unit suite, a replay, a smoke cell — behaves byte-identically to before this
module existed, and the client-safe destructive refusal remains the default with
nothing to switch it off.

**What a profile changes is exactly one thing**: a
:class:`~clinkz.safety.destructive.DestructiveVerdict` that refused for a
category the profile names is converted into an allow that records why. The
classifier itself is untouched — it still classifies, it still names the
category and the deciding signal, and it can still only ever refuse MORE than its
predecessor. The override happens after classification, which is what makes the
action log able to say exactly what was permitted and on what grounds.
"""

from __future__ import annotations

import logging

from clinkz.models.engagement import BenchmarkProfile
from clinkz.safety.destructive import DestructiveVerdict

logger = logging.getLogger(__name__)

_active_profile: BenchmarkProfile | None = None


def set_active_benchmark_profile(profile: BenchmarkProfile | None) -> None:
    """Install (or clear) the engagement's benchmark profile.

    Called once by the orchestrator, from the authorization record. Logged
    loudly on install: an operator scrolling a run log must be able to see that
    the destructive rails were relaxed, and for what.

    Args:
        profile: The profile, or ``None`` to restore the client-safe default.
    """
    global _active_profile
    _active_profile = profile
    if profile is None:
        return
    logger.warning(
        "BENCHMARK PROFILE ACTIVE — destructive categories permitted against this "
        "target: %s (declared by %s, reference %s). Categories that remain refused "
        "on any target are unaffected.",
        ", ".join(sorted(profile.permitted_categories)),
        profile.declared_by,
        profile.declared_reference,
    )


def get_active_benchmark_profile() -> BenchmarkProfile | None:
    """The engagement's benchmark profile, or ``None`` (the default)."""
    return _active_profile


def benchmark_override(verdict: DestructiveVerdict) -> DestructiveVerdict:
    """Apply the active profile to a classifier *verdict*.

    Args:
        verdict: The verdict :mod:`clinkz.safety.destructive` produced.

    Returns:
        The verdict unchanged when there is no profile, when the verdict allowed
        anyway, or when the profile does not name this category. Otherwise an
        allowing verdict whose ``reason`` records that a profile permitted it and
        which signal would have refused it — so the permission is as auditable in
        the log as a refusal is.
    """
    profile = _active_profile
    if profile is None or not verdict.refused:
        return verdict
    if not profile.permits_category(verdict.category):
        return verdict
    return verdict.model_copy(
        update={
            "refused": False,
            "reason": (
                f"permitted by the engagement's benchmark profile "
                f"(category {verdict.category!r}, declared by {profile.declared_by} under "
                f"{profile.declared_reference}). Without it this would have been refused: "
                f"{verdict.reason}"
            ),
        }
    )


def override_category(verdict: DestructiveVerdict) -> str:
    """The category a profile permitted, or ``""`` when nothing was overridden.

    Lets a caller log the permission without re-deriving it: the governor needs
    the pre-override category for the action-log entry, and reading it off the
    original verdict is cheaper and less error-prone than a second classify.
    """
    profile = _active_profile
    if profile is None or not verdict.refused:
        return ""
    return verdict.category if profile.permits_category(verdict.category) else ""


def is_benchmark_permitted(verdict: DestructiveVerdict) -> bool:
    """Whether the active profile permits this refused *verdict*."""
    return bool(override_category(verdict))


__all__ = [
    "benchmark_override",
    "get_active_benchmark_profile",
    "is_benchmark_permitted",
    "override_category",
    "set_active_benchmark_profile",
]
