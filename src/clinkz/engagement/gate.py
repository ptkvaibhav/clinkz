"""The engagement gate — the refusals that happen before anything is sent.

Two things an autonomous pentest must never do: run without written
authorization, and run outside the window it was authorized for. Both are
enforced here, at :meth:`~clinkz.orchestrator.orchestrator.OrchestratorAgent.run`
entry and then continuously at the request chokepoint.

This module is deliberately dependency-free apart from the models — it must be
importable from :mod:`clinkz.safety.governor` without an import cycle, because
the governor re-checks the window on every request.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from clinkz.models.engagement import AuthorizationRecord, EngagementWindow

if TYPE_CHECKING:  # pragma: no cover — typing only
    from clinkz.models.scope import EngagementScope

logger = logging.getLogger(__name__)


class EngagementAbortedError(Exception):
    """Base class for every condition that stops an engagement outright.

    Distinct from an ordinary error: an abort means the engagement is not
    permitted to continue, so callers propagate it rather than retrying.
    """


class AuthorizationRequiredError(EngagementAbortedError):
    """Raised when an engagement is started without an authorization record."""


class EngagementWindowClosedError(EngagementAbortedError):
    """Raised when the current moment falls outside the authorized window."""


def require_authorization(scope: EngagementScope) -> AuthorizationRecord:
    """Return the scope's authorization record, refusing when it is absent.

    This is the single refusal that makes the authorization record a required
    input rather than an optional flag: an engagement cannot reach its first
    tool call without passing through here.

    Args:
        scope: The engagement scope.

    Returns:
        The validated :class:`~clinkz.models.engagement.AuthorizationRecord`.

    Raises:
        AuthorizationRequiredError: When the scope carries no authorization record.
    """
    record = scope.authorization
    if record is None:
        raise AuthorizationRequiredError(
            "Refusing to start: this engagement has no authorization record.\n"
            "A real engagement requires the authorizing party's name, role and "
            "contact, the authorization reference, the permitted-technique list, "
            "and an emergency contact.\n"
            "Supply them with --authorization <file.json>, or as an "
            '"authorization" object inside the --scope file.'
        )
    return record


def require_window_open(
    window: EngagementWindow | None,
    *,
    at: datetime | None = None,
) -> None:
    """Refuse when *at* (default: now) falls outside the authorized window.

    A ``None`` window means the operator did not agree a window; that is
    permitted (not every engagement is time-boxed) and this check passes. What
    is NOT permitted is a window that exists and has closed.

    Args:
        window: The agreed window, or ``None``.
        at: Moment to check; defaults to now (UTC).

    Raises:
        EngagementWindowClosedError: Before the window opens or after it closes.
    """
    if window is None:
        return
    moment = at or datetime.now(UTC)
    if not window.has_started(moment):
        raise EngagementWindowClosedError(
            f"Refusing to start: the engagement window opens at "
            f"{window.start.isoformat()} and it is now {moment.isoformat()}."
        )
    if window.has_ended(moment):
        raise EngagementWindowClosedError(
            f"Hard stop: the engagement window closed at {window.end.isoformat()} "
            f"and it is now {moment.isoformat()}. No further requests will be sent."
        )


def open_engagement(
    scope: EngagementScope,
    *,
    at: datetime | None = None,
) -> AuthorizationRecord:
    """Run every start-of-engagement refusal and return the authorization.

    Args:
        scope: The engagement scope.
        at: Moment to evaluate the window against; defaults to now.

    Returns:
        The authorization record.

    Raises:
        AuthorizationRequiredError: No authorization record.
        EngagementWindowClosedError: Outside the authorized window.
    """
    record = require_authorization(scope)
    require_window_open(scope.window, at=at)
    logger.info(
        "Engagement authorized by %s (%s) under reference %s — permitted techniques: %s",
        record.authorizing_party,
        record.authorizing_role,
        record.authorization_reference,
        "ALL" if record.permits_all else ", ".join(record.permitted_techniques),
    )
    if scope.window is not None:
        logger.info(
            "Engagement window: %s → %s (%.0f minutes remaining)",
            scope.window.start.isoformat(),
            scope.window.end.isoformat(),
            scope.window.remaining_seconds(at) / 60.0,
        )
    return record


__all__ = [
    "AuthorizationRequiredError",
    "EngagementAbortedError",
    "EngagementWindowClosedError",
    "open_engagement",
    "require_authorization",
    "require_window_open",
]
