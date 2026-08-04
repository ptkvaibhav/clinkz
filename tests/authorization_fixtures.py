"""Shared authorization record for tests that start a real engagement.

:meth:`~clinkz.orchestrator.orchestrator.OrchestratorAgent.run` refuses to start
without an :class:`~clinkz.models.engagement.AuthorizationRecord` — that refusal
is the product requirement, not an inconvenience, so tests carry a record rather
than the gate carrying an exception for tests.

Kept as a module (not a fixture) because most suites attach the record to a
module-level ``SCOPE`` constant, which a pytest fixture cannot reach.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from clinkz.models.engagement import AuthorizationRecord, EngagementWindow

#: A complete, valid authorization record. Every field is populated because the
#: model rejects a blank one — which is the point of the model.
TEST_AUTHORIZATION = AuthorizationRecord(
    authorizing_party="Test Authorizer",
    authorizing_role="Head of Engineering",
    authorizing_contact="authorizer@example.test",
    authorization_reference="TEST-SOW-0001",
    permitted_techniques=["*"],
    emergency_contact="oncall@example.test",
    notes="Synthetic authorization for the test suite.",
)


def open_window(hours: int = 24) -> EngagementWindow:
    """Return a window that is open right now.

    Args:
        hours: How far the window extends in each direction.

    Returns:
        An :class:`~clinkz.models.engagement.EngagementWindow` containing now.
    """
    now = datetime.now(UTC)
    return EngagementWindow(start=now - timedelta(hours=hours), end=now + timedelta(hours=hours))


__all__ = ["TEST_AUTHORIZATION", "open_window"]
