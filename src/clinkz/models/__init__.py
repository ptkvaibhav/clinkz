"""Pydantic v2 data models for Clinkz.

All tool outputs and inter-agent data must be represented as one of these models.
Never pass raw strings between agents.
"""

from clinkz.models.finding import Finding, FindingStatus, Severity
from clinkz.models.report import ExecutiveSummary, PentestReport, ReportFormat
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host, Service, ServiceProtocol

__all__ = [
    "EngagementScope",
    "ScopeEntry",
    "ScopeType",
    "Finding",
    "FindingStatus",
    "Severity",
    "Host",
    "Service",
    "ServiceProtocol",
    "PentestReport",
    "ExecutiveSummary",
    "ReportFormat",
]
