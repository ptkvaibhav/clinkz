"""Scope and engagement configuration models.

The EngagementScope defines exactly what is permitted to test.
Every tool wrapper calls scope.contains(target) before running.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class ScopeType(StrEnum):
    """Classification of a scope entry."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


class ScopeEntry(BaseModel):
    """A single in-scope (or out-of-scope) target."""

    value: str = Field(description="IP, CIDR block, domain, or URL")
    type: ScopeType
    notes: str = Field(default="", description="Optional context for this entry")

    @field_validator("value")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class EngagementScope(BaseModel):
    """Full scope definition for a pentest engagement.

    Loaded from a JSON file passed via --scope on the CLI,
    or constructed programmatically for testing.

    Example scope.json::

        {
            "name": "ACME Corp Q1 2025",
            "targets": [
                {"value": "10.10.10.0/24", "type": "cidr"},
                {"value": "app.acme.com",  "type": "domain"}
            ],
            "excluded": [
                {"value": "10.10.10.1", "type": "ip", "notes": "Production gateway — no touch"}
            ]
        }
    """

    name: str = Field(description="Human-readable engagement name")
    description: str = Field(default="")
    targets: list[ScopeEntry] = Field(description="In-scope targets")
    excluded: list[ScopeEntry] = Field(
        default_factory=list,
        description="Explicitly excluded targets (takes precedence over targets)",
    )
    max_rate: int = Field(default=100, description="Max requests per second across all tools")
    allowed_ports: list[int] = Field(
        default_factory=list,
        description="Whitelist of ports to test. Empty list means all ports allowed.",
    )

    def contains(self, target: str) -> bool:
        """Check if a target IP, domain, or URL is within scope.

        If *target* looks like a URL (has a ``://`` scheme), the hostname
        is extracted and checked instead.  Port numbers are stripped so
        that ``http://172.20.0.2:3000`` correctly matches a scope entry
        of ``172.20.0.2``.

        Checks exclusions first (exclusions take precedence).

        Args:
            target: IP address, hostname, or URL to check.

        Returns:
            True if target is in scope and not excluded.
        """
        normalized = self._extract_host(target)
        if self._matches_any(normalized, self.excluded):
            return False
        return self._matches_any(normalized, self.targets)

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract the bare hostname/IP from a target string.

        Handles URLs (``http://1.2.3.4:8080/path``) and ``host:port``
        notation.  Returns the input unchanged if it is already a bare
        hostname or IP.
        """
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        # Strip a trailing port (e.g. "172.20.0.2:3000")
        if ":" in target:
            host, _, port = target.rpartition(":")
            if port.isdigit():
                return host
        return target

    def _matches_any(self, target: str, entries: list[ScopeEntry]) -> bool:
        """Return True if target matches any entry in the list."""
        for entry in entries:
            if self._matches_entry(target, entry):
                return True
        return False

    def _matches_entry(self, target: str, entry: ScopeEntry) -> bool:
        """Check if target matches a single scope entry."""
        if entry.type == ScopeType.IP:
            return target == entry.value

        if entry.type == ScopeType.CIDR:
            try:
                network = ipaddress.ip_network(entry.value, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in network
            except ValueError:
                return False

        if entry.type in (ScopeType.DOMAIN, ScopeType.URL):
            # Normalize the entry value the same way we normalize the target
            entry_host = self._extract_host(entry.value)
            # Simple suffix match — handles subdomains
            return target == entry_host or target.endswith(f".{entry_host}")

        return False
