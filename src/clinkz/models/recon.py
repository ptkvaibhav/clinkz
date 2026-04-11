"""Recon-phase data models for the deterministic recon agent (v2).

These models represent structured output from each step of the
deterministic recon pipeline: port scanning, service detection,
technology extraction, web reconnaissance, and the final synthesis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, computed_field


class PortScanResult(BaseModel):
    """Structured output from a full TCP port scan."""

    open_ports: list[int] = Field(default_factory=list)
    raw_output: str = ""
    tool_used: str = ""


class ReconService(BaseModel):
    """A service discovered during version/script scanning.

    Unlike ``models.target.Service`` (which is the canonical storage model),
    this model is specific to the recon agent's internal pipeline and includes
    the ``is_http`` computed property used to decide whether web recon is needed.
    """

    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str = ""
    version: str | None = None
    scripts_output: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_http(self) -> bool:
        """True if this service appears to be HTTP/HTTPS."""
        http_names = {"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"}
        if self.service_name.lower() in http_names:
            return True
        # Common HTTP ports as fallback when service name is unknown
        if self.service_name == "" and self.port in {80, 443, 8080, 8443, 8000, 8888, 3000}:
            return True
        return False


class ServiceScanResult(BaseModel):
    """Structured output from service/version detection scan."""

    services: list[ReconService] = Field(default_factory=list)
    raw_output: str = ""
    tool_used: str = ""


class Technology(BaseModel):
    """A single technology identified in the target's stack."""

    name: str
    version: str | None = None
    category: str = "other"  # web_server, language, framework, database, os, other


class TechStack(BaseModel):
    """Complete technology stack extracted by LLM analysis."""

    technologies: list[Technology] = Field(default_factory=list)


class WebReconResult(BaseModel):
    """Structured output from HTTP-specific reconnaissance."""

    fingerprints: list[dict[str, Any]] = Field(default_factory=list)
    waf_detected: bool = False
    waf_name: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    technologies_found: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Final output of the deterministic recon agent.

    Consumed by the Orchestrator and downstream agents (Scan, Exploit).
    """

    target: str
    ports: PortScanResult
    services: ServiceScanResult
    web_info: WebReconResult | None = None
    tech_stack: TechStack
    llm_summary: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
