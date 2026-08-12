"""Recon-phase data models for the deterministic recon agent (v2).

These models represent structured output from each step of the
deterministic recon pipeline: port scanning, service detection,
technology extraction, web reconnaissance, and the final synthesis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, computed_field

# Canonical web ports. A service on one of these is treated as HTTP-capable
# even when nmap mislabels the service name (see ``ReconService.is_http``).
# Kept deliberately tight to web-serving defaults so non-web services are not
# probed as HTTP.
_KNOWN_WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888, 8008, 5000, 3000})


class DetectedComponent(BaseModel):
    """One software component a fingerprinting tool identified on the target.

    The unit of the component inventory: what a dependency→CVE lookup needs, and
    what a fingerprinting wrapper is actually able to say. ``version`` is empty
    far more often than not — a tool that names ``nginx`` without a version has
    still contributed a real observation, and a CVE lookup that needs a version
    must say it has none rather than invent one.

    Attributes:
        name: Product/technology name as the tool reported it ("nginx", "Express").
        version: Version string exactly as observed, or ``""`` when the tool
            identified the product but not its version. NEVER inferred.
        source: How it was observed — the tool name plus the evidence kind
            ("whatweb:plugin", "nmap:service", "httpx:tech"). Carried so a lead
            built from this can name what saw it.
        port: TCP port the component was observed on, when the observation was
            port-scoped (a service banner). ``0`` for a web-layer observation.
    """

    name: str
    version: str = ""
    source: str = ""
    port: int = 0

    def identity(self) -> tuple[str, str]:
        """Case-normalised ``(name, version)``, for dedup across tools."""
        return self.name.strip().lower(), self.version.strip()


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
        """True if this service appears to be HTTP/HTTPS.

        A known web port qualifies as HTTP-capable *regardless* of the name
        nmap assigned it. nmap labels a port from its ``/etc/services`` default
        when ``-sV`` cannot fingerprint the protocol (e.g. 3000/tcp → ``ppp``),
        which previously bypassed the empty-name fallback and silently skipped
        web recon on a live web app. Since Clinkz is web-focused, attempting
        HTTP against a known web port is always correct — the probe simply
        fails fast if the service is genuinely non-HTTP. The set is kept tight
        (canonical web ports only) so genuinely non-web ports (e.g. 22/ssh)
        are never probed as HTTP.
        """
        http_names = {"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"}
        if self.service_name.lower() in http_names:
            return True
        return self.port in _KNOWN_WEB_PORTS


class ServiceScanResult(BaseModel):
    """Structured output from service/version detection scan."""

    services: list[ReconService] = Field(default_factory=list)
    raw_output: str = ""
    tool_used: str = ""
    #: Service banners the scanner resolved to a product + version. Populated
    #: from the scanner's declared component contract, so a wrapper that stops
    #: declaring it produces a loud dead seam rather than a silent empty list.
    components: list[DetectedComponent] = Field(default_factory=list)


class Technology(BaseModel):
    """A single technology identified in the target's stack."""

    name: str
    version: str | None = None
    category: str = "other"  # web_server, language, framework, database, os, other


class TechStack(BaseModel):
    """Complete technology stack extracted by LLM analysis."""

    technologies: list[Technology] = Field(default_factory=list)


def dedupe_components(components: list[DetectedComponent]) -> list[DetectedComponent]:
    """Collapse duplicate observations, preferring the one carrying a version.

    Two tools naming the same product is the normal case (nmap's banner and
    whatweb's plugin both say "nginx"), and only one of them usually knows the
    version. Keeping the versioned observation is what makes the inventory
    useful; keeping both would make a downstream CVE lookup run twice and report
    the unversioned one as "version unknown" beside the answer.

    Order is preserved on first appearance, so the result is deterministic.

    Args:
        components: Observations in the order they were collected.

    Returns:
        One entry per ``(lowercased name, port)``, versioned where any observer
        supplied a version.
    """
    by_key: dict[tuple[str, int], DetectedComponent] = {}
    order: list[tuple[str, int]] = []
    for component in components:
        name = component.name.strip()
        if not name:
            continue
        key = (name.lower(), component.port)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = component
            order.append(key)
        elif not existing.version and component.version:
            by_key[key] = component
    return [by_key[key] for key in order]


class WebReconResult(BaseModel):
    """Structured output from HTTP-specific reconnaissance."""

    fingerprints: list[dict[str, Any]] = Field(default_factory=list)
    waf_detected: bool = False
    waf_name: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    technologies_found: list[str] = Field(default_factory=list)
    #: Components the web-layer fingerprinters named, versions included. Kept
    #: alongside ``technologies_found`` (a bare name list several consumers
    #: already read) rather than replacing it, so this is additive.
    components: list[DetectedComponent] = Field(default_factory=list)


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
    #: Every component any fingerprinting tool named this run — the service
    #: banners nmap resolved plus whatever the web-layer fingerprinter added,
    #: deduplicated on ``(name, version, port)``. This is the inventory the
    #: dependency→CVE path keys on, and it is deliberately a RECON output: what
    #: software is running is an observation, and which of it is vulnerable is a
    #: separate question answered later, by a different agent, against evidence.
    components: list[DetectedComponent] = Field(default_factory=list)
