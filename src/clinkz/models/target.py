"""Target host and service models.

Populated by the Recon Agent (nmap, subfinder, httpx) and enriched by
subsequent phases. Stored in the state store and passed between agents.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import BaseModel, Field


class ServiceProtocol(StrEnum):
    """Network protocol for a service."""

    TCP = "tcp"
    UDP = "udp"


class Service(BaseModel):
    """A network service discovered on a host port.

    Attributes:
        port: Port number (1 – 65535).
        protocol: TCP or UDP.
        name: Service name as identified by nmap (e.g., "http", "ssh").
        product: Software product name (e.g., "Apache httpd", "OpenSSH").
        version: Product version string (e.g., "2.4.51", "8.9p1").
        banner: Raw service banner, if captured.
        extra_info: Additional nmap or tool-specific metadata.
    """

    port: int = Field(ge=1, le=65535)
    protocol: ServiceProtocol = ServiceProtocol.TCP
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    extra_info: str = ""


class Host(BaseModel):
    """A discovered target host.

    Attributes:
        id: Auto-generated UUID for tracking in the state store.
        ip: Primary IP address.
        hostnames: Resolved hostnames / domain names for this IP.
        os: Detected operating system family (e.g., "Linux", "Windows").
        os_version: OS version string (e.g., "Ubuntu 22.04").
        services: List of open ports / services.
        is_alive: Whether the host responded to probes.
        tags: Arbitrary labels (e.g., "web", "database", "cdn").
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip: str
    hostnames: list[str] = Field(default_factory=list)
    os: str = ""
    os_version: str = ""
    services: list[Service] = Field(default_factory=list)
    is_alive: bool = True
    tags: list[str] = Field(default_factory=list)

    @property
    def primary_hostname(self) -> str:
        """Return the first hostname or the IP if no hostnames are known."""
        return self.hostnames[0] if self.hostnames else self.ip

    def get_http_services(self) -> list[Service]:
        """Return services that appear to serve HTTP/HTTPS."""
        http_names = {"http", "https", "http-alt", "http-proxy", "ssl/http"}
        return [s for s in self.services if s.name.lower() in http_names]
