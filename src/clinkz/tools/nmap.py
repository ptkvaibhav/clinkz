"""Nmap tool wrapper — port scanning and service fingerprinting.

Sample fixture: tests/fixtures/nmap_sample_output.xml
"""

from __future__ import annotations

# defusedxml hardens parsing against XML attacks (XXE, billion laughs, etc.) —
# nmap output reflects target-controlled banners/hostnames, so treat it as
# untrusted even though we invoke the tool ourselves.
from typing import Any
from xml.etree.ElementTree import Element  # noqa: S405 — type only, parsing uses defusedxml

from defusedxml import ElementTree as ET  # noqa: N817 — ET is the canonical ElementTree alias

from clinkz.models.target import Host, Service, ServiceProtocol
from clinkz.tools.base import ToolBase, ToolOutput


class NmapOutput(ToolOutput):
    """Structured output from an nmap scan."""

    hosts: list[Host] = []
    open_ports: list[int] = []


class NmapTool(ToolBase):
    """Nmap port scanner and service fingerprinter.

    Runs: nmap -sV -sC -oX - <target> -p <ports>
    """

    capabilities = ["port_scanning", "service_detection", "os_fingerprinting", "host_discovery"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Scan a target for open ports and identify running services."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification. ONLY accepts: comma-separated numbers like '80,443,3000' or ranges like '1-1000'. Never use words like 'common', 'top', 'all', or 'default'. Examples of VALID values: '22,80,443', '1-1000', '80,443,8000-9000'. Examples of INVALID values: 'common', 'top_1000', 'all'.",  # noqa: E501
                        "default": "1-1000",
                    },
                    "flags": {
                        "type": "string",
                        "description": "Additional nmap flags (e.g., '-sU' for UDP, '--script vuln').",  # noqa: E501
                        "default": "",
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required for nmap")
        self._check_scope(target)
        import re

        ports = args.get("ports", "1-1000")
        # Reject non-numeric port specs (e.g. "common", "top_1000")
        if not re.fullmatch(r"[\d,\- ]+", ports):
            ports = "1-1000"

        # Sanitize flags — block dangerous nmap options that could write files,
        # execute scripts from untrusted paths, or perform destructive actions.
        flags = args.get("flags", "")
        _blocked = {
            "--script-args-file",
            "--datadir",
            "-oN",
            "-oX",
            "-oS",
            "-oG",
            "-oA",
            "--resume",
            "--stylesheet",
            "--webxml",
            "--append-output",
            "--interactive",
            "-iL",
            "-iR",
            "--excludefile",
        }
        if flags:
            for token in flags.split():
                flag_name = token.split("=")[0]
                if flag_name in _blocked:
                    raise ValueError(f"Blocked nmap flag: {flag_name}")

        return {
            "target": target,
            "ports": ports,
            "flags": flags,
        }

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "-oX",
            "-",  # XML output to stdout
            "-p",
            args["ports"],
        ]
        if args.get("flags"):
            cmd.extend(args["flags"].split())
        cmd.append(args["target"])
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> NmapOutput:
        """Parse nmap XML output into Host and Service Pydantic models.

        Args:
            raw_output: Raw XML string from nmap -oX.

        Returns:
            NmapOutput with fully populated hosts and open_ports lists.
        """
        if not raw_output or not raw_output.strip():
            return NmapOutput(tool_name=self.name, success=False, raw_output=raw_output)

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as exc:
            return NmapOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"XML parse error: {exc}",
            )

        hosts: list[Host] = []

        for host_el in root.findall("host"):
            # ------------------------------------------------------------------
            # Status
            # ------------------------------------------------------------------
            status_el = host_el.find("status")
            is_alive = status_el is not None and status_el.get("state") == "up"

            # ------------------------------------------------------------------
            # Primary IPv4 address
            # ------------------------------------------------------------------
            ip = ""
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ip = addr_el.get("addr", "")
                    break
            if not ip:
                continue  # skip hosts with no IPv4 address

            # ------------------------------------------------------------------
            # Hostnames
            # ------------------------------------------------------------------
            hostnames: list[str] = []
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn_el in hostnames_el.findall("hostname"):
                    name = hn_el.get("name", "")
                    if name:
                        hostnames.append(name)

            # ------------------------------------------------------------------
            # OS detection — pick osmatch with highest accuracy
            # ------------------------------------------------------------------
            os_family = ""
            os_version = ""
            os_el = host_el.find("os")
            if os_el is not None:
                best_match: Element | None = None
                best_accuracy = -1
                for osmatch_el in os_el.findall("osmatch"):
                    accuracy = int(osmatch_el.get("accuracy", "0"))
                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best_match = osmatch_el
                if best_match is not None:
                    os_version = best_match.get("name", "")
                    osclass_el = best_match.find("osclass")
                    if osclass_el is not None:
                        os_family = osclass_el.get("osfamily", "")

            # ------------------------------------------------------------------
            # Open ports / services
            # ------------------------------------------------------------------
            services: list[Service] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    port_num = int(port_el.get("portid", "0"))
                    try:
                        protocol = ServiceProtocol(port_el.get("protocol", "tcp"))
                    except ValueError:
                        protocol = ServiceProtocol.TCP

                    svc_name = product = version = extra_info = ""
                    svc_el = port_el.find("service")
                    if svc_el is not None:
                        svc_name = svc_el.get("name", "")
                        product = svc_el.get("product", "")
                        version = svc_el.get("version", "")
                        extra_info = svc_el.get("extrainfo", "")

                    # NSE script outputs
                    scripts: dict[str, str] = {}
                    for script_el in port_el.findall("script"):
                        script_id = script_el.get("id", "")
                        if script_id:
                            scripts[script_id] = script_el.get("output", "")

                    services.append(
                        Service(
                            port=port_num,
                            protocol=protocol,
                            name=svc_name,
                            product=product,
                            version=version,
                            extra_info=extra_info,
                            scripts=scripts,
                        )
                    )

            hosts.append(
                Host(
                    ip=ip,
                    hostnames=hostnames,
                    os=os_family,
                    os_version=os_version,
                    services=services,
                    is_alive=is_alive,
                )
            )

        open_ports = sorted({svc.port for host in hosts for svc in host.services})
        return NmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=hosts,
            open_ports=open_ports,
        )
