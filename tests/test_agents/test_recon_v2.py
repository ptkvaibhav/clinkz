"""Tests for deterministic ReconAgent v2 — structured steps with LLM checkpoints.

Coverage:
- test_recon_step_sequence: all 7 steps run in order
- test_recon_no_web_services: step 5 skipped when no HTTP ports
- test_recon_tool_fallback: nmap unavailable → fallback to next tool
- test_recon_result_structure: ReconResult has all required fields
- test_recon_models: all Pydantic models serialize/deserialize correctly
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from clinkz.agents.recon import ReconAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.recon import (
    PortScanResult,
    ReconResult,
    ReconService,
    ServiceScanResult,
    Technology,
    TechStack,
    WebReconResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.target import Host, Service
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.nmap import NmapTool
from clinkz.tools.resolver import ToolMatch, ToolResolver

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="recon-v2-test",
    targets=[ScopeEntry(value="10.0.0.1", type=ScopeType.IP)],
)

# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


class MockLLM(LLMClient):
    """Deterministic LLM for recon v2 tests.

    generate_text() returns predictable responses based on prompt content.
    reason() is not used by the v2 agent (it calls generate_text directly).
    """

    def __init__(self) -> None:
        self.generate_text_calls: list[str] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> Any:
        raise NotImplementedError("v2 ReconAgent does not use reason()")

    async def research(self, query: str) -> str:
        return "No research results."

    async def generate_text(self, prompt: str) -> str:
        self.generate_text_calls.append(prompt)

        if "port scan results" in prompt.lower():
            return "Port 80 (HTTP) and 443 (HTTPS) are open. Priority: web services."

        if "technology stack" in prompt.lower() or "extract" in prompt.lower():
            return json.dumps(
                [
                    {"name": "nginx", "version": "1.24", "category": "web_server"},
                    {"name": "PHP", "version": "8.1", "category": "language"},
                ]
            )

        if "synthesiz" in prompt.lower():
            return (
                "Attack surface: 2 open ports (80, 443) running nginx 1.24 with PHP 8.1. "
                "Recommended: test for web vulnerabilities, check PHP CVEs."
            )

        return "LLM analysis complete."


# ---------------------------------------------------------------------------
# Mock tool outputs
# ---------------------------------------------------------------------------


class _MockNmapOutput(ToolOutput):
    """Mock nmap output with hosts and open_ports."""

    hosts: list[Host] = []
    open_ports: list[int] = []


class _MockWhatWebOutput(ToolOutput):
    """Mock whatweb output."""

    results: list[dict[str, Any]] = []


class _MockWafw00fOutput(ToolOutput):
    """Mock wafw00f output."""

    results: list[dict[str, Any]] = []


class _MockHTTPOutput(ToolOutput):
    """Mock HTTP client output."""

    response_headers: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Mock tool classes
# ---------------------------------------------------------------------------


class _MockNmapTool(ToolBase):
    """Returns one host at 10.0.0.1 with ports 80/443."""

    capabilities = ["port_scanning", "service_detection"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock port scanner"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock nmap output"

    def parse_output(self, raw_output: str) -> _MockNmapOutput:
        host = Host(
            ip="10.0.0.1",
            hostnames=["target.local"],
            services=[
                Service(port=80, name="http", product="nginx", version="1.24"),
                Service(port=443, name="https", product="nginx", version="1.24"),
            ],
        )
        return _MockNmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=[host],
            open_ports=[80, 443],
        )


class _MockNmapNoHTTPTool(ToolBase):
    """Returns host with only SSH (no HTTP services)."""

    capabilities = ["port_scanning", "service_detection"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock port scanner (no HTTP)"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock nmap output ssh only"

    def parse_output(self, raw_output: str) -> _MockNmapOutput:
        host = Host(
            ip="10.0.0.1",
            hostnames=["target.local"],
            services=[
                Service(port=22, name="ssh", product="OpenSSH", version="8.9p1"),
            ],
        )
        return _MockNmapOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            hosts=[host],
            open_ports=[22],
        )


class _MockWhatWebTool(ToolBase):
    """Mock web fingerprinter."""

    capabilities = ["web_fingerprinting"]
    category = "recon"

    @property
    def name(self) -> str:
        return "whatweb"

    @property
    def description(self) -> str:
        return "Mock whatweb"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock whatweb output"

    def parse_output(self, raw_output: str) -> _MockWhatWebOutput:
        return _MockWhatWebOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=[{"technologies": ["nginx", "PHP"]}],
        )


class _MockWafw00fTool(ToolBase):
    """Mock WAF detector — no WAF found."""

    capabilities = ["waf_detection"]
    category = "recon"

    @property
    def name(self) -> str:
        return "wafw00f"

    @property
    def description(self) -> str:
        return "Mock wafw00f"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "no waf detected"

    def parse_output(self, raw_output: str) -> _MockWafw00fOutput:
        return _MockWafw00fOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            results=[{"waf_detected": False}],
        )


# ---------------------------------------------------------------------------
# Resolver factories
# ---------------------------------------------------------------------------


# Real Juice Shop service-scan nmap output: port 3000 is a live web app, but
# nmap labels it ``ppp`` (its /etc/services default when -sV can't fingerprint).
# Used by the recon-side mirror test below.
_JUICESHOP_PPP_XML = (
    Path(__file__).parent.parent / "fixtures" / "nmap_juiceshop_ppp.xml"
).read_text(encoding="utf-8")


class _MockNmapPppTool(ToolBase):
    """Service-detection tool returning the REAL Juice Shop nmap output.

    ``parse_output`` delegates to the real :class:`NmapTool` parser so recon's
    assembly runs over genuine tool output where the web port (3000) carries a
    mislabeled ``ppp`` service name.
    """

    capabilities = ["port_scanning", "service_detection"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock nmap returning real Juice Shop ppp output"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return _JUICESHOP_PPP_XML

    def parse_output(self, raw_output: str) -> Any:
        return NmapTool(scope=SCOPE).parse_output(raw_output)


def _make_resolver(
    *,
    nmap_cls: type[ToolBase] = _MockNmapTool,
    include_web: bool = True,
) -> ToolResolver:
    """Build a mock ToolResolver with configurable tool classes."""
    resolver = MagicMock(spec=ToolResolver)

    _cap_map: dict[str, tuple[type[ToolBase], str]] = {
        "port_scanning": (nmap_cls, "nmap"),
        "service_detection": (nmap_cls, "nmap"),
    }
    if include_web:
        _cap_map["web_fingerprinting"] = (_MockWhatWebTool, "whatweb")
        _cap_map["waf_detection"] = (_MockWafw00fTool, "wafw00f")

    def _find_tool(cap: str) -> ToolMatch | None:
        entry = _cap_map.get(cap)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find_tool
    resolver.find_tools_ranked.return_value = ["nmap"]
    return resolver


def _make_fallback_resolver() -> ToolResolver:
    """Build a resolver where nmap fails and masscan is the fallback.

    Mock tool classes are defined locally to avoid polluting
    ToolBase.__subclasses__() (which the ToolResolver auto-discovers).
    """

    class _UnavailableNmap(ToolBase):
        capabilities: list[str] = []
        category = "recon"

        @property
        def name(self) -> str:
            return "nmap"

        @property
        def description(self) -> str:
            return "Mock unavailable nmap"

        def get_schema(self) -> dict[str, Any]:
            return {"name": self.name, "description": self.description, "parameters": {}}

        def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
            return args

        async def execute(self, args: dict[str, Any]) -> str:
            raise FileNotFoundError("nmap not found")

        def parse_output(self, raw_output: str) -> _MockNmapOutput:
            return _MockNmapOutput(tool_name=self.name, success=False, raw_output="")

    class _Masscan(ToolBase):
        capabilities: list[str] = []
        category = "recon"

        @property
        def name(self) -> str:
            return "masscan"

        @property
        def description(self) -> str:
            return "Mock masscan fallback"

        def get_schema(self) -> dict[str, Any]:
            return {"name": self.name, "description": self.description, "parameters": {}}

        def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
            return args

        async def execute(self, args: dict[str, Any]) -> str:
            return "mock masscan output"

        def parse_output(self, raw_output: str) -> _MockNmapOutput:
            host = Host(
                ip="10.0.0.1",
                hostnames=[],
                services=[
                    Service(port=80, name="http"),
                    Service(port=22, name="ssh"),
                ],
            )
            return _MockNmapOutput(
                tool_name=self.name,
                success=True,
                raw_output=raw_output,
                hosts=[host],
                open_ports=[22, 80],
            )

    resolver = MagicMock(spec=ToolResolver)

    _call_count = {"port_scanning": 0}

    def _find_tool(cap: str) -> ToolMatch | None:
        if cap == "port_scanning":
            _call_count["port_scanning"] += 1
            # First call returns nmap (which will fail), second returns masscan
            if _call_count["port_scanning"] <= 1:
                return ToolMatch(
                    name="nmap",
                    source="local",
                    available=True,
                    tool_class=_UnavailableNmap,
                )
            return ToolMatch(
                name="masscan",
                source="local",
                available=True,
                tool_class=_Masscan,
            )
        if cap == "service_detection":
            return ToolMatch(
                name="nmap",
                source="local",
                available=True,
                tool_class=_MockNmapTool,
            )
        return None

    resolver.find_tool.side_effect = _find_tool
    resolver.find_tools_ranked.return_value = ["nmap", "masscan"]
    return resolver


# ---------------------------------------------------------------------------
# Mock HTTPClientTool (prevents real HTTP requests in tests)
# ---------------------------------------------------------------------------


class _MockHTTPClientTool:
    """Stand-in for HTTPClientTool to avoid real network calls."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return '{"status_code": 200}'

    def parse_output(self, raw_output: str) -> MagicMock:
        mock = MagicMock()
        mock.response_headers = {"Server": "nginx/1.24", "X-Powered-By": "PHP/8.1"}
        return mock


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------


async def _make_agent(
    db_path: Path,
    resolver: Any = None,
    llm: LLMClient | None = None,
) -> tuple[ReconAgent, StateStore, str]:
    """Create a ReconAgent with mock dependencies."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("recon-v2-test", SCOPE.model_dump())
    agent = ReconAgent(
        llm=llm or MockLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
        resolver=resolver if resolver is not None else _make_resolver(),
    )
    return agent, state, eid


# ---------------------------------------------------------------------------
# Test: step sequence (all 7 steps run in order)
# ---------------------------------------------------------------------------


@patch("clinkz.tools.http_client.HTTPClientTool", _MockHTTPClientTool)
async def test_recon_step_sequence(tmp_path: Path) -> None:
    """All 7 steps execute in the correct order."""
    llm = MockLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm)

    result = await agent.run({"target": "10.0.0.1"})
    await state.close()

    assert result["status"] == "complete"

    # LLM should have been called 3 times (steps 2, 4, 6)
    assert len(llm.generate_text_calls) == 3

    # Step 2: port analysis
    assert "port scan results" in llm.generate_text_calls[0].lower()

    # Step 4: technology extraction
    assert "technology stack" in llm.generate_text_calls[1].lower()

    # Step 6: synthesis
    assert "synthesiz" in llm.generate_text_calls[2].lower()


# ---------------------------------------------------------------------------
# Test: no web services → step 5 skipped
# ---------------------------------------------------------------------------


async def test_recon_no_web_services(tmp_path: Path) -> None:
    """When no HTTP ports are found, web recon (step 5) is skipped."""
    resolver = _make_resolver(nmap_cls=_MockNmapNoHTTPTool, include_web=True)
    llm = MockLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver, llm=llm)

    result = await agent.run({"target": "10.0.0.1"})
    await state.close()

    assert result["status"] == "complete"
    # web_info should be None (step 5 skipped)
    assert result["result"]["web_info"] is None

    # web_fingerprinting and waf_detection should NOT have been called
    find_tool_caps = [call.args[0] for call in resolver.find_tool.call_args_list]
    assert "web_fingerprinting" not in find_tool_caps
    assert "waf_detection" not in find_tool_caps


# ---------------------------------------------------------------------------
# Test: tool fallback (nmap unavailable → next tool in chain)
# ---------------------------------------------------------------------------


@patch("clinkz.tools.http_client.HTTPClientTool", _MockHTTPClientTool)
async def test_recon_tool_fallback(tmp_path: Path) -> None:
    """When nmap fails, the agent falls back to the next tool in the chain."""
    resolver = _make_fallback_resolver()
    llm = MockLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver, llm=llm)

    result = await agent.run({"target": "10.0.0.1"})
    await state.close()

    assert result["status"] == "complete"
    # Port scan should have found ports via masscan fallback
    ports = result["result"]["ports"]
    assert len(ports["open_ports"]) > 0
    assert ports["tool_used"] == "masscan"


# ---------------------------------------------------------------------------
# Test: result structure
# ---------------------------------------------------------------------------


@patch("clinkz.tools.http_client.HTTPClientTool", _MockHTTPClientTool)
async def test_recon_result_structure(tmp_path: Path) -> None:
    """ReconResult contains all required fields with correct types."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"target": "10.0.0.1"})
    await state.close()

    r = result["result"]

    # Required top-level fields
    assert r["target"] == "10.0.0.1"
    assert isinstance(r["ports"], dict)
    assert isinstance(r["services"], dict)
    assert isinstance(r["tech_stack"], dict)
    assert isinstance(r["llm_summary"], str)
    assert r["llm_summary"]  # non-empty
    assert "timestamp" in r

    # Ports structure
    assert isinstance(r["ports"]["open_ports"], list)
    assert isinstance(r["ports"]["tool_used"], str)

    # Services structure
    assert isinstance(r["services"]["services"], list)
    if r["services"]["services"]:
        svc = r["services"]["services"][0]
        assert "port" in svc
        assert "service_name" in svc
        assert "is_http" in svc

    # Tech stack structure
    assert isinstance(r["tech_stack"]["technologies"], list)
    if r["tech_stack"]["technologies"]:
        tech = r["tech_stack"]["technologies"][0]
        assert "name" in tech
        assert "category" in tech

    # Web info (present because we have HTTP ports)
    assert r["web_info"] is not None
    assert "waf_detected" in r["web_info"]
    assert "headers" in r["web_info"]


# ---------------------------------------------------------------------------
# Test: recon assembly emits an HTTP service for a mislabeled known web port
# ---------------------------------------------------------------------------


async def test_recon_emits_http_service_for_mislabeled_web_port(tmp_path: Path) -> None:
    """Recon's result-assembly emits an HTTP-capable service for a known web
    port even when nmap mislabels the name (Juice Shop port 3000 -> 'ppp').

    This is the recon-side mirror of the is_http model fix and the regression
    guard for the recon->scan empty-services blocker: the service that scan
    must receive to fire its crawl branch is built here, from real nmap output,
    by ``_step_service_scan``. If recon drops the mislabeled web service, scan
    sees no HTTP service and ``service_scans`` comes back empty.
    """
    resolver = _make_resolver(nmap_cls=_MockNmapPppTool, include_web=False)
    agent, state, _ = await _make_agent(tmp_path / "ppp.db", resolver=resolver)
    services = await agent._step_service_scan("clinkz-juiceshop", [3000])
    await state.close()

    assert services.services, "recon dropped the mislabeled port-3000 web service"
    svc = next((s for s in services.services if s.port == 3000), None)
    assert svc is not None, "port-3000 service missing from recon assembly"
    assert svc.service_name == "ppp"  # nmap's mislabel is preserved verbatim...
    assert svc.is_http is True  # ...but recon still classifies it HTTP-capable
    # has_http gate (recon Step-5 web recon, and scan's crawl branch) must fire.
    assert any(s.is_http for s in services.services)


# ---------------------------------------------------------------------------
# Test: Pydantic model serialization/deserialization
# ---------------------------------------------------------------------------


class TestReconModels:
    """Test all recon Pydantic models serialize and deserialize correctly."""

    def test_port_scan_result(self) -> None:
        psr = PortScanResult(open_ports=[22, 80, 443], raw_output="nmap output", tool_used="nmap")
        data = psr.model_dump()
        restored = PortScanResult.model_validate(data)
        assert restored.open_ports == [22, 80, 443]
        assert restored.tool_used == "nmap"

    def test_recon_service_is_http(self) -> None:
        http_svc = ReconService(port=80, service_name="http")
        assert http_svc.is_http is True

        https_svc = ReconService(port=443, service_name="https")
        assert https_svc.is_http is True

        ssh_svc = ReconService(port=22, service_name="ssh")
        assert ssh_svc.is_http is False

        # Unknown service on common HTTP port → is_http True
        unknown_80 = ReconService(port=80, service_name="")
        assert unknown_80.is_http is True

        # Known web port mislabeled by nmap (3000/tcp → "ppp" from /etc/services,
        # which is what happened to Juice Shop) → still is_http True. This is the
        # regression: a non-empty, non-http name on a known web port must not
        # bypass the web-port fallback.
        ppp_3000 = ReconService(port=3000, service_name="ppp")
        assert ppp_3000.is_http is True

        # Other known web ports with non-http names also qualify.
        for web_port in (8080, 8000, 5000, 8443):
            svc = ReconService(port=web_port, service_name="unknown")
            assert svc.is_http is True, f"port {web_port} should be HTTP-capable"

        # Unknown service on non-HTTP port → is_http False
        unknown_9999 = ReconService(port=9999, service_name="")
        assert unknown_9999.is_http is False

    def test_recon_service_roundtrip(self) -> None:
        svc = ReconService(
            port=8080,
            protocol="tcp",
            service_name="http-proxy",
            version="2.4.51",
            scripts_output='{"http-title": "Test"}',
        )
        data = svc.model_dump()
        restored = ReconService.model_validate(data)
        assert restored.port == 8080
        assert restored.is_http is True
        assert restored.version == "2.4.51"

    def test_service_scan_result(self) -> None:
        ssr = ServiceScanResult(
            services=[
                ReconService(port=80, service_name="http"),
                ReconService(port=22, service_name="ssh"),
            ],
            raw_output="raw",
            tool_used="nmap",
        )
        data = ssr.model_dump()
        restored = ServiceScanResult.model_validate(data)
        assert len(restored.services) == 2
        assert restored.services[0].is_http is True
        assert restored.services[1].is_http is False

    def test_technology(self) -> None:
        tech = Technology(name="nginx", version="1.24", category="web_server")
        data = tech.model_dump()
        assert data == {"name": "nginx", "version": "1.24", "category": "web_server"}
        restored = Technology.model_validate(data)
        assert restored.name == "nginx"

    def test_tech_stack(self) -> None:
        ts = TechStack(
            technologies=[
                Technology(name="nginx", version="1.24", category="web_server"),
                Technology(name="PHP", version="8.1", category="language"),
            ]
        )
        data = ts.model_dump()
        restored = TechStack.model_validate(data)
        assert len(restored.technologies) == 2

    def test_web_recon_result(self) -> None:
        wr = WebReconResult(
            fingerprints=[{"url": "http://10.0.0.1", "tool": "whatweb"}],
            waf_detected=True,
            waf_name="Cloudflare",
            headers={"Server": "nginx/1.24", "X-Powered-By": "PHP/8.1"},
            technologies_found=["nginx", "PHP"],
        )
        data = wr.model_dump()
        restored = WebReconResult.model_validate(data)
        assert restored.waf_detected is True
        assert restored.waf_name == "Cloudflare"
        assert len(restored.technologies_found) == 2

    def test_recon_result_full(self) -> None:
        result = ReconResult(
            target="10.0.0.1",
            ports=PortScanResult(open_ports=[80, 443], tool_used="nmap"),
            services=ServiceScanResult(
                services=[ReconService(port=80, service_name="http")],
                tool_used="nmap",
            ),
            web_info=WebReconResult(waf_detected=False, headers={"Server": "nginx"}),
            tech_stack=TechStack(
                technologies=[Technology(name="nginx", version="1.24", category="web_server")]
            ),
            llm_summary="Summary text.",
        )
        data = result.model_dump()
        restored = ReconResult.model_validate(data)

        assert restored.target == "10.0.0.1"
        assert len(restored.ports.open_ports) == 2
        assert len(restored.services.services) == 1
        assert restored.web_info is not None
        assert restored.web_info.headers["Server"] == "nginx"
        assert restored.tech_stack.technologies[0].name == "nginx"
        assert restored.llm_summary == "Summary text."
        assert isinstance(restored.timestamp, datetime)

    def test_recon_result_json_roundtrip(self) -> None:
        result = ReconResult(
            target="10.0.0.1",
            ports=PortScanResult(open_ports=[80], tool_used="nmap"),
            services=ServiceScanResult(services=[], tool_used="none"),
            tech_stack=TechStack(),
            llm_summary="Test.",
        )
        json_str = result.model_dump_json()
        restored = ReconResult.model_validate_json(json_str)
        assert restored.target == "10.0.0.1"
        assert restored.web_info is None
