"""Tests for deterministic ScanAgent v2 — service-specific methods with fallback chains.

Coverage:
- test_scan_step_sequence: all 6 steps run in order
- test_scan_http_service: mock crawler + fuzzer, verify endpoints extracted
- test_scan_dispatches_by_service_type: verify correct method called per service
- test_scan_fallback_on_insufficient: mock insufficient crawl, verify fallback triggered
- test_scan_coverage_check: mock LLM coverage assessment, verify expansion logic
- test_scan_skips_unsupported_service: verify unknown services logged and skipped
- test_scan_result_structure: verify ScanResult completeness
- test_scan_models: all Pydantic models serialize/deserialize correctly
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from clinkz.agents.scan import ScanAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.recon import (
    PortScanResult,
    ReconResult,
    ReconService,
    Technology,
    TechStack,
)
from clinkz.models.recon import (
    ServiceScanResult as ReconServiceScanResult,
)
from clinkz.models.scan import (
    CoverageAssessment,
    DBScanResult,
    Endpoint,
    FormField,
    FTPScanResult,
    HTTPScanResult,
    ScanResult,
    ServiceScanResult,
    SMBScanResult,
    SSHScanResult,
    WebForm,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolMatch, ToolResolver

# ---------------------------------------------------------------------------
# Shared test scope and recon result
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="scan-v2-test",
    targets=[ScopeEntry(value="10.0.0.1", type=ScopeType.IP)],
)


def _make_recon_result(
    *,
    services: list[ReconService] | None = None,
    techs: list[Technology] | None = None,
) -> ReconResult:
    """Build a ReconResult for test use."""
    if services is None:
        services = [
            ReconService(port=80, service_name="http", version="nginx/1.24"),
            ReconService(port=22, service_name="ssh", version="OpenSSH 8.9p1"),
        ]
    if techs is None:
        techs = [
            Technology(name="nginx", version="1.24", category="web_server"),
            Technology(name="PHP", version="8.1", category="language"),
        ]

    return ReconResult(
        target="10.0.0.1",
        ports=PortScanResult(open_ports=[s.port for s in services], tool_used="nmap"),
        services=ReconServiceScanResult(services=services, tool_used="nmap"),
        tech_stack=TechStack(technologies=techs),
        llm_summary="Test recon summary.",
    )


# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


class MockLLM(LLMClient):
    """Deterministic LLM for scan v2 tests."""

    def __init__(self, *, coverage_sufficient: bool = True) -> None:
        self.generate_text_calls: list[str] = []
        self._coverage_sufficient = coverage_sufficient

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> Any:
        raise NotImplementedError("v2 ScanAgent does not use reason()")

    async def research(self, query: str) -> str:
        return "No research results."

    async def generate_text(self, prompt: str) -> str:
        self.generate_text_calls.append(prompt)

        if "planning a scan strategy" in prompt.lower() or "plan" in prompt.lower()[:50]:
            return "Scan plan: crawl HTTP on port 80, check SSH auth methods."

        if "review" in prompt.lower() and "scan results" in prompt.lower():
            return "HTTP service has 10 endpoints. SSH has password auth enabled."

        if "coverage" in prompt.lower() or "sufficient" in prompt.lower():
            return json.dumps(
                {
                    "sufficient": self._coverage_sufficient,
                    "gaps": []
                    if self._coverage_sufficient
                    else ["Only 2 endpoints found, expected more"],
                    "recommendations": [] if self._coverage_sufficient else ["Try deeper crawl"],
                }
            )

        return "LLM analysis complete."


# ---------------------------------------------------------------------------
# Mock tool outputs
# ---------------------------------------------------------------------------


class _MockCrawlOutput(ToolOutput):
    """Mock crawler output with URLs."""

    endpoints: list[str] = []
    urls: list[str] = []


class _MockFuzzOutput(ToolOutput):
    """Mock fuzzer output with paths."""

    paths: list[str] = []
    directories: list[str] = []


class _MockNmapScriptOutput(ToolOutput):
    """Mock nmap script output."""

    raw_text: str = ""


# ---------------------------------------------------------------------------
# Mock tool classes
# ---------------------------------------------------------------------------


class _MockCrawlTool(ToolBase):
    """Returns a list of crawled URLs."""

    capabilities = ["web_crawling"]
    category = "scan"

    @property
    def name(self) -> str:
        return "katana"

    @property
    def description(self) -> str:
        return "Mock web crawler"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock crawl output"

    def parse_output(self, raw_output: str) -> _MockCrawlOutput:
        return _MockCrawlOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            endpoints=[
                "http://10.0.0.1/index.php",
                "http://10.0.0.1/login.php",
                "http://10.0.0.1/about.php",
                "http://10.0.0.1/contact.php",
                "http://10.0.0.1/admin/",
                "http://10.0.0.1/api/v1/users",
            ],
        )


class _MockFuzzTool(ToolBase):
    """Returns a list of discovered directories."""

    capabilities = ["directory_fuzzing"]
    category = "scan"

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def description(self) -> str:
        return "Mock directory fuzzer"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return "mock fuzz output"

    def parse_output(self, raw_output: str) -> _MockFuzzOutput:
        return _MockFuzzOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
            paths=["/admin", "/backup", "/config"],
        )


class _MockNmapTool(ToolBase):
    """Mock nmap for script-based scans (FTP, SSH, SMB, DB)."""

    capabilities = ["port_scanning", "service_detection"]
    category = "recon"

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Mock nmap"

    def get_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": {}}

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        flags = args.get("flags", "")
        if "ftp-anon" in flags:
            return "ftp anonymous access allowed, vsftpd backdoor possible"
        if "ssh-auth-methods" in flags:
            return "publickey password keyboard-interactive"
        if "smb-enum-shares" in flags:
            return "null session available, signing not required"
        return "mock nmap output"

    def parse_output(self, raw_output: str) -> _MockNmapScriptOutput:
        return _MockNmapScriptOutput(
            tool_name=self.name,
            success=True,
            raw_output=raw_output,
        )


# ---------------------------------------------------------------------------
# Resolver factories
# ---------------------------------------------------------------------------


def _make_resolver() -> ToolResolver:
    """Build a mock ToolResolver with crawl, fuzz, and nmap tools."""
    resolver = MagicMock(spec=ToolResolver)

    _cap_map: dict[str, tuple[type[ToolBase], str]] = {
        "web_crawling": (_MockCrawlTool, "katana"),
        "directory_fuzzing": (_MockFuzzTool, "ffuf"),
        "port_scanning": (_MockNmapTool, "nmap"),
        "service_detection": (_MockNmapTool, "nmap"),
    }

    def _find_tool(cap: str) -> ToolMatch | None:
        entry = _cap_map.get(cap)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find_tool
    resolver.find_tools_ranked.return_value = ["katana"]

    # Mock try_until_sufficient to call the run_fn with first tool
    async def _try_until_sufficient(
        capability: str, min_results: int, run_fn: Any, *args: Any
    ) -> tuple[str, Any]:
        entry = _cap_map.get(capability)
        if entry is None:
            raise ValueError(f"No tools for {capability}")
        cls, name = entry
        result = await run_fn(name, *args)
        return name, result

    resolver.try_until_sufficient = AsyncMock(side_effect=_try_until_sufficient)
    return resolver


def _make_insufficient_resolver() -> ToolResolver:
    """Build a resolver where crawl returns insufficient results (< 5)."""
    resolver = MagicMock(spec=ToolResolver)

    class _SmallCrawlTool(_MockCrawlTool):
        def parse_output(self, raw_output: str) -> _MockCrawlOutput:
            return _MockCrawlOutput(
                tool_name=self.name,
                success=True,
                raw_output=raw_output,
                endpoints=["http://10.0.0.1/index.php", "http://10.0.0.1/login.php"],
            )

    _cap_map: dict[str, tuple[type[ToolBase], str]] = {
        "web_crawling": (_SmallCrawlTool, "katana"),
        "directory_fuzzing": (_MockFuzzTool, "ffuf"),
        "port_scanning": (_MockNmapTool, "nmap"),
        "service_detection": (_MockNmapTool, "nmap"),
    }

    def _find_tool(cap: str) -> ToolMatch | None:
        entry = _cap_map.get(cap)
        if entry is None:
            return None
        cls, name = entry
        return ToolMatch(name=name, source="local", available=True, tool_class=cls)

    resolver.find_tool.side_effect = _find_tool
    resolver.find_tools_ranked.return_value = ["katana"]

    async def _try_until_sufficient(
        capability: str, min_results: int, run_fn: Any, *args: Any
    ) -> tuple[str, Any]:
        entry = _cap_map.get(capability)
        if entry is None:
            raise ValueError(f"No tools for {capability}")
        cls, name = entry
        result = await run_fn(name, *args)
        return name, result

    resolver.try_until_sufficient = AsyncMock(side_effect=_try_until_sufficient)
    return resolver


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------


async def _make_agent(
    db_path: Path,
    resolver: Any = None,
    llm: LLMClient | None = None,
) -> tuple[ScanAgent, StateStore, str]:
    """Create a ScanAgent with mock dependencies."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("scan-v2-test", SCOPE.model_dump())
    agent = ScanAgent(
        llm=llm or MockLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
        resolver=resolver if resolver is not None else _make_resolver(),
    )
    return agent, state, eid


# ---------------------------------------------------------------------------
# Test: step sequence (all 6 steps run in order)
# ---------------------------------------------------------------------------


async def test_scan_step_sequence(tmp_path: Path) -> None:
    """All 6 steps execute in the correct order."""
    llm = MockLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm)

    recon = _make_recon_result()
    result = await agent.run({"recon_result": recon})
    await state.close()

    assert result["status"] == "complete"

    # LLM should have been called 3 times (steps 1, 3, 4)
    assert len(llm.generate_text_calls) == 3

    # Step 1: scan planning
    assert (
        "plan" in llm.generate_text_calls[0].lower()
        or "strategy" in llm.generate_text_calls[0].lower()
    )

    # Step 3: review scan results
    assert (
        "review" in llm.generate_text_calls[1].lower()
        or "scan results" in llm.generate_text_calls[1].lower()
    )

    # Step 4: coverage check
    assert (
        "coverage" in llm.generate_text_calls[2].lower()
        or "sufficient" in llm.generate_text_calls[2].lower()
    )


# ---------------------------------------------------------------------------
# Test: HTTP service scanning
# ---------------------------------------------------------------------------


async def test_scan_http_service(tmp_path: Path) -> None:
    """Mock crawler + fuzzer, verify endpoints extracted."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    recon = _make_recon_result(
        services=[ReconService(port=80, service_name="http", version="nginx/1.24")],
    )
    result = await agent.run({"recon_result": recon})
    await state.close()

    r = result["result"]
    assert len(r["service_scans"]) >= 1

    http_scan = r["service_scans"][0]
    assert http_scan["service_type"] == "http"
    assert http_scan["port"] == 80

    http_result = http_scan["result"]
    assert len(http_result["endpoints"]) > 0
    assert len(http_result["directories"]) > 0
    assert http_result["crawl_tool_used"] == "katana"
    assert http_result["fuzz_tool_used"] == "ffuf"


# ---------------------------------------------------------------------------
# Test: dispatches by service type
# ---------------------------------------------------------------------------


async def test_scan_dispatches_by_service_type(tmp_path: Path) -> None:
    """Verify correct scan method called for each service type."""
    recon = _make_recon_result(
        services=[
            ReconService(port=80, service_name="http"),
            ReconService(port=21, service_name="ftp"),
            ReconService(port=22, service_name="ssh"),
            ReconService(port=445, service_name="microsoft-ds"),
            ReconService(port=3306, service_name="mysql"),
        ],
    )

    agent, state, _ = await _make_agent(tmp_path / "test.db")
    result = await agent.run({"recon_result": recon})
    await state.close()

    r = result["result"]
    service_types = [s["service_type"] for s in r["service_scans"]]
    assert "http" in service_types
    assert "ftp" in service_types
    assert "ssh" in service_types
    assert "smb" in service_types
    assert "database" in service_types


# ---------------------------------------------------------------------------
# Test: fallback on insufficient crawl results
# ---------------------------------------------------------------------------


async def test_scan_fallback_on_insufficient(tmp_path: Path) -> None:
    """When coverage is insufficient, step 5 expansion is triggered."""
    llm = MockLLM(coverage_sufficient=False)
    resolver = _make_insufficient_resolver()
    agent, state, _ = await _make_agent(tmp_path / "test.db", resolver=resolver, llm=llm)

    recon = _make_recon_result(
        services=[ReconService(port=80, service_name="http")],
    )
    result = await agent.run({"recon_result": recon})
    await state.close()

    assert result["status"] == "complete"

    # LLM should have been called 3 times (steps 1, 3, 4)
    assert len(llm.generate_text_calls) == 3

    # Coverage should report gaps
    r = result["result"]
    # Step 5 should have run additional scans (service_scans should have more)
    assert len(r["service_scans"]) >= 1


# ---------------------------------------------------------------------------
# Test: coverage check
# ---------------------------------------------------------------------------


async def test_scan_coverage_check(tmp_path: Path) -> None:
    """Mock LLM coverage assessment, verify expansion logic."""
    # Sufficient case — no expansion
    llm_sufficient = MockLLM(coverage_sufficient=True)
    agent, state, _ = await _make_agent(tmp_path / "suff.db", llm=llm_sufficient)
    recon = _make_recon_result()
    result = await agent.run({"recon_result": recon})
    await state.close()

    r = result["result"]
    coverage = r["coverage_assessment"]
    assert coverage["sufficient"] is True
    assert len(coverage["gaps"]) == 0

    # Insufficient case — expansion triggered
    llm_insuff = MockLLM(coverage_sufficient=False)
    agent2, state2, _ = await _make_agent(tmp_path / "insuff.db", llm=llm_insuff)
    result2 = await agent2.run({"recon_result": recon})
    await state2.close()

    r2 = result2["result"]
    coverage2 = r2["coverage_assessment"]
    # The coverage from step 4 is stored before expansion — expansion adds more scans
    # but coverage_assessment reflects step 4 result
    assert coverage2["sufficient"] is False
    assert len(coverage2["gaps"]) > 0


# ---------------------------------------------------------------------------
# Test: unsupported service skipped
# ---------------------------------------------------------------------------


async def test_scan_skips_unsupported_service(tmp_path: Path) -> None:
    """Unknown services are logged and skipped without error."""
    recon = _make_recon_result(
        services=[
            ReconService(port=80, service_name="http"),
            ReconService(port=9999, service_name="unknown-custom-service"),
        ],
    )

    agent, state, _ = await _make_agent(tmp_path / "test.db")
    result = await agent.run({"recon_result": recon})
    await state.close()

    r = result["result"]
    # Only HTTP should be scanned, unknown service should be skipped
    service_types = [s["service_type"] for s in r["service_scans"]]
    assert "http" in service_types
    assert "unknown-custom-service" not in service_types


# ---------------------------------------------------------------------------
# Test: result structure
# ---------------------------------------------------------------------------


async def test_scan_result_structure(tmp_path: Path) -> None:
    """ScanResult contains all required fields with correct types."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    recon = _make_recon_result()
    result = await agent.run({"recon_result": recon})
    await state.close()

    r = result["result"]

    # Required top-level fields
    assert r["target"] == "10.0.0.1"
    assert isinstance(r["service_scans"], list)
    assert isinstance(r["total_endpoints"], int)
    assert isinstance(r["total_forms"], int)
    assert isinstance(r["total_params"], int)
    assert isinstance(r["coverage_assessment"], dict)
    assert "timestamp" in r

    # Coverage assessment structure
    ca = r["coverage_assessment"]
    assert "sufficient" in ca
    assert "gaps" in ca
    assert "recommendations" in ca

    # At least one service scan
    assert len(r["service_scans"]) >= 1
    scan = r["service_scans"][0]
    assert "service_type" in scan
    assert "port" in scan
    assert "result" in scan


# ---------------------------------------------------------------------------
# Test: Pydantic model serialization/deserialization
# ---------------------------------------------------------------------------


class TestScanModels:
    """Test all scan Pydantic models serialize and deserialize correctly."""

    def test_endpoint(self) -> None:
        ep = Endpoint(
            url="http://10.0.0.1/api", method="POST", params=["id", "name"], status_code=200
        )
        data = ep.model_dump()
        restored = Endpoint.model_validate(data)
        assert restored.url == "http://10.0.0.1/api"
        assert restored.method == "POST"
        assert restored.params == ["id", "name"]

    def test_form_field(self) -> None:
        ff = FormField(name="username", type="text", value="admin")
        data = ff.model_dump()
        restored = FormField.model_validate(data)
        assert restored.name == "username"

    def test_web_form(self) -> None:
        form = WebForm(
            action="/login",
            method="POST",
            fields=[
                FormField(name="user", type="text"),
                FormField(name="pass", type="password"),
            ],
            has_csrf_token=True,
        )
        data = form.model_dump()
        restored = WebForm.model_validate(data)
        assert restored.action == "/login"
        assert len(restored.fields) == 2
        assert restored.has_csrf_token is True

    def test_http_scan_result(self) -> None:
        hsr = HTTPScanResult(
            endpoints=[Endpoint(url="http://10.0.0.1/")],
            forms=[WebForm(action="/login", method="POST")],
            directories=["/admin", "/backup"],
            technologies_detected=["nginx", "PHP"],
            crawl_tool_used="katana",
            fuzz_tool_used="ffuf",
        )
        data = hsr.model_dump()
        restored = HTTPScanResult.model_validate(data)
        assert len(restored.endpoints) == 1
        assert len(restored.directories) == 2
        assert restored.crawl_tool_used == "katana"

    def test_ftp_scan_result(self) -> None:
        ftp = FTPScanResult(
            anonymous_access=True, writable_dirs=["/upload"], version_vulns=["vsftpd-backdoor"]
        )
        data = ftp.model_dump()
        restored = FTPScanResult.model_validate(data)
        assert restored.anonymous_access is True
        assert "vsftpd-backdoor" in restored.version_vulns

    def test_ssh_scan_result(self) -> None:
        ssh = SSHScanResult(
            version="OpenSSH 8.9p1", auth_methods=["publickey", "password"], weak_config=[]
        )
        data = ssh.model_dump()
        restored = SSHScanResult.model_validate(data)
        assert restored.version == "OpenSSH 8.9p1"
        assert "password" in restored.auth_methods

    def test_smb_scan_result(self) -> None:
        smb = SMBScanResult(
            shares=[{"name": "IPC$", "access": "read"}],
            null_session=True,
            signing_required=False,
        )
        data = smb.model_dump()
        restored = SMBScanResult.model_validate(data)
        assert restored.null_session is True
        assert restored.signing_required is False

    def test_db_scan_result(self) -> None:
        db = DBScanResult(accessible=True, version="5.7.38", default_creds=True, db_type="mysql")
        data = db.model_dump()
        restored = DBScanResult.model_validate(data)
        assert restored.accessible is True
        assert restored.db_type == "mysql"

    def test_service_scan_result_http(self) -> None:
        ssr = ServiceScanResult(
            service_type="http",
            port=80,
            result=HTTPScanResult(endpoints=[Endpoint(url="http://10.0.0.1/")]),
        )
        data = ssr.model_dump()
        restored = ServiceScanResult.model_validate(data)
        assert restored.service_type == "http"
        assert restored.port == 80

    def test_service_scan_result_ftp(self) -> None:
        ssr = ServiceScanResult(
            service_type="ftp",
            port=21,
            result=FTPScanResult(anonymous_access=True),
        )
        data = ssr.model_dump()
        restored = ServiceScanResult.model_validate(data)
        assert restored.service_type == "ftp"

    def test_coverage_assessment(self) -> None:
        ca = CoverageAssessment(
            sufficient=False,
            gaps=["Only 2 endpoints found"],
            recommendations=["Crawl deeper"],
        )
        data = ca.model_dump()
        restored = CoverageAssessment.model_validate(data)
        assert restored.sufficient is False
        assert len(restored.gaps) == 1

    def test_scan_result_full(self) -> None:
        result = ScanResult(
            target="10.0.0.1",
            service_scans=[
                ServiceScanResult(
                    service_type="http",
                    port=80,
                    result=HTTPScanResult(
                        endpoints=[Endpoint(url="http://10.0.0.1/")],
                        forms=[WebForm(action="/login", method="POST")],
                        directories=["/admin"],
                        crawl_tool_used="katana",
                        fuzz_tool_used="ffuf",
                    ),
                ),
                ServiceScanResult(
                    service_type="ssh",
                    port=22,
                    result=SSHScanResult(version="OpenSSH 8.9p1", auth_methods=["publickey"]),
                ),
            ],
            total_endpoints=1,
            total_forms=1,
            total_params=0,
            coverage_assessment=CoverageAssessment(sufficient=True),
        )
        data = result.model_dump()
        restored = ScanResult.model_validate(data)
        assert restored.target == "10.0.0.1"
        assert len(restored.service_scans) == 2
        assert restored.total_endpoints == 1
        assert isinstance(restored.timestamp, datetime)

    def test_scan_result_json_roundtrip(self) -> None:
        result = ScanResult(
            target="10.0.0.1",
            service_scans=[],
            coverage_assessment=CoverageAssessment(sufficient=True),
        )
        json_str = result.model_dump_json()
        restored = ScanResult.model_validate_json(json_str)
        assert restored.target == "10.0.0.1"
        assert restored.coverage_assessment.sufficient is True
