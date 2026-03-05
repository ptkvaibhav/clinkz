"""Tests for MCPClient and ToolResolver MCP integration.

Test coverage:
- MCPClient.connect() via stdio transport
- MCPClient.list_tools() returns expected tool metadata
- MCPClient.call_tool() executes a tool and returns structured result
- MCPClient.disconnect() cleans up without error
- Graceful ConnectionError when server command is invalid
- ToolResolver.initialize() discovers MCP tools
- ToolResolver.find_tool() prefers MCP over local tools after initialize()
- ToolResolver.check_mcp_servers() returns empty list before initialize()
- ToolResolver.get_mcp_client_for_tool() returns live client
- ToolResolver.shutdown() disconnects all clients
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.tools.mcp_client import MCPCallResult, MCPClient, MCPToolInfo
from clinkz.tools.resolver import ToolResolver, _infer_capabilities

# Path to the minimal FastMCP server used for real transport tests
_SERVER_SCRIPT = Path(__file__).parent.parent / "fixtures" / "test_mcp_server_script.py"


# ---------------------------------------------------------------------------
# MCPClient — real stdio transport tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_and_disconnect() -> None:
    """MCPClient can connect to and disconnect from the test server."""
    client = MCPClient()
    await client.connect([sys.executable, str(_SERVER_SCRIPT)])
    assert client.is_connected
    await client.disconnect()
    assert not client.is_connected


@pytest.mark.asyncio
async def test_list_tools_returns_two_tools() -> None:
    """list_tools() returns exactly the two tools exposed by the test server."""
    client = MCPClient()
    await client.connect([sys.executable, str(_SERVER_SCRIPT)])
    try:
        tools = await client.list_tools()
        assert len(tools) == 2
        names = {t.name for t in tools}
        assert names == {"ping", "add"}
        for t in tools:
            assert isinstance(t, MCPToolInfo)
            assert t.description  # non-empty description
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_call_tool_ping() -> None:
    """call_tool('ping') executes successfully and returns text content."""
    client = MCPClient()
    await client.connect([sys.executable, str(_SERVER_SCRIPT)])
    try:
        result = await client.call_tool("ping", {"message": "hello"})
        assert isinstance(result, MCPCallResult)
        assert result.success is True
        assert result.is_error is False
        assert "pong" in result.raw_output.lower()
        assert result.tool_name == "ping"
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_call_tool_add() -> None:
    """call_tool('add') returns the correct sum as text content."""
    client = MCPClient()
    await client.connect([sys.executable, str(_SERVER_SCRIPT)])
    try:
        result = await client.call_tool("add", {"a": 3, "b": 7})
        assert result.success is True
        # The numeric result should appear somewhere in the raw output
        assert "10" in result.raw_output
    finally:
        await client.disconnect()


@pytest.mark.asyncio
async def test_disconnect_is_idempotent() -> None:
    """Calling disconnect() twice does not raise."""
    client = MCPClient()
    await client.connect([sys.executable, str(_SERVER_SCRIPT)])
    await client.disconnect()
    await client.disconnect()  # should not raise


@pytest.mark.asyncio
async def test_connect_raises_on_invalid_command() -> None:
    """connect() raises ConnectionError when the command doesn't exist."""
    client = MCPClient()
    with pytest.raises(ConnectionError):
        await client.connect(["this-binary-does-not-exist-anywhere-xyz"])


@pytest.mark.asyncio
async def test_assert_connected_raises_before_connect() -> None:
    """Calling list_tools() or call_tool() before connect() raises RuntimeError."""
    client = MCPClient()
    with pytest.raises(RuntimeError, match="not connected"):
        await client.list_tools()
    with pytest.raises(RuntimeError, match="not connected"):
        await client.call_tool("ping")


# ---------------------------------------------------------------------------
# ToolResolver — MCP integration tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_resolver() -> ToolResolver:
    """A ToolResolver with no MCP endpoints pre-configured."""
    return ToolResolver()


@pytest.mark.asyncio
async def test_check_mcp_servers_empty_before_initialize(
    fresh_resolver: ToolResolver,
) -> None:
    """check_mcp_servers() returns [] before initialize() is called."""
    assert fresh_resolver.check_mcp_servers() == []


@pytest.mark.asyncio
async def test_initialize_discovers_mcp_tools(fresh_resolver: ToolResolver) -> None:
    """initialize() connects to the test server and caches both tools."""
    await fresh_resolver.initialize(
        extra_servers=[[sys.executable, str(_SERVER_SCRIPT)]]
    )
    try:
        entries = fresh_resolver.check_mcp_servers()
        names = {e["name"] for e in entries}
        assert "ping" in names
        assert "add" in names
    finally:
        await fresh_resolver.shutdown()


@pytest.mark.asyncio
async def test_find_tool_prefers_mcp_after_initialize(
    fresh_resolver: ToolResolver,
) -> None:
    """find_tool() returns an MCP match for 'ping' after initialize()."""
    await fresh_resolver.initialize(
        extra_servers=[[sys.executable, str(_SERVER_SCRIPT)]]
    )
    try:
        match = fresh_resolver.find_tool("ping")
        assert match is not None
        assert match.source == "mcp"
        assert match.name == "ping"
        assert match.available is True
        assert match.mcp_client is not None
    finally:
        await fresh_resolver.shutdown()


@pytest.mark.asyncio
async def test_find_tool_falls_back_to_local_for_unknown_mcp_cap(
    fresh_resolver: ToolResolver,
) -> None:
    """find_tool('port_scanning') falls back to local when no MCP tool covers it."""
    await fresh_resolver.initialize(
        extra_servers=[[sys.executable, str(_SERVER_SCRIPT)]]
    )
    try:
        with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
            match = fresh_resolver.find_tool("port_scanning")
        assert match is not None
        assert match.source == "local"
        assert match.name == "nmap"
    finally:
        await fresh_resolver.shutdown()


@pytest.mark.asyncio
async def test_get_mcp_client_for_tool(fresh_resolver: ToolResolver) -> None:
    """get_mcp_client_for_tool() returns the live MCPClient for a tool."""
    await fresh_resolver.initialize(
        extra_servers=[[sys.executable, str(_SERVER_SCRIPT)]]
    )
    try:
        client = fresh_resolver.get_mcp_client_for_tool("ping")
        assert client is not None
        assert client.is_connected
    finally:
        await fresh_resolver.shutdown()


@pytest.mark.asyncio
async def test_initialize_graceful_fallback_on_bad_server(
    fresh_resolver: ToolResolver,
) -> None:
    """initialize() logs a warning and continues when a server is unavailable."""
    # bad-server-xyz does not exist — should not raise, just skip
    await fresh_resolver.initialize(extra_servers=["bad-server-xyz-does-not-exist"])
    # No tools discovered from the bad server
    assert fresh_resolver.check_mcp_servers() == []


@pytest.mark.asyncio
async def test_shutdown_disconnects_all_clients(fresh_resolver: ToolResolver) -> None:
    """shutdown() disconnects all cached MCPClient instances."""
    await fresh_resolver.initialize(
        extra_servers=[[sys.executable, str(_SERVER_SCRIPT)]]
    )
    assert len(fresh_resolver._mcp_clients) == 1
    await fresh_resolver.shutdown()
    assert len(fresh_resolver._mcp_clients) == 0
    assert fresh_resolver.check_mcp_servers() == []


# ---------------------------------------------------------------------------
# Capability inference unit tests (no network needed)
# ---------------------------------------------------------------------------


def test_infer_capabilities_by_description() -> None:
    """_infer_capabilities maps keyword-rich description to known capabilities."""
    caps = _infer_capabilities("my_tool", "Performs port scanning and service detection")
    assert "port_scanning" in caps
    assert "service_detection" in caps


def test_infer_capabilities_always_includes_tool_name() -> None:
    """Tool name is always included as a fallback capability."""
    caps = _infer_capabilities("my_custom_tool", "Does something obscure")
    assert "my_custom_tool" in caps


def test_infer_capabilities_normalises_hyphens() -> None:
    """Tool names with hyphens are normalised to underscores."""
    caps = _infer_capabilities("burp-suite", "Web proxy for testing")
    assert "burp_suite" in caps


# ---------------------------------------------------------------------------
# Resolver MCP preference (mocked — no server needed)
# ---------------------------------------------------------------------------


def test_find_tool_prefers_mcp_over_local_mocked(fresh_resolver: ToolResolver) -> None:
    """Manually populate _mcp_tools_cache and verify MCP preference in find_tool()."""
    fake_client = AsyncMock()
    fake_client.is_connected = True

    fresh_resolver._mcp_tools_cache.append(
        {
            "name": "mcp-scanner",
            "endpoint": "http://localhost:5000",
            "capabilities": ["port_scanning"],
            "server_key": "http://localhost:5000",
        }
    )
    fresh_resolver._mcp_clients["http://localhost:5000"] = fake_client  # type: ignore[assignment]

    with patch("clinkz.tools.resolver.shutil.which", return_value="/usr/bin/nmap"):
        match = fresh_resolver.find_tool("port_scanning")

    assert match is not None
    assert match.source == "mcp"
    assert match.name == "mcp-scanner"
    assert match.mcp_client is fake_client
