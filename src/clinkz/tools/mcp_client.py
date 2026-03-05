"""MCP client — connects to external MCP tool servers.

Agents discover and invoke tools on remote MCP servers through this client.
Supports both stdio (subprocess command) and HTTP/SSE (URL) transports.

Usage::

    client = MCPClient()
    await client.connect(["python", "server.py"])       # stdio
    await client.connect("http://localhost:8080/mcp")   # SSE

    tools = await client.list_tools()
    result = await client.call_tool("ping", {"message": "hello"})
    await client.disconnect()
"""

from __future__ import annotations

import logging
import shlex
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import BaseModel

from clinkz.tools.base import ToolOutput

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class MCPToolInfo(BaseModel):
    """Metadata about a single tool exposed by an MCP server.

    Attributes:
        name: Tool identifier used when calling it on the server.
        description: Human-readable description of what the tool does.
        input_schema: JSON Schema dict describing the tool's parameters.
    """

    name: str
    description: str
    input_schema: dict[str, Any]


class MCPCallResult(ToolOutput):
    """Result from calling a tool on an MCP server.

    Inherits from ToolOutput for consistency with local tool results.

    Attributes:
        content: Structured content items returned by the server.
                 Each item is a dict with at least a ``type`` key.
        is_error: True if the MCP server flagged the call as an error.
    """

    content: list[dict[str, Any]] = []
    is_error: bool = False


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MCPClient:
    """Client for connecting to and calling tools on a single MCP server.

    Manages a persistent connection.  Supports stdio transport (subprocess
    command string or list) and HTTP/SSE transport (URL string).

    The connection stays open until :meth:`disconnect` is called, so multiple
    :meth:`call_tool` invocations reuse the same session — no reconnection
    overhead per call.

    Example::

        client = MCPClient()
        await client.connect("burpsuite-mcp")                 # stdio
        await client.connect(["python", "my_server.py"])      # stdio list
        await client.connect("http://localhost:8080/mcp")     # SSE URL

        tools  = await client.list_tools()
        result = await client.call_tool("scan", {"target": "example.com"})
        await client.disconnect()
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._server_spec: str | list[str] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def connect(self, server_spec: str | list[str]) -> None:
        """Connect to an MCP server and initialise the session.

        Args:
            server_spec: For HTTP/SSE transport supply a URL string
                (``http://…`` or ``https://…``).  For stdio transport supply
                the command as a single shell string (``"python server.py"``)
                or as a pre-split list (``["python", "server.py"]``).

        Raises:
            ConnectionError: If connection or MCP initialisation fails.
        """
        self._server_spec = server_spec
        self._exit_stack = AsyncExitStack()

        try:
            if _is_url(server_spec):
                transport = await self._connect_sse(server_spec)
            else:
                transport = await self._connect_stdio(server_spec)

            read_stream, write_stream = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self._session.initialize()
            logger.info("MCPClient: connected to %s", server_spec)

        except Exception as exc:
            await self._cleanup()
            raise ConnectionError(
                f"Failed to connect to MCP server {server_spec!r}: {exc}"
            ) from exc

    async def list_tools(self) -> list[MCPToolInfo]:
        """Discover tools exposed by the connected MCP server.

        Returns:
            List of :class:`MCPToolInfo` objects, one per tool.

        Raises:
            RuntimeError: If :meth:`connect` has not been called yet.
        """
        self._assert_connected()
        result = await self._session.list_tools()  # type: ignore[union-attr]
        tools: list[MCPToolInfo] = []
        for tool in result.tools:
            tools.append(
                MCPToolInfo(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=dict(tool.inputSchema) if tool.inputSchema else {},
                )
            )
        logger.debug("MCPClient: server advertises %d tool(s)", len(tools))
        return tools

    async def call_tool(
        self, name: str, params: dict[str, Any] | None = None
    ) -> MCPCallResult:
        """Invoke a named tool on the MCP server.

        Args:
            name: Tool name as returned by :meth:`list_tools`.
            params: Arguments to pass to the tool.  Defaults to ``{}``.

        Returns:
            :class:`MCPCallResult` with structured content and success flag.

        Raises:
            RuntimeError: If :meth:`connect` has not been called yet.
        """
        self._assert_connected()
        params = params or {}
        logger.info("MCPClient: calling tool '%s' params=%s", name, params)
        result = await self._session.call_tool(name, params)  # type: ignore[union-attr]

        content_dicts = _serialise_content(result.content)
        is_error = bool(getattr(result, "isError", False))
        raw_text = _extract_text(content_dicts)

        return MCPCallResult(
            tool_name=name,
            success=not is_error,
            raw_output=raw_text,
            error=raw_text if is_error else "",
            content=content_dicts,
            is_error=is_error,
        )

    async def disconnect(self) -> None:
        """Cleanly shut down the MCP session and underlying transport."""
        await self._cleanup()
        logger.info("MCPClient: disconnected from %s", self._server_spec)

    @property
    def is_connected(self) -> bool:
        """True when a live session is open."""
        return self._session is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_connected(self) -> None:
        if self._session is None:
            raise RuntimeError(
                "MCPClient is not connected. Call connect() first."
            )

    async def _cleanup(self) -> None:
        if self._exit_stack is not None:
            await self._exit_stack.aclose()
            self._exit_stack = None
        self._session = None

    async def _connect_stdio(
        self, spec: str | list[str]
    ) -> tuple[Any, Any]:
        params = _build_stdio_params(spec)
        return await self._exit_stack.enter_async_context(  # type: ignore[union-attr]
            stdio_client(params)
        )

    async def _connect_sse(self, url: str | list[str]) -> tuple[Any, Any]:
        from mcp.client.sse import sse_client

        target = url if isinstance(url, str) else url[0]
        return await self._exit_stack.enter_async_context(  # type: ignore[union-attr]
            sse_client(target)
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _is_url(spec: str | list[str]) -> bool:
    """Return True when spec looks like an HTTP/SSE URL."""
    s = spec if isinstance(spec, str) else spec[0]
    return s.startswith("http://") or s.startswith("https://")


def _build_stdio_params(spec: str | list[str]) -> StdioServerParameters:
    """Convert a command string or list to StdioServerParameters."""
    if isinstance(spec, list):
        command, args = spec[0], spec[1:]
    else:
        parts = shlex.split(spec)
        command, args = parts[0], parts[1:]
    return StdioServerParameters(command=command, args=args)


def _serialise_content(content: list[Any]) -> list[dict[str, Any]]:
    """Convert MCP content items to plain dicts."""
    out: list[dict[str, Any]] = []
    for item in content:
        if hasattr(item, "model_dump"):
            out.append(item.model_dump())
        elif hasattr(item, "__dict__"):
            out.append(vars(item))
        else:
            out.append({"type": "unknown", "value": str(item)})
    return out


def _extract_text(content: list[dict[str, Any]]) -> str:
    """Join all ``text`` content items into a single string."""
    return "\n".join(
        str(item.get("text", ""))
        for item in content
        if item.get("type") == "text"
    )
