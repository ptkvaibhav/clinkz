#!/usr/bin/env python
"""Minimal FastMCP server used exclusively by ``test_mcp_client.py``.

**Not a test module.** It is launched as a subprocess over stdio by the MCP
client tests. It used to be named ``test_mcp_server_script.py``, which made
pytest *collect* it — and collection imports ``mcp.server.fastmcp`` in the
runner's own interpreter, so an environment without that extra installed failed
the entire run at collection time (the CI ``lint-and-test`` break) while a
developer machine that happened to have it passed. The name, not the import,
was the bug.

Exposes two dummy tools:
  - ping(message)  → echoes the message back
  - add(a, b)      → returns the sum of two integers

Run with:  python mcp_server_script.py
The server communicates over stdio (default FastMCP transport).
"""

from mcp.server.fastmcp import FastMCP

mcp_server = FastMCP("clinkz-test-server")


@mcp_server.tool()
def ping(message: str = "hello") -> str:
    """Ping tool — echoes message back with a 'pong' prefix."""
    return f"pong: {message}"


@mcp_server.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return their sum."""
    return a + b


if __name__ == "__main__":
    mcp_server.run()
