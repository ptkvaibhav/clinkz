#!/usr/bin/env python
"""Minimal FastMCP server used exclusively by test_mcp_client.py.

Exposes two dummy tools:
  - ping(message)  → echoes the message back
  - add(a, b)      → returns the sum of two integers

Run with:  python test_mcp_server_script.py
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
