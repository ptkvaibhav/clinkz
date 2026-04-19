"""Binary identity verification for Clinkz tools.

``shutil.which("httpx")`` will happily return a path to the Python ``httpx``
library's command-line entry point — which is a completely different program
from ProjectDiscovery's ``httpx`` web probe. The same trap exists for any
tool whose name collides with an unrelated program on the host PATH.

To defend against this, the resolver runs each candidate binary with a
lightweight identity probe (typically ``--version``) and looks for a
signature substring that uniquely identifies the expected program.

The check is best-effort: tools not registered in
:data:`BINARY_SIGNATURES` skip verification (returning ``True`` so behavior
is unchanged for those tools).
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


# tool_name -> list of (command_args, expected_substring_in_output)
# First match wins. All checks use short timeouts.
BINARY_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "httpx": [
        ("--version", "projectdiscovery"),
        ("-version", "projectdiscovery"),
    ],
    "nmap": [("--version", "Nmap version")],
    "nuclei": [("--version", "projectdiscovery")],
    "katana": [("--version", "projectdiscovery")],
    "ffuf": [("--version", "ffuf")],
    "subfinder": [("--version", "projectdiscovery")],
    "wafw00f": [("--version", "wafw00f")],
    "whatweb": [("--version", "WhatWeb")],
    "sqlmap": [("--version", "sqlmap")],
    "nikto": [("-Version", "Nikto")],
}


_VERIFY_TIMEOUT = 3.0


async def _run_probe(argv: list[str]) -> str:
    """Run *argv* and return combined stdout+stderr (lower-cased).

    Returns an empty string on any failure (timeout, missing binary, etc.).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.debug("binary_identity: probe %s failed to spawn: %s", argv, exc)
        return ""

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_VERIFY_TIMEOUT)
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        logger.debug("binary_identity: probe %s timed out", argv)
        return ""

    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")
    return f"{out}\n{err}".lower()


async def verify_binary_identity(
    tool_name: str,
    exec_prefix: list[str] | None = None,
) -> bool:
    """Probe *tool_name* and check its output matches the expected signature.

    Args:
        tool_name: Tool name as registered with the resolver (e.g. ``"httpx"``).
        exec_prefix: Optional prefix to prepend to the command, e.g.
            ``["docker", "exec", "clinkz-tools"]`` for docker mode, or
            ``None`` / ``[]`` for a direct local invocation.

    Returns:
        True when the probe output contains the expected signature for any
        of the configured argument variants, or when the tool is not present
        in :data:`BINARY_SIGNATURES` (unchanged legacy behavior). False when
        every variant fails, times out, or produces output that lacks the
        signature.
    """
    signatures = BINARY_SIGNATURES.get(tool_name)
    if not signatures:
        # No signature registered — nothing to verify against.
        return True

    prefix = list(exec_prefix) if exec_prefix else []

    for args, expected in signatures:
        argv = [*prefix, tool_name, args]
        output = await _run_probe(argv)
        if expected.lower() in output:
            return True

    logger.debug(
        "binary_identity: %s did not match any signature in %s",
        tool_name,
        [s for s, _ in signatures],
    )
    return False
