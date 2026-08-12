"""Tool Abstraction Layer (TAL) — base class for all tool wrappers.

Every tool wrapper must:
1. Inherit from ToolBase
2. Implement the four abstract methods
3. Call _check_scope() before running against any target
4. Return a ToolOutput subclass (Pydantic model), never a raw string

This ensures:
- Scope enforcement on every tool invocation
- Structured output that agents can reason over
- Consistent error handling and logging
- Easy unit testing with fixture outputs
"""

from __future__ import annotations

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from clinkz.models.recon import DetectedComponent
from clinkz.models.scope import EngagementScope

logger = logging.getLogger(__name__)


class ToolOutput(BaseModel):
    """Base class for all tool outputs.

    All concrete tool output models must inherit from this class.

    Attributes:
        tool_name: Name of the tool that produced this output.
        success: True if the tool ran without fatal errors.
        raw_output: Raw stdout from the tool (stored for debugging).
        error: Error message if success is False.
    """

    tool_name: str
    success: bool
    raw_output: str = ""
    error: str = ""

    # ------------------------------------------------------------------
    # Discovery contract
    # ------------------------------------------------------------------
    #
    # A consumer that guesses a producer's field names is a seam that fails
    # silently. ``_run_fuzz_tool`` read ``parsed.paths`` / ``parsed.directories``
    # while :class:`~clinkz.tools.ffuf.FfufOutput` has only ``results``, so both
    # ``hasattr`` checks were False, the seam returned ``[]``, and every ffuf hit
    # was discarded — for as long as the seam had existed. Nothing failed: an
    # empty list is indistinguishable from "the fuzzer found nothing".
    #
    # The contract inverts that. The PRODUCER declares what it contributes; the
    # consumer calls a method that exists on every output type. A wrapper that
    # forgets to declare it does not silently yield nothing — it answers
    # ``declares_discovery() is False``, which the consumer logs loudly and the
    # component ledger records as a structurally dead seam.

    def discovered_urls(self) -> list[str]:
        """URLs or paths this output contributes to the surface map.

        Override in any output type whose tool discovers surface (crawlers,
        fuzzers, probers). The base implementation returns nothing, which is
        correct for outputs that carry no discovery items (an HTTP response, a
        WAF verdict) and is distinguishable from a real empty result via
        :meth:`declares_discovery`.

        Returns:
            Discovered URL/path strings, in the tool's own order.
        """
        return []

    @classmethod
    def declares_discovery(cls) -> bool:
        """Whether this output type declares a discovery contract.

        Returns:
            True when the class overrides :meth:`discovered_urls`. A consumer
            that asks a non-declaring output for surface is reading a seam that
            can never deliver, and must say so rather than absorb the empty
            list as a finding-free result.
        """
        return cls.discovered_urls is not ToolOutput.discovered_urls

    # ------------------------------------------------------------------
    # Fingerprint contract
    # ------------------------------------------------------------------
    #
    # The same inversion as the discovery contract above, applied to the other
    # seam that was reading a producer by guesswork. ``ReconAgent._step_web_recon``
    # extracted technologies with
    #
    #     if hasattr(r, "technologies"): ...
    #     if hasattr(r, "tech"): ...
    #
    # over ``parsed.results`` — two spellings, because two wrappers happened to
    # name the field differently, and a third wrapper naming it a third way would
    # have contributed nothing with no error. It also read ONLY the names:
    # ``WhatWebScanResult.versions`` has always been parsed and never once been
    # consumed, which is why no engagement could test a dependency against a
    # known CVE. The producer declares the whole observation now, version
    # included.

    def detected_components(self) -> list[DetectedComponent]:
        """Software components this output identified on the target.

        Override in any output type whose tool fingerprints software (web
        fingerprinters, service scanners, probers). The base implementation
        returns nothing, which is correct for outputs carrying no fingerprint
        (a crawl result, a WAF verdict) and is distinguishable from a real empty
        result via :meth:`declares_components`.

        Returns:
            Components in the tool's own order, deduplicated by the wrapper.
        """
        return []

    @classmethod
    def declares_components(cls) -> bool:
        """Whether this output type declares a fingerprint contract."""
        return cls.detected_components is not ToolOutput.detected_components


class ToolBase(ABC):
    """Abstract base class for all Clinkz tool wrappers.

    Subclass this for every external tool (nmap, ffuf, nuclei, etc.).

    Class-level attributes to override in each subclass:
        capabilities: List of capability strings (e.g., ["port_scanning"]).
                      Used by the ToolResolver for dynamic discovery.
        category: Broad phase category — "recon", "scan", "exploit", or "utility".

    Example::

        class NmapTool(ToolBase):
            capabilities = ["port_scanning", "service_detection"]
            category = "recon"

            @property
            def name(self) -> str: return "nmap"

            def get_schema(self) -> dict: ...
            def validate_input(self, args) -> dict: ...
            async def execute(self, args) -> str: ...
            def parse_output(self, raw) -> NmapOutput: ...
    """

    #: Override in subclasses — list of capability strings for the ToolResolver.
    capabilities: list[str] = []

    #: Override in subclasses — broad phase: "recon", "scan", "exploit", "utility".
    category: str = "utility"

    def __init__(self, scope: EngagementScope, timeout: int = 300) -> None:
        self.scope = scope
        self.timeout = timeout
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        # Sequence number of the most recent invocation this tool wrote to
        # the tool_invocations/ directory. Used by BaseAgent._execute_tool to
        # attach parsed output after parse_output() returns. Negative when
        # no invocation has been recorded yet for this instance.
        self.last_invocation_seq: int = -1

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name used by the LLM (e.g., 'nmap', 'ffuf')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-sentence description of what this tool does."""
        ...

    @abstractmethod
    def get_schema(self) -> dict[str, Any]:
        """Return an OpenAI-compatible function schema for this tool.

        Returns:
            Dict with keys: name, description, parameters (JSON Schema).

        Example::

            {
                "name": "nmap",
                "description": "Port scan a target host.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP or hostname"},
                        "ports": {"type": "string", "description": "Port range, e.g. 1-1000"},
                    },
                    "required": ["target"],
                },
            }
        """
        ...

    @abstractmethod
    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        """Validate and sanitise arguments before tool execution.

        Scope checking MUST happen here.

        Args:
            args: Raw arguments from the LLM.

        Returns:
            Validated and sanitised arguments.

        Raises:
            ValueError: If arguments are invalid or target is out of scope.
        """
        ...

    @abstractmethod
    async def execute(self, args: dict[str, Any]) -> str:
        """Run the tool and return raw stdout.

        Args:
            args: Validated arguments from validate_input().

        Returns:
            Raw tool output as a string.
        """
        ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> ToolOutput:
        """Parse raw tool output into a structured Pydantic model.

        Args:
            raw_output: Raw string from execute().

        Returns:
            A ToolOutput subclass with structured data.
        """
        ...

    @classmethod
    def native_availability(cls) -> bool | None:
        """Whether this tool is usable, for tools that are not a PATH binary.

        The resolver decides availability by looking for a binary, which is the
        right question for ``nmap`` and the wrong one for a tool whose runtime is
        a Python package plus a downloaded browser. Overriding this lets such a
        tool answer honestly instead of being forced into one of two lies:
        "always available" (and failing at use) or "never available".

        Returns:
            ``True``/``False`` when the subclass can answer definitively, or
            ``None`` — the default — to fall back to the binary check.
        """
        return None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_scope(self, target: str) -> None:
        """Verify target is in scope before running.

        Args:
            target: Hostname or IP to validate.

        Raises:
            ValueError: If target is outside the engagement scope.
        """
        if not self.scope.contains(target):
            raise ValueError(
                f"Target '{target}' is outside the engagement scope. "
                "Refusing to run tool. Check your scope definition."
            )

    def _halt_result(self) -> tuple[str, str, int] | None:
        """Return a failure triple when the engagement has been halted.

        The kill switch has to reach subprocess tools too — a halted engagement
        that keeps shelling out to ``ffuf`` has not stopped. Returning a
        non-zero result rather than raising keeps the contract every caller
        already handles, and stderr says plainly why nothing ran.

        Only the halt is checked here. Rate limiting and the concurrency cap
        live at the HTTP chokepoint (:meth:`clinkz.tools.http_client.HTTPClientTool.execute`)
        and must NOT be duplicated here: the docker path reaches this method
        from inside that chokepoint, so acquiring a second slot per request
        would deadlock the semaphore and double-count every rate token.
        External tools that generate their own traffic are paced by their own
        rate flags instead — see :meth:`clinkz.tools.ffuf.FfufTool.execute`.

        Returns:
            ``(stdout, stderr, returncode)`` when halted, else ``None``.
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is None or not governor.halted:
            return None
        message = (
            f"engagement halted ({governor.halt_reason}): {governor.halt_detail} "
            "— no further tool execution"
        )
        self._logger.warning("%s [%s]", message, self.name)
        return "", message, 1

    async def _run_subprocess(self, cmd: list[str]) -> tuple[str, str, int]:
        """Execute a shell command and capture output.

        When ``TOOL_EXEC_MODE=docker`` in config, the command is wrapped in
        ``docker exec <DOCKER_CONTAINER> ...`` so that tools run inside the
        security-tools container instead of on the host.

        Args:
            cmd: Command and arguments (no shell=True — avoids injection).

        Returns:
            (stdout, stderr, returncode)

        Raises:
            asyncio.TimeoutError: If the command exceeds self.timeout seconds.
        """
        from clinkz.config import settings
        from clinkz.observability.trace import Stopwatch

        halted = self._halt_result()
        if halted is not None:
            return halted

        exec_mode = settings.tool_exec_mode
        if exec_mode == "docker":
            cmd = ["docker", "exec", settings.docker_container, *cmd]

        self._logger.debug("Executing: %s", " ".join(cmd))
        stopwatch = Stopwatch()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=self.timeout,
        )
        returncode = proc.returncode or 0
        self._logger.debug("Exit code: %d", returncode)
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        self._emit_trace_records(
            cmd=cmd,
            exec_mode=exec_mode,
            stdin=None,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_ms=stopwatch.elapsed_ms,
        )
        return stdout, stderr, returncode

    async def _run_subprocess_stdin(
        self,
        cmd: list[str],
        stdin_data: str,
        trace_cmd: list[str] | None = None,
    ) -> tuple[str, str, int]:
        """Execute a command with data piped to stdin.

        Like :meth:`_run_subprocess` but feeds *stdin_data* to the process.
        When ``TOOL_EXEC_MODE=docker``, uses ``docker exec -i`` so that stdin
        is forwarded into the container.

        Args:
            cmd: Command and arguments.
            stdin_data: Text to write to the process's stdin.
            trace_cmd: What to RECORD in place of *cmd*, when the two must
                differ. The redaction chokepoint works on values it can
                recognise in the text it is given, so an argument that carries
                credential material in an ENCODED form — base64, a packed blob —
                passes through it untouched: it is one opaque token, not a
                ``name=value`` a cookie rule can match. A caller that builds
                such an argument is the only code that still knows what is
                inside it, and so is the only code that can hand the recorder a
                safe equivalent. Defaults to *cmd*, so every existing caller is
                unchanged.

        Returns:
            (stdout, stderr, returncode)

        Raises:
            asyncio.TimeoutError: If the command exceeds self.timeout seconds.
        """
        from clinkz.config import settings
        from clinkz.observability.trace import Stopwatch, get_active_trace_writer  # noqa: F401

        halted = self._halt_result()
        if halted is not None:
            return halted

        exec_mode = settings.tool_exec_mode
        prefix = (
            ["docker", "exec", "-i", settings.docker_container] if exec_mode == "docker" else []
        )
        cmd = [*prefix, *cmd]
        recorded_cmd = [*prefix, *trace_cmd] if trace_cmd is not None else cmd

        self._logger.debug("Executing (stdin): %s", " ".join(recorded_cmd))
        stopwatch = Stopwatch()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode()),
            timeout=self.timeout,
        )
        returncode = proc.returncode or 0
        self._logger.debug("Exit code: %d", returncode)
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        self._emit_trace_records(
            cmd=recorded_cmd,
            exec_mode=exec_mode,
            stdin=stdin_data,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_ms=stopwatch.elapsed_ms,
            via_stdin=True,
        )
        return stdout, stderr, returncode

    def _emit_trace_records(
        self,
        *,
        cmd: list[str],
        exec_mode: str,
        stdin: str | None,
        stdout: str,
        stderr: str,
        returncode: int,
        duration_ms: float,
        via_stdin: bool = False,
    ) -> None:
        """Write the full-fidelity invocation record and the trace summary.

        Centralised here so both ``_run_subprocess`` and ``_run_subprocess_stdin``
        emit consistent records — and so a future caller (e.g. an MCP-backed
        execute path) can reuse the same helper.
        """
        from clinkz.observability.trace import get_active_trace_writer

        writer = get_active_trace_writer()
        if writer is None:
            return

        try:
            seq, path = writer.record_tool_invocation(
                tool_name=self.name,
                exec_mode=exec_mode,
                cwd=os.getcwd(),
                command=cmd,
                env_overrides={},
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                exit_code=returncode,
                duration_ms=duration_ms,
            )
            self.last_invocation_seq = seq
        except Exception as exc:  # noqa: BLE001 — tracing must never raise
            self._logger.warning("Failed to record tool invocation: %s", exc)
            seq, path = -1, None

        extra: dict[str, Any] = {"tool": self.name, "invocation_seq": seq}
        if path is not None:
            try:
                extra["invocation_file"] = str(path.relative_to(writer.outputs_root))
            except ValueError:
                extra["invocation_file"] = str(path)
        if via_stdin:
            extra["via_stdin"] = True

        writer.tool_call(
            stage=getattr(self, "category", "utility"),
            cmd=cmd,
            stdout_summary=stdout,
            stderr_summary=stderr,
            exit_code=returncode,
            duration_ms=duration_ms,
            extra=extra,
        )
