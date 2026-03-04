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
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

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

    async def _run_subprocess(self, cmd: list[str]) -> tuple[str, str, int]:
        """Execute a shell command and capture output.

        Args:
            cmd: Command and arguments (no shell=True — avoids injection).

        Returns:
            (stdout, stderr, returncode)

        Raises:
            asyncio.TimeoutError: If the command exceeds self.timeout seconds.
        """
        self._logger.debug("Executing: %s", " ".join(cmd))
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
        return stdout, stderr, returncode
