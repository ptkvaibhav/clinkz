"""Global configuration for Clinkz.

All settings are loaded from environment variables (via .env or shell).
Never hardcode API keys — use .env.example as a template.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

LLMProvider = Literal["openai", "anthropic", "gemini", "ollama"]


class Settings(BaseModel):
    """Validated settings loaded from environment variables."""

    # LLM provider
    llm_provider: LLMProvider = Field(default="openai")

    # API keys
    openai_api_key: str | None = Field(default=None)
    anthropic_api_key: str | None = Field(default=None)
    gemini_api_key: str | None = Field(default=None)
    google_api_key: str | None = Field(default=None)  # legacy alias for gemini_api_key

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434")

    # Model selection
    orchestrator_model: str = Field(default="gpt-4o")
    agent_model: str = Field(default="gpt-4o-mini")
    anthropic_model: str = Field(default="claude-sonnet-4-20250514")
    gemini_model: str = Field(default="gemini-2.5-flash")

    # Per-agent LLM provider overrides (default to global llm_provider if unset)
    recon_llm_provider: LLMProvider = Field(default="gemini")
    scan_llm_provider: LLMProvider = Field(default="gemini")
    exploit_llm_provider: LLMProvider = Field(default="anthropic")
    research_llm_provider: LLMProvider = Field(default="anthropic")
    report_llm_provider: LLMProvider = Field(default="gemini")

    # State store
    db_path: Path = Field(default=Path("clinkz.db"))

    # Tool execution
    tool_timeout: int = Field(default=300, description="Max seconds per tool invocation")

    # Tool execution mode: "local" runs tools directly, "docker" runs via docker exec
    tool_exec_mode: str = Field(default="local", description="'local' or 'docker'")
    docker_container: str = Field(
        default="clinkz-tools", description="Docker container name for tool execution"
    )

    # MCP servers — list of server commands or URLs, JSON-encoded in .env
    # Examples: ["burpsuite-mcp", "http://localhost:8080/mcp", "python my_server.py"]
    mcp_servers: list[str] = Field(default_factory=list)

    @classmethod
    def from_env(cls) -> Settings:
        """Construct Settings from environment variables."""
        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "openai"),  # type: ignore[arg-type]
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            orchestrator_model=os.getenv("ORCHESTRATOR_MODEL", "gpt-4o"),
            agent_model=os.getenv("AGENT_MODEL", "gpt-4o-mini"),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            recon_llm_provider=os.getenv("RECON_LLM_PROVIDER", "gemini"),  # type: ignore[arg-type]
            scan_llm_provider=os.getenv("SCAN_LLM_PROVIDER", "gemini"),  # type: ignore[arg-type]
            exploit_llm_provider=os.getenv("EXPLOIT_LLM_PROVIDER", "anthropic"),  # type: ignore[arg-type]
            research_llm_provider=os.getenv("RESEARCH_LLM_PROVIDER", "anthropic"),  # type: ignore[arg-type]
            report_llm_provider=os.getenv("REPORT_LLM_PROVIDER", "gemini"),  # type: ignore[arg-type]
            db_path=Path(os.getenv("DB_PATH", "clinkz.db")),
            tool_timeout=int(os.getenv("TOOL_TIMEOUT", "300")),
            tool_exec_mode=os.getenv("TOOL_EXEC_MODE", "local"),
            docker_container=os.getenv("DOCKER_CONTAINER", "clinkz-tools"),
            mcp_servers=json.loads(os.getenv("MCP_SERVERS", "[]")),
        )


# Module-level singleton — imported everywhere as `from clinkz.config import settings`
settings = Settings.from_env()
