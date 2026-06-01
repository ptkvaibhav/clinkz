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
    anthropic_model: str = Field(default="claude-sonnet-4-6")
    gemini_model: str = Field(default="gemini-2.5-pro")
    gemini_exploit_model: str = Field(default="gemini-2.5-pro")

    # Per-agent LLM provider overrides
    # - Fast, cheap, high-volume calls → gemini (Flash)
    # - Complex reasoning, fewer calls  → anthropic (Claude)
    recon_llm_provider: LLMProvider = Field(default="gemini")
    scan_llm_provider: LLMProvider = Field(default="gemini")
    report_llm_provider: LLMProvider = Field(default="gemini")
    exploit_llm_provider: LLMProvider = Field(default="anthropic")
    research_llm_provider: LLMProvider = Field(default="anthropic")

    # Global default used by the resilient client when no per-agent override
    # matches and the profile chain is exhausted.
    llm_provider_default: LLMProvider = Field(default="gemini")

    # Per-provider retry budget (used by each LLMClient's backoff loop).
    # With fallback chains we keep each provider's budget low so we move to
    # the next provider quickly instead of burning minutes on a single one.
    llm_max_retries: int = Field(default=3, description="Max retries per provider")
    llm_retry_base_delay: float = Field(
        default=2.0, description="Initial exponential backoff delay (seconds)"
    )
    llm_retry_max_delay: float = Field(
        default=30.0, description="Cap on exponential backoff (seconds)"
    )

    # State store
    db_path: Path = Field(default=Path("clinkz.db"))

    # Tool execution
    tool_timeout: int = Field(default=300, description="Max seconds per tool invocation")

    # Exploit planning — caps the deterministic fallback plan so a large crawl
    # cannot explode into thousands of tasks (the LLM plan is the normal path).
    exploit_max_plan_tasks: int = Field(
        default=150,
        description="Maximum number of tasks in a deterministic exploit plan.",
    )

    # Exploit dispatch — per-vuln-class soft caps used by the round-robin
    # scheduler. Once a category produces this many findings OR consumes this
    # many seconds, its remaining tasks move to the back of the rotation so
    # untouched categories run first (no single high-fan-out class can starve
    # the shared phase budget).
    exploit_category_max_findings: int = Field(
        default=5,
        description="Findings after which a vuln-class is deprioritised in dispatch.",
    )
    exploit_category_time_budget: float = Field(
        default=90.0,
        description="Seconds after which a vuln-class is deprioritised in dispatch.",
    )

    # Tool execution mode: "local" runs tools directly, "docker" runs via docker exec.
    # Default is "docker" because local mode is a footgun — the resolver can
    # match unrelated host binaries that share a name (e.g., the Python `httpx`
    # CLI masquerading as ProjectDiscovery's httpx). Override with
    # TOOL_EXEC_MODE=local when a developer genuinely wants host execution.
    tool_exec_mode: str = Field(default="docker", description="'local' or 'docker'")
    docker_container: str = Field(
        default="clinkz-tools", description="Docker container name for tool execution"
    )

    # MCP servers — list of server commands or URLs, JSON-encoded in .env
    # Examples: ["burpsuite-mcp", "http://localhost:8080/mcp", "python my_server.py"]
    mcp_servers: list[str] = Field(default_factory=list)

    @classmethod
    def from_env(cls) -> Settings:
        """Construct Settings from environment variables.

        Per-agent LLM providers accept both the modern ``LLM_PROVIDER_<AGENT>``
        names and the legacy ``<AGENT>_LLM_PROVIDER`` names (in that priority
        order) so old ``.env`` files keep working.
        """

        def _agent_provider(agent: str, fallback: str) -> str:
            upper = agent.upper()
            return (
                os.getenv(f"LLM_PROVIDER_{upper}")
                or os.getenv(f"{upper}_LLM_PROVIDER")
                or os.getenv("LLM_PROVIDER_DEFAULT")
                or fallback
            )

        global_default = os.getenv("LLM_PROVIDER_DEFAULT") or os.getenv("LLM_PROVIDER", "openai")

        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "openai"),  # type: ignore[arg-type]
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            orchestrator_model=os.getenv("ORCHESTRATOR_MODEL", "gpt-4o"),
            agent_model=os.getenv("AGENT_MODEL", "gpt-4o-mini"),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-pro"),
            gemini_exploit_model=os.getenv("GEMINI_EXPLOIT_MODEL", "gemini-2.5-pro"),
            recon_llm_provider=_agent_provider("recon", "gemini"),  # type: ignore[arg-type]
            scan_llm_provider=_agent_provider("scan", "gemini"),  # type: ignore[arg-type]
            exploit_llm_provider=_agent_provider("exploit", "anthropic"),  # type: ignore[arg-type]
            research_llm_provider=_agent_provider("research", "anthropic"),  # type: ignore[arg-type]
            report_llm_provider=_agent_provider("report", "gemini"),  # type: ignore[arg-type]
            llm_provider_default=global_default,  # type: ignore[arg-type]
            llm_max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            llm_retry_base_delay=float(os.getenv("LLM_RETRY_BASE_DELAY", "2.0")),
            llm_retry_max_delay=float(os.getenv("LLM_RETRY_MAX_DELAY", "30.0")),
            db_path=Path(os.getenv("DB_PATH", "clinkz.db")),
            tool_timeout=int(os.getenv("TOOL_TIMEOUT", "300")),
            exploit_max_plan_tasks=int(os.getenv("EXPLOIT_MAX_PLAN_TASKS", "150")),
            exploit_category_max_findings=int(os.getenv("EXPLOIT_CATEGORY_MAX_FINDINGS", "5")),
            exploit_category_time_budget=float(os.getenv("EXPLOIT_CATEGORY_TIME_BUDGET", "90.0")),
            tool_exec_mode=os.getenv("TOOL_EXEC_MODE", "docker"),
            docker_container=os.getenv("DOCKER_CONTAINER", "clinkz-tools"),
            mcp_servers=json.loads(os.getenv("MCP_SERVERS", "[]")),
        )


# Module-level singleton — imported everywhere as `from clinkz.config import settings`
settings = Settings.from_env()
