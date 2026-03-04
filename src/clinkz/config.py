"""Global configuration for Clinkz.

All settings are loaded from environment variables (via .env or shell).
Never hardcode API keys — use .env.example as a template.
"""

from __future__ import annotations

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
    google_api_key: str | None = Field(default=None)

    # Ollama
    ollama_base_url: str = Field(default="http://localhost:11434")

    # Model selection
    orchestrator_model: str = Field(default="gpt-4o")
    agent_model: str = Field(default="gpt-4o-mini")

    # State store
    db_path: Path = Field(default=Path("clinkz.db"))

    # Tool execution
    tool_timeout: int = Field(default=300, description="Max seconds per tool invocation")

    @classmethod
    def from_env(cls) -> Settings:
        """Construct Settings from environment variables."""
        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "openai"),  # type: ignore[arg-type]
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            orchestrator_model=os.getenv("ORCHESTRATOR_MODEL", "gpt-4o"),
            agent_model=os.getenv("AGENT_MODEL", "gpt-4o-mini"),
            db_path=Path(os.getenv("DB_PATH", "clinkz.db")),
            tool_timeout=int(os.getenv("TOOL_TIMEOUT", "300")),
        )


# Module-level singleton — imported everywhere as `from clinkz.config import settings`
settings = Settings.from_env()
