"""LLM client factory.

Returns the correct LLMClient implementation based on the LLM_PROVIDER
environment variable (or an explicit override).

Usage::

    from clinkz.llm.factory import get_llm_client
    client = get_llm_client()           # uses LLM_PROVIDER from env
    client = get_llm_client("openai")   # explicit override
"""

from __future__ import annotations

import logging

from clinkz.config import settings
from clinkz.llm.base import LLMClient

logger = logging.getLogger(__name__)


def get_llm_client(provider: str | None = None) -> LLMClient:
    """Instantiate and return the correct LLMClient.

    Args:
        provider: Override the provider. If None, reads LLM_PROVIDER from settings.

    Returns:
        An initialized LLMClient instance.

    Raises:
        ValueError: If the provider is not supported.
    """
    resolved = provider or settings.llm_provider
    logger.info("Initializing LLM client: provider=%s", resolved)

    if resolved == "openai":
        from clinkz.llm.openai_client import OpenAIClient

        return OpenAIClient()

    if resolved == "anthropic":
        from clinkz.llm.anthropic_client import AnthropicClient

        return AnthropicClient()

    if resolved == "gemini":
        from clinkz.llm.gemini_client import GeminiClient

        return GeminiClient()

    if resolved == "ollama":
        from clinkz.llm.ollama_client import OllamaClient

        return OllamaClient()

    raise ValueError(
        f"Unsupported LLM provider: '{resolved}'. Valid options: openai, anthropic, gemini, ollama"
    )
