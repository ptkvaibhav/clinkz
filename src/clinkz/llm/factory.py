"""LLM client factory.

Returns the correct LLMClient implementation based on the LLM_PROVIDER
environment variable (or an explicit override).

Usage::

    from clinkz.llm.factory import get_llm_client
    client = get_llm_client()                      # global default
    client = get_llm_client("openai")              # explicit provider
    client = get_llm_client(agent_role="exploit")  # per-agent provider
"""

from __future__ import annotations

import logging

from clinkz.config import settings
from clinkz.llm.base import LLMClient

logger = logging.getLogger(__name__)


#: Mapping from agent role (``"recon"`` / ``"scan"`` / ...) to the settings
#: field that holds that agent's preferred provider. Keeps the role → env
#: var plumbing in one place.
AGENT_PROVIDER_SETTINGS: dict[str, str] = {
    "recon": "recon_llm_provider",
    "scan": "scan_llm_provider",
    "crawl": "scan_llm_provider",  # legacy alias
    "exploit": "exploit_llm_provider",
    "research": "research_llm_provider",
    "report": "report_llm_provider",
}


def get_llm_client(
    provider: str | None = None,
    *,
    agent_role: str | None = None,
    model: str | None = None,
) -> LLMClient:
    """Instantiate and return the correct LLMClient.

    Args:
        provider: Explicit provider override. Takes precedence over
            ``agent_role`` when supplied.
        agent_role: Agent role name (e.g., ``"recon"``, ``"exploit"``).
            When set and ``provider`` is None, resolves to the provider
            configured for that role in settings.
        model: Optional model-name override. Forwarded to the Gemini and
            Anthropic clients (which accept a single ``model`` kwarg) so a
            caller can pin a per-role model — e.g. Research uses
            ``gemini_research_model`` while Recon/Scan keep ``gemini_model``.
            Ignored by providers that take no single model kwarg (OpenAI).

    Returns:
        An initialized LLMClient instance.

    Raises:
        ValueError: If the resolved provider is not supported.
    """
    resolved = provider
    if resolved is None and agent_role is not None:
        setting_name = AGENT_PROVIDER_SETTINGS.get(agent_role)
        if setting_name is not None:
            resolved = getattr(settings, setting_name, None)
    if resolved is None:
        resolved = settings.llm_provider_default or settings.llm_provider

    logger.info("Initializing LLM client: provider=%s agent_role=%s", resolved, agent_role or "-")

    if resolved == "openai":
        from clinkz.llm.openai_client import OpenAIClient

        return OpenAIClient()

    if resolved == "anthropic":
        from clinkz.llm.anthropic_client import AnthropicClient

        return AnthropicClient(model=model)

    if resolved == "gemini":
        from clinkz.llm.gemini_client import GeminiClient

        return GeminiClient(model=model)

    if resolved == "ollama":
        from clinkz.llm.ollama_client import OllamaClient

        return OllamaClient()

    raise ValueError(
        f"Unsupported LLM provider: '{resolved}'. Valid options: openai, anthropic, gemini, ollama"
    )
