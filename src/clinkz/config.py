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

    # Top-level LLM provider. Defaults to gemini to reflect the actual runtime:
    # every per-agent default below is gemini/anthropic and no agent defaults to
    # openai — openai is retained only as the terminal fallback in the resilient
    # chains (llm/fallback.py). This is the last-resort provider the Orchestrator's
    # own reasoning LLM resolves to when neither ORCHESTRATOR_LLM_PROVIDER nor an
    # explicit --provider is set.
    llm_provider: LLMProvider = Field(default="gemini")

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
    anthropic_model: str = Field(default="claude-sonnet-5")
    # All Gemini-backed agents (Recon / Scan / Report, and Exploit's Gemini
    # fallback) run on Gemini 3.1 Flash-Lite (GA). Never set this to the
    # deprecated gemini-3.1-flash-lite-preview (shut down 2026-05-25).
    gemini_model: str = Field(default="gemini-3.1-flash-lite")
    gemini_exploit_model: str = Field(default="gemini-3.1-flash-lite")
    # Research runs on Gemini 3.1 Flash-Lite (GA). Pinned separately from the
    # shared gemini_model so Recon/Scan/Report are unaffected. Never set this to
    # the deprecated gemini-3.1-flash-lite-preview (shut down 2026-05-25).
    gemini_research_model: str = Field(default="gemini-3.1-flash-lite")

    # Per-agent LLM provider overrides
    # - Fast, cheap, high-volume calls → gemini (Flash)
    # - Complex reasoning, fewer calls  → anthropic (Claude)
    recon_llm_provider: LLMProvider = Field(default="gemini")
    scan_llm_provider: LLMProvider = Field(default="gemini")
    report_llm_provider: LLMProvider = Field(default="gemini")
    exploit_llm_provider: LLMProvider = Field(default="anthropic")
    # Research moved from anthropic → gemini (Flash-Lite) for live Search
    # Grounding and to avoid the slow retry-storm it previously hit on the
    # heavier Gemini Pro model via the AnthropicClient.research() fallback hop.
    research_llm_provider: LLMProvider = Field(default="gemini")

    # Global default used by the resilient client when no per-agent override
    # matches and the profile chain is exhausted.
    llm_provider_default: LLMProvider = Field(default="gemini")

    # Hard per-call timeout (seconds) for a single LLM request. This is an
    # operation-level safety valve: a single hung generate/messages.create call
    # is cancelled after this many seconds so it can never stall the engagement
    # (the Gemini client already enforces its own 120s ceiling; Anthropic and
    # OpenAI wrap each call in asyncio.wait_for with this value). Bounding a
    # single LLM call matters more now that the exploit phase has no wall-clock
    # deadline — op-level timeouts are the only safety valve.
    llm_request_timeout: float = Field(
        default=120.0, description="Hard timeout (seconds) for a single LLM call"
    )

    # Output ceiling for a single LLM call. On a thinking-capable model this
    # budget covers reasoning AND response text together, so a value sized for
    # the answer alone lets a hard prompt spend the whole allowance thinking
    # and return zero text blocks. The old 4096 did exactly that to the exploit
    # planner. 16000 is the documented non-streaming ceiling — high enough to
    # leave reasoning room, low enough to stay inside the SDK's HTTP timeout.
    llm_max_output_tokens: int = Field(
        default=16000, description="max_tokens for a single LLM call (covers thinking + text)"
    )

    # Prompt caching. Applies only where a caller supplied a stable prefix
    # (llm.base.PromptSegments); a plain-string prompt is unaffected either way.
    llm_prompt_cache_enabled: bool = Field(
        default=True, description="Attach a cache breakpoint to run-stable prompt prefixes"
    )
    # "5m" (1.25x write premium) or "1h" (2.0x). Measured across the four P7
    # engagements, the exploit agent's largest gap between consecutive Anthropic
    # calls was 118s and NO gap exceeded 5 minutes, so the 5m entry never
    # expires mid-run and 1h would double the write cost for nothing.
    llm_prompt_cache_ttl: str = Field(
        default="5m", description="Cache breakpoint TTL: '5m' or '1h'"
    )

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

    # Gemini call-rate ceiling (requests/minute) enforced by GeminiClient's
    # sliding-window limiter. Default sized for Gemini API Tier 1 (well above
    # the free tier's 5 RPM) while staying conservative enough to avoid bursting
    # into 429s. Tune with GEMINI_MAX_RPM.
    gemini_max_rpm: int = Field(
        default=30, description="Max Gemini requests per minute (per client)"
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

    # Exploit phase wall-clock budget (seconds). 0 (the default) means NO phase
    # cap — the full exploit task queue runs to completion and no category is
    # starved by a phase-level clock. Operation-level timeouts (per HTTP request,
    # per tool subprocess, per LLM call) are the safety valve against a genuine
    # hang. Set EXPLOIT_PHASE_BUDGET>0 to restore the old cooperative-stop
    # behaviour (the agent stops dispatching new tasks shortly before the budget
    # elapses and returns cleanly). Kept configurable rather than hardcoding
    # "unbounded" so the bound is trivially reversible.
    exploit_phase_budget: float = Field(
        default=0.0,
        description="Wall-clock seconds for the exploit phase; 0 = unbounded (no phase cap).",
    )

    # How many ranked endpoints to show the LLM exploit planner. The full
    # endpoint list (often hundreds, polluted with crawler artifacts) is
    # structurally deduped and ranked first; this caps how many of the
    # highest-value ones are placed in the planning prompt. Raised from the old
    # hardcoded 50, which let canonical vulnerable endpoints fall outside the
    # window on large crawls.
    exploit_plan_prompt_endpoints: int = Field(
        default=120,
        description="Max ranked endpoints placed in the LLM exploit-planning prompt.",
    )

    # Exploit dispatch — per-vuln-class soft caps used by the round-robin
    # scheduler. Once a category produces this many findings OR consumes this
    # many seconds, its remaining tasks move to the back of the rotation so
    # untouched categories run first. With no phase budget these only affect
    # ordering/fairness — every task still runs to completion (a deprioritised
    # category is moved to the back of the rotation, never dropped).
    exploit_category_max_findings: int = Field(
        default=5,
        description="Findings after which a vuln-class is deprioritised in dispatch.",
    )
    exploit_category_time_budget: float = Field(
        default=90.0,
        description="Seconds after which a vuln-class is deprioritised in dispatch.",
    )

    # Research phase hard wall-clock budget (seconds). The Research Agent returns
    # whatever techniques it has gathered once this elapses, so a slow/grounded
    # provider can never consume the whole engagement. Exploit is decoupled from
    # Research (it depends on Scan), so this only bounds Research's own runtime.
    research_time_budget: float = Field(
        default=180.0,
        description="Max wall-clock seconds for the Research phase before partial return.",
    )

    # Scan phase hard wall-clock budget (seconds). The Scan Agent skips its
    # remaining optional work once this elapses and returns the surface it has
    # mapped so far — because the phase that maps the attack surface must never
    # be force-killed. It used to have no budget of its own and was cut off by
    # the orchestrator's generic phase timeout, which discards the agent's
    # return value: on a real SPA the crawl + enrichment + coverage-expansion
    # pass ran past 600 s and the Exploit planner was handed ZERO endpoints
    # after the scan had discovered 138. A partial map is a scan result; a
    # killed phase is not.
    scan_time_budget: float = Field(
        default=900.0,
        description="Max wall-clock seconds for the Scan phase before partial return.",
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

    # ---- Out-of-band (P6) confirmation collaborator (docs/p6-oob-design.md) ----
    # DISABLED by default so the black-box floor is unchanged: with no collaborator
    # every blind hypothesis defers exactly as before (``blind_suspected``). Opt in
    # per engagement — "docker" self-hosts a receive-only DNS+HTTP listener the
    # target reaches on the lab bridge (guarantees egress); "external" is reserved
    # for a self-hosted interactsh-style server (the public shared server is
    # refused, not defaulted — §P6.1.5 guardrail 5).
    oob_collaborator_mode: Literal["disabled", "docker", "external"] = Field(
        default="disabled",
        description="P6 OOB collaborator provisioning mode ('disabled' = black-box floor).",
    )
    # The callback authority the carrier interpolates the minted nonce into. For the
    # PATH shape (docker default) this is a fixed reachable host[:port]; for the
    # SUBDOMAIN shape it is a wildcard-resolvable base zone. Set per environment.
    oob_zone: str = Field(
        default="oob.clinkz.test",
        description="P6 collaborator callback authority (zone or reachable host:port).",
    )
    # "subdomain" rides the nonce as <nonce>.<zone> (needs wildcard DNS); "path"
    # rides it as http://<zone>/<nonce> with a fixed authority (guaranteed reachable
    # in docker mode, no wildcard-DNS dependency).
    oob_callback_shape: Literal["subdomain", "path"] = Field(
        default="path",
        description="Where the P6 nonce rides in the callback host ('subdomain'|'path').",
    )
    # The single shared wall-clock the whole pending set of blind probes drains
    # against (fire-and-reap, §P6.3.2). Bounds the tail wait; sized small for the
    # lab (a real target's async-logging callback may need longer).
    oob_wait_window: float = Field(
        default=20.0,
        description="Seconds to wait (shared window) for P6 callbacks before reaping.",
    )
    # Listener bind ports + the address the DNS leg advertises (the IPv4 a target
    # should connect to). Defaults are host-side; a driver/orchestrator overrides
    # the advertised address with the bridge/host address a real target can reach.
    oob_http_port: int = Field(default=18080, description="P6 collaborator HTTP port.")
    oob_dns_port: int = Field(default=15353, description="P6 collaborator DNS (UDP) port.")
    oob_advertised_ip: str = Field(
        default="127.0.0.1",
        description="IPv4 the P6 DNS leg answers with (target-reachable address).",
    )

    # --- P7: the client-side execution oracle -------------------------------
    # Three states, because the two things that were previously conflated pull in
    # opposite directions.
    #
    # A REAL ENGAGEMENT should confirm DOM-XSS, client-rendered XSS and CSP when
    # a browser is available: an oracle that only a hand-built driver can reach
    # is not a capability the product has. A DIRECT METHODOLOGY INVOCATION — a
    # unit suite, a replay, a smoke cell — must never launch a browser, because
    # then the engine behaves differently on a developer machine that has
    # Playwright than on CI that does not, and that divergence is exactly what
    # made a keyless gate report a different number than CI (LESSONS #35). It is
    # also worth real time: self-resolving in the unit suites took them from
    # 1.8 s to 21 s.
    #
    # So the switch is on WHO IS ASKING, not on what happens to be installed:
    #
    #   auto       — the default. The Orchestrator provisions the oracle for an
    #                engagement it is running; a directly-invoked agent does not
    #                resolve one for itself, so the black-box floor stays
    #                byte-identical and the suites stay browser-free.
    #   playwright — always, including self-resolution from a direct invocation.
    #                What a live driver opts into.
    #   disabled   — never, even in an engagement. The escape hatch for a run
    #                that must not start a browser at all.
    client_oracle_mode: Literal["auto", "disabled", "playwright"] = Field(
        default="auto",
        description=(
            "P7 client-side execution oracle mode: 'auto' (engagements only), "
            "'playwright' (also self-resolved on direct invocation), 'disabled'."
        ),
    )

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

        global_default = os.getenv("LLM_PROVIDER_DEFAULT") or os.getenv("LLM_PROVIDER", "gemini")

        return cls(
            llm_provider=os.getenv("LLM_PROVIDER", "gemini"),  # type: ignore[arg-type]
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            orchestrator_model=os.getenv("ORCHESTRATOR_MODEL", "gpt-4o"),
            agent_model=os.getenv("AGENT_MODEL", "gpt-4o-mini"),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5"),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite"),
            gemini_exploit_model=os.getenv("GEMINI_EXPLOIT_MODEL", "gemini-3.1-flash-lite"),
            gemini_research_model=os.getenv("GEMINI_RESEARCH_MODEL", "gemini-3.1-flash-lite"),
            recon_llm_provider=_agent_provider("recon", "gemini"),  # type: ignore[arg-type]
            scan_llm_provider=_agent_provider("scan", "gemini"),  # type: ignore[arg-type]
            exploit_llm_provider=_agent_provider("exploit", "anthropic"),  # type: ignore[arg-type]
            research_llm_provider=_agent_provider("research", "gemini"),  # type: ignore[arg-type]
            report_llm_provider=_agent_provider("report", "gemini"),  # type: ignore[arg-type]
            llm_provider_default=global_default,  # type: ignore[arg-type]
            llm_request_timeout=float(os.getenv("LLM_REQUEST_TIMEOUT", "120.0")),
            llm_max_output_tokens=int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "16000")),
            llm_prompt_cache_enabled=os.getenv("LLM_PROMPT_CACHE_ENABLED", "true").lower()
            not in ("0", "false", "no"),
            llm_prompt_cache_ttl=os.getenv("LLM_PROMPT_CACHE_TTL", "5m"),
            llm_max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            llm_retry_base_delay=float(os.getenv("LLM_RETRY_BASE_DELAY", "2.0")),
            llm_retry_max_delay=float(os.getenv("LLM_RETRY_MAX_DELAY", "30.0")),
            gemini_max_rpm=int(os.getenv("GEMINI_MAX_RPM", "30")),
            db_path=Path(os.getenv("DB_PATH", "clinkz.db")),
            tool_timeout=int(os.getenv("TOOL_TIMEOUT", "300")),
            exploit_max_plan_tasks=int(os.getenv("EXPLOIT_MAX_PLAN_TASKS", "150")),
            exploit_phase_budget=float(os.getenv("EXPLOIT_PHASE_BUDGET", "0.0")),
            exploit_plan_prompt_endpoints=int(os.getenv("EXPLOIT_PLAN_PROMPT_ENDPOINTS", "120")),
            exploit_category_max_findings=int(os.getenv("EXPLOIT_CATEGORY_MAX_FINDINGS", "5")),
            exploit_category_time_budget=float(os.getenv("EXPLOIT_CATEGORY_TIME_BUDGET", "90.0")),
            research_time_budget=float(os.getenv("RESEARCH_TIME_BUDGET", "180.0")),
            scan_time_budget=float(os.getenv("SCAN_TIME_BUDGET", "900.0")),
            tool_exec_mode=os.getenv("TOOL_EXEC_MODE", "docker"),
            docker_container=os.getenv("DOCKER_CONTAINER", "clinkz-tools"),
            mcp_servers=json.loads(os.getenv("MCP_SERVERS", "[]")),
            oob_collaborator_mode=os.getenv("OOB_COLLABORATOR_MODE", "disabled"),  # type: ignore[arg-type]
            oob_zone=os.getenv("OOB_ZONE", "oob.clinkz.test"),
            oob_callback_shape=os.getenv("OOB_CALLBACK_SHAPE", "path"),  # type: ignore[arg-type]
            oob_wait_window=float(os.getenv("OOB_WAIT_WINDOW", "20.0")),
            oob_http_port=int(os.getenv("OOB_HTTP_PORT", "18080")),
            oob_dns_port=int(os.getenv("OOB_DNS_PORT", "15353")),
            oob_advertised_ip=os.getenv("OOB_ADVERTISED_IP", "127.0.0.1"),
            client_oracle_mode=os.getenv("CLIENT_ORACLE_MODE", "auto"),  # type: ignore[arg-type]
        )


# Module-level singleton — imported everywhere as `from clinkz.config import settings`
settings = Settings.from_env()
