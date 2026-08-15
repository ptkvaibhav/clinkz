# Contributing to Clinkz

## Development Setup

```bash
git clone https://github.com/ptkvaibhav/clinkz.git
cd clinkz
python scripts/bootstrap.py   # FIRST — activates this clone's enforcement hooks
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env       # Add your API key
```

Run `scripts/bootstrap.py` before anything else. `core.hooksPath` is per-clone
local config that is never committed, so a fresh clone has no active pre-commit
hook and a `git add -f outputs/… && git commit` lands the leak in HEAD. The
bootstrap needs nothing but git and the standard library, so it runs before the
virtualenv exists. See [`.claude/hooks/README.md`](.claude/hooks/README.md) for
the three enforcement layers and which of them can be bypassed.

## Adding a New Tool Wrapper

See [docs/adding-tools.md](docs/adding-tools.md) for the full guide. In short:

1. Create `src/clinkz/tools/your_tool.py` inheriting from `ToolBase`
2. Implement `validate_input()`, `build_command()`, and `parse_output()`
3. Register capabilities in the `CAPABILITIES` class attribute
4. Add a test in `tests/test_tools/test_your_tool.py` using fixture data
5. Save sample output in `tests/fixtures/`
6. Add the tool to `PARSERS` in `src/clinkz/observability/corpus_replay.py` so the
   offline parser gate actually covers it — a tool absent from that map is
   counted as `no-parser` and its parser can break unnoticed

When you mock a tool output in a test, **mirror the real model's fields**. A mock
shaped to what the consumer happens to read makes the suite assert a contract only
the mock honours.

All tool wrappers must:
- Return Pydantic models (never raw strings)
- Call `_check_scope()` in `validate_input()` for scope enforcement
- **Override `discovered_urls()` if the tool discovers surface** (crawler, fuzzer,
  prober). The consumer seam reads this declared contract; it never guesses at
  field names. A wrapper that discovers URLs and does not declare it is reported
  as a DEAD SEAM rather than silently contributing nothing — which is exactly
  what ffuf did for the whole life of its seam
- Use `_run_subprocess()` for process execution

## Adding a New Agent

1. Create `src/clinkz/agents/your_agent.py` inheriting from `BaseAgent`
2. Write a system prompt in `src/clinkz/agents/prompts/your_agent_system.md`
3. Implement the agent's ReAct loop logic (Observe → Reason → Act → Reflect)
4. Register the agent in the Orchestrator's lifecycle manager
5. Add tests in `tests/test_agents/test_your_agent.py`

Agents must never reference tools by name — use the Tool Resolver to find capabilities.

## Running Tests

```bash
# Keyless gate — deterministic, container-free (excludes every live/container suite)
pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration

# Container gate — live suites, require the target containers up (run serially)
pytest tests/test_integration/
pytest tests/test_skills_dvwa/ -m dvwa_smoke
pytest tests/test_skills_juiceshop/ -m juiceshop_smoke
pytest -m pipeline_smoke tests/test_pipeline_smoke/

# Specific module
pytest tests/test_tools/test_nmap.py -v

# With coverage
pytest --cov=clinkz tests/
```

## Code Style

- **Python 3.12+** with type hints on all functions
- **Pydantic v2** for all data models
- **async/await** for all tool execution and LLM calls
- **Google Python Style Guide** for docstrings and conventions
- Lint and format with [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff check src/     # Lint
ruff format src/    # Format
```

## Key Rules

- Never import an LLM SDK (openai, anthropic, etc.) outside `src/clinkz/llm/`
- Never hardcode API keys — use environment variables
- Never hardcode tool names in agent code — use the Tool Resolver
- All inter-agent communication goes through the Orchestrator
- All tool outputs must be parsed into Pydantic models
- Never add a flag that skips the authorization gate — an engagement without a
  named authorizing party is not an engagement
- Never put credentials on `EngagementScope`; it is `model_dump()`-ed into the
  state store. Passwords are `SecretStr`, and anything that reaches an artifact
  writer goes through `clinkz.engagement.secrets.redact` — **every** writer,
  including the report, which was once the only one that did not
- A new credential SHAPE goes in `clinkz.engagement.credential_shapes`, never in
  a second vocabulary — the redactor and the disclosure gate must not drift. The
  entropy heuristic stays in the gate alone: broadening the write path shreds
  evidence, and a gate that cries wolf gets ignored
- Never write a raw session token, `Authorization` value, or cookie value into an
  artifact. Record a fingerprint instead. `clinkz artifact-scan <id>` is the
  check, and it must pass before a bundle is shared. It covers the companion
  artifacts beside the bundle too — a guard's root is part of its verdict
- A `scripts/` driver writes through `scripts/_artifact_io.py`, never
  `path.write_text` directly: a driver tees the HTTP chokepoint and serialises
  raw exchanges itself, so the engine's writers never see them. A driver that
  hardcodes a lab password registers it, like every other intake route.
  `tests/test_engagement/test_driver_artifact_writes.py` enforces this from the
  source, so a new driver is covered without touching the test
- Never add a switch that disables the destructive-action refusal. It is the
  contract with the client, not a tunable
- A new destructive token goes in `clinkz.safety.destructive`, never in a second
  vocabulary — the navigation guard and the submission guard must not drift.
  Check any new token against `tests/test_safety/test_destructive_classifier.py`:
  reading our own payloads as application semantics silently reduces an
  authorized engagement to a crawler
- A new `_test_*` class needs an entry in `clinkz.models.vuln_classes` (label,
  capability, limitation, remediation) or the registry-sync test fails — an
  unregistered class is invisible in the report and ungated by authorization

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with tests
3. Ensure `ruff check src/ tests/` and the keyless gate (`pytest tests/ -q --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`) pass
4. Submit a PR with a clear description of what and why
