# Contributing to Clinkz

## Development Setup

```bash
git clone https://github.com/ptkvaibhav/clinkz.git
cd clinkz
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env       # Add your API key
```

## Adding a New Tool Wrapper

See [docs/adding-tools.md](docs/adding-tools.md) for the full guide. In short:

1. Create `src/clinkz/tools/your_tool.py` inheriting from `ToolBase`
2. Implement `validate_input()`, `build_command()`, and `parse_output()`
3. Register capabilities in the `CAPABILITIES` class attribute
4. Add a test in `tests/test_tools/test_your_tool.py` using fixture data
5. Save sample output in `tests/fixtures/`

All tool wrappers must:
- Return Pydantic models (never raw strings)
- Call `_check_scope()` in `validate_input()` for scope enforcement
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

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with tests
3. Ensure `ruff check src/ tests/` and the keyless gate (`pytest tests/ -q --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`) pass
4. Submit a PR with a clear description of what and why
