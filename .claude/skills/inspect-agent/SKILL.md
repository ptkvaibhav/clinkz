---
name: inspect-agent
description: "Deep-inspect a specific Clinkz agent — verify it follows v2 patterns, check for violations, review test coverage"
---
Apply phase-work rules unless overridden by this skill.

Inspect the specified agent for v2 compliance. The agent to inspect: $ARGUMENTS

1. Read the agent source file in src/clinkz/agents/
2. Check v2 pattern compliance:
   - Does it use deterministic steps with numbered methods?
   - Are LLM calls only at defined checkpoints (not driving the workflow)?
   - Does it use self._resolver for tool calls (not direct imports)?
   - Does it use self.llm for LLM calls (not direct SDK imports)?
   - Are all methods async?
   - Does it have structured logging at each step boundary?
   - Does it use Pydantic v2 models for all inputs/outputs?
3. Check for violations:
   - grep for direct tool imports (from clinkz.tools.<name> import)
   - grep for direct LLM SDK imports (import openai, import anthropic, import google)
   - grep for free-form loops that could iterate indefinitely
4. Check test coverage:
   - Find corresponding test file in tests/test_agents/
   - List all test methods
   - Run the tests: pytest <test_file> -v --tb=short
5. Report: compliant/non-compliant with specific violations listed
