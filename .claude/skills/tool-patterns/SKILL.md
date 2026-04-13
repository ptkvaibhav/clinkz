---
name: tool-patterns
description: "Load ToolBase wrapper patterns for creating new tool integrations"
---
Read src/clinkz/tools/base.py for the ToolBase ABC.
Read any existing wrapper (e.g., src/clinkz/tools/nmap.py) for the pattern.

Every wrapper needs:
- tool_name, binary_name, capabilities list, category
- build_command() -> CLI args
- parse_output() -> Pydantic model (never raw strings)
- Sample output fixture in tests/fixtures/
- Tests for parse_output and build_command
- Registration in TOOL_CHAINS in resolver.py

Run pytest, ruff check, ruff format after all changes.
