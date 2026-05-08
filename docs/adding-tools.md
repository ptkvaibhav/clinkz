# Adding a New Tool

This guide explains how to add a new security tool wrapper to Clinkz.

## 1. Create the tool file

Create `src/clinkz/tools/<toolname>.py`:

```python
from __future__ import annotations
from typing import Any
from pydantic import BaseModel
from clinkz.tools.base import ToolBase, ToolOutput


class MyToolOutput(ToolOutput):
    """Structured output from MyTool."""
    results: list[str] = []


class MyTool(ToolBase):
    """One-sentence description of what MyTool does."""

    @property
    def name(self) -> str:
        return "mytool"

    @property
    def description(self) -> str:
        return "Description shown to the LLM when choosing tools."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target to scan.",
                    },
                },
                "required": ["target"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("target", "").strip()
        if not target:
            raise ValueError("'target' is required")
        self._check_scope(target)  # ALWAYS check scope
        return {"target": target}

    async def execute(self, args: dict[str, Any]) -> str:
        cmd = ["mytool", "--flag", args["target"]]
        stdout, stderr, _ = await self._run_subprocess(cmd)
        return stdout or stderr

    def parse_output(self, raw_output: str) -> MyToolOutput:
        # Parse raw_output into structured data
        results = [line for line in raw_output.splitlines() if line.strip()]
        return MyToolOutput(
            tool_name=self.name,
            success=bool(results),
            raw_output=raw_output,
            results=results,
        )
```

## 2. Register with the Tool Resolver

Add a `capabilities` class attribute and `category` to your tool class. The **Tool Resolver** (`src/clinkz/tools/resolver.py`) auto-discovers all `ToolBase` subclasses and indexes them by capability, so agents find tools dynamically — no manual registration needed:

```python
class MyTool(ToolBase):
    capabilities = ["my_capability", "related_capability"]
    category = "recon"  # or "scan", "exploit"
    # ...
```

Agents request tools by capability (e.g., `resolver.find_tool("my_capability")`), not by name. You do **not** need to import or register your tool in agent code.

## 3. Add to Docker image

Clinkz defaults to `TOOL_EXEC_MODE=docker`, so every tool wrapper's
`_run_subprocess()` is wrapped in `docker exec` against the `clinkz-tools`
container. New binaries must therefore be installed inside the image — add
them to `docker/Dockerfile.tools`:

```dockerfile
RUN apt-get install -y mytool
# or
RUN go install github.com/author/mytool@latest
```

If your tool ships a versioned CLI under a generic name that already exists
on `$PATH` (e.g. `httpx` collides with the Python package), add a fingerprint
to `src/clinkz/tools/binary_identity.py::BINARY_SIGNATURES` so the resolver
can refuse the impostor.

## 4. Create a fixture and write tests

Save a real tool output sample:

```
tests/fixtures/mytool_output.txt
```

Write a test in `tests/test_tools/test_mytool.py`:

```python
from pathlib import Path
from clinkz.tools.mytool import MyTool

FIXTURE = Path("tests/fixtures/mytool_output.txt").read_text()

def test_parse_output():
    tool = MyTool(scope=...)
    result = tool.parse_output(FIXTURE)
    assert result.success is True
    assert len(result.results) > 0
```

## Checklist

- [ ] Inherits from `ToolBase`
- [ ] `validate_input()` calls `self._check_scope(target)`
- [ ] Returns a `ToolOutput` subclass (never a raw string)
- [ ] Has `capabilities` and `category` class attributes for auto-discovery
- [ ] Added to `docker/Dockerfile.tools`
- [ ] Fixture saved in `tests/fixtures/`
- [ ] Unit tests passing with `pytest tests/test_tools/test_mytool.py -v`
