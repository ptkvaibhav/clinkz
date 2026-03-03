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

## 2. Register with the agent

In the relevant phase agent (e.g., `agents/recon.py`), add the tool to the tools list:

```python
from clinkz.tools.mytool import MyTool

# in ReconAgent.__init__ or factory function:
tools = [
    NmapTool(scope=scope, timeout=settings.tool_timeout),
    MyTool(scope=scope, timeout=settings.tool_timeout),
    # ...
]
```

## 3. Add to Docker image

Add the tool installation to `docker/Dockerfile.tools`:

```dockerfile
RUN apt-get install -y mytool
# or
RUN go install github.com/author/mytool@latest
```

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
- [ ] Registered with the appropriate phase agent
- [ ] Added to `docker/Dockerfile.tools`
- [ ] Fixture saved in `tests/fixtures/`
- [ ] Unit tests passing with `pytest tests/test_tools/test_mytool.py -v`
