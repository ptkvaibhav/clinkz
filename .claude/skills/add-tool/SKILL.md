---
name: add-tool
description: "Scaffold a new tool wrapper with ToolBase subclass, parser, tests, and resolver registration"
---
The tool to add is: $ARGUMENTS

1. Read src/clinkz/tools/base.py for the ToolBase interface.
2. Read an existing wrapper (e.g., src/clinkz/tools/nmap.py) as reference.
3. Research the tool's CLI interface, flags, and output format.
4. Create src/clinkz/tools/<tool_name>.py:
   - Subclass ToolBase
   - Set tool_name, binary_name, capabilities list, category
   - Implement build_command() with appropriate default flags
   - Implement parse_output() returning a Pydantic model
5. Create a sample output fixture in tests/fixtures/<tool_name>_sample.txt
6. Create tests/test_tools/test_<tool_name>.py:
   - Test parse_output against the fixture
   - Test build_command generates correct CLI args
7. Add the tool to TOOL_CHAINS in resolver.py under the appropriate capabilities.
8. Run pytest on the new tests. Run ruff check + format.
9. Commit: "feat: add <tool_name> tool wrapper"
