---
name: test-skill
description: "Test a specific exploit skill against DVWA to verify it produces findings"
---
The skill to test is: $ARGUMENTS

Find the corresponding deterministic _test_* method in the Exploit Agent
(src/clinkz/agents/exploit.py). Identify the matching DVWA endpoint for this
vulnerability class.

Run the skill in isolation against DVWA. Report:
- Did it find the vulnerability?
- What was the PoC (request + response)?
- Any errors or unexpected behavior?
- If it failed, analyze why and suggest a fix.
