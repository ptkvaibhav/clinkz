"""Communication protocol constants for the Clinkz agent system.

Defines canonical agent names and standard message-flow patterns.
All agent names used in AgentMessage.from_agent / to_agent must come
from this module so spellings stay consistent across the codebase.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical agent names
# ---------------------------------------------------------------------------

ORCHESTRATOR = "orchestrator"
RECON = "recon"
SCAN = "scan"
EXPLOIT = "exploit"
REPORT = "report"
CRITIC = "critic"

#: All agents known to the system.  The MessageBus uses this set for
#: broadcast delivery and to validate routing decisions.
KNOWN_AGENTS: frozenset[str] = frozenset(
    {ORCHESTRATOR, RECON, SCAN, EXPLOIT, REPORT, CRITIC}
)

# ---------------------------------------------------------------------------
# Standard task/response content keys
# ---------------------------------------------------------------------------

#: Key used by task messages to convey the instruction text.
TASK_KEY = "task"

#: Key used by result messages to carry structured output data.
RESULT_KEY = "result"

#: Key used by query messages for the question being asked.
QUERY_KEY = "query"

#: Key used by response messages for the answer.
RESPONSE_KEY = "response"

#: Key used by status messages to convey agent state.
STATUS_KEY = "status"

#: Key used by error messages to describe the failure.
ERROR_KEY = "error"
