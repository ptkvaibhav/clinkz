"""Unit tests for comms/protocol.py constants."""

from __future__ import annotations

from clinkz.comms.protocol import (
    CRITIC,
    ERROR_KEY,
    EXPLOIT,
    KNOWN_AGENTS,
    ORCHESTRATOR,
    QUERY_KEY,
    RECON,
    REPORT,
    RESPONSE_KEY,
    RESULT_KEY,
    SCAN,
    STATUS_KEY,
    TASK_KEY,
)


def test_agent_name_strings() -> None:
    assert ORCHESTRATOR == "orchestrator"
    assert RECON == "recon"
    assert SCAN == "scan"
    assert EXPLOIT == "exploit"
    assert REPORT == "report"
    assert CRITIC == "critic"


def test_known_agents_contains_all_six() -> None:
    assert len(KNOWN_AGENTS) == 6
    assert ORCHESTRATOR in KNOWN_AGENTS
    assert RECON in KNOWN_AGENTS
    assert SCAN in KNOWN_AGENTS
    assert EXPLOIT in KNOWN_AGENTS
    assert REPORT in KNOWN_AGENTS
    assert CRITIC in KNOWN_AGENTS


def test_known_agents_is_frozenset() -> None:
    assert isinstance(KNOWN_AGENTS, frozenset)


def test_known_agents_immutable() -> None:
    """frozenset operations must not raise but must not modify the original."""
    new_set = KNOWN_AGENTS | {"extra"}
    assert "extra" not in KNOWN_AGENTS
    assert len(KNOWN_AGENTS) == 6
    _ = new_set  # silence unused-variable warning


def test_content_key_constants() -> None:
    assert TASK_KEY == "task"
    assert RESULT_KEY == "result"
    assert QUERY_KEY == "query"
    assert RESPONSE_KEY == "response"
    assert STATUS_KEY == "status"
    assert ERROR_KEY == "error"


def test_content_keys_are_strings() -> None:
    for key in (TASK_KEY, RESULT_KEY, QUERY_KEY, RESPONSE_KEY, STATUS_KEY, ERROR_KEY):
        assert isinstance(key, str)
