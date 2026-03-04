"""Unit tests for AgentMessage and MessageType.

Covers model creation, auto-generated fields, factory helpers,
parent-message correlation, and Pydantic serialization round-trips.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from clinkz.comms.message import AgentMessage, MessageType


EID = "engagement-0001"


# ---------------------------------------------------------------------------
# MessageType enum
# ---------------------------------------------------------------------------


def test_message_type_values() -> None:
    assert MessageType.TASK == "task"
    assert MessageType.RESULT == "result"
    assert MessageType.QUERY == "query"
    assert MessageType.RESPONSE == "response"
    assert MessageType.STATUS == "status"
    assert MessageType.ERROR == "error"


def test_message_type_all_six_members() -> None:
    assert len(MessageType) == 6


# ---------------------------------------------------------------------------
# AgentMessage defaults
# ---------------------------------------------------------------------------


def test_auto_id_generated() -> None:
    m = AgentMessage(
        from_agent="orchestrator",
        to_agent="recon",
        message_type=MessageType.TASK,
        content={},
        engagement_id=EID,
    )
    assert m.id
    assert len(m.id) == 36  # UUID4 format


def test_two_messages_have_different_ids() -> None:
    m1 = AgentMessage(
        from_agent="orchestrator", to_agent="recon",
        message_type=MessageType.TASK, content={}, engagement_id=EID,
    )
    m2 = AgentMessage(
        from_agent="orchestrator", to_agent="recon",
        message_type=MessageType.TASK, content={}, engagement_id=EID,
    )
    assert m1.id != m2.id


def test_auto_timestamp_is_utc() -> None:
    before = datetime.now(UTC)
    m = AgentMessage(
        from_agent="orchestrator", to_agent="recon",
        message_type=MessageType.TASK, content={}, engagement_id=EID,
    )
    after = datetime.now(UTC)
    assert before <= m.timestamp <= after
    assert m.timestamp.tzinfo is not None


def test_parent_message_id_defaults_none() -> None:
    m = AgentMessage(
        from_agent="orchestrator", to_agent="recon",
        message_type=MessageType.TASK, content={}, engagement_id=EID,
    )
    assert m.parent_message_id is None


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "factory_name, expected_type",
    [
        ("task", MessageType.TASK),
        ("result", MessageType.RESULT),
        ("query", MessageType.QUERY),
        ("response", MessageType.RESPONSE),
        ("status", MessageType.STATUS),
        ("error", MessageType.ERROR),
    ],
)
def test_factory_sets_correct_message_type(factory_name: str, expected_type: MessageType) -> None:
    factory = getattr(AgentMessage, factory_name)
    m = factory(
        from_agent="orchestrator",
        to_agent="recon",
        engagement_id=EID,
        content={"key": "value"},
    )
    assert m.message_type == expected_type
    assert m.from_agent == "orchestrator"
    assert m.to_agent == "recon"
    assert m.engagement_id == EID
    assert m.content == {"key": "value"}


def test_factory_task_carries_content() -> None:
    m = AgentMessage.task(
        from_agent="orchestrator",
        to_agent="recon",
        engagement_id=EID,
        content={"task": "Scan 192.168.1.0/24 for open ports"},
    )
    assert m.content["task"] == "Scan 192.168.1.0/24 for open ports"


def test_factory_result_with_parent_correlation() -> None:
    task = AgentMessage.task(
        from_agent="orchestrator", to_agent="recon",
        engagement_id=EID, content={"task": "scan"},
    )
    result = AgentMessage.result(
        from_agent="recon", to_agent="orchestrator",
        engagement_id=EID,
        content={"hosts": ["192.168.1.1"]},
        parent_message_id=task.id,
    )
    assert result.parent_message_id == task.id
    assert result.message_type == MessageType.RESULT


def test_factory_error_content() -> None:
    m = AgentMessage.error(
        from_agent="recon", to_agent="orchestrator",
        engagement_id=EID,
        content={"error": "nmap not found"},
    )
    assert m.message_type == MessageType.ERROR
    assert "nmap not found" in m.content["error"]


# ---------------------------------------------------------------------------
# Serialisation round-trips
# ---------------------------------------------------------------------------


def test_model_dump_contains_all_fields() -> None:
    m = AgentMessage.task(
        from_agent="orchestrator", to_agent="recon",
        engagement_id=EID, content={"task": "go"},
    )
    d = m.model_dump()
    for field in ("id", "from_agent", "to_agent", "message_type",
                  "content", "engagement_id", "parent_message_id", "timestamp"):
        assert field in d


def test_model_dump_json_round_trip() -> None:
    m = AgentMessage.query(
        from_agent="exploit", to_agent="orchestrator",
        engagement_id=EID,
        content={"query": "What is the OS on 192.168.1.5?"},
    )
    json_str = m.model_dump_json()
    m2 = AgentMessage.model_validate_json(json_str)
    assert m2.id == m.id
    assert m2.message_type == m.message_type
    assert m2.content == m.content
    assert m2.timestamp == m.timestamp


def test_model_validate_from_dict() -> None:
    d = {
        "id": "00000000-0000-0000-0000-000000000001",
        "from_agent": "orchestrator",
        "to_agent": "scan",
        "message_type": "task",
        "content": {"task": "crawl http://target/"},
        "engagement_id": EID,
        "parent_message_id": None,
        "timestamp": "2025-03-04T09:00:00+00:00",
    }
    m = AgentMessage.model_validate(d)
    assert m.id == "00000000-0000-0000-0000-000000000001"
    assert m.message_type == MessageType.TASK
    assert m.to_agent == "scan"
