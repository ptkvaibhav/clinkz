"""AgentMessage — the standard message envelope for all inter-agent communication.

Every piece of information that flows between agents (tasks, results, queries,
status updates) is wrapped in an AgentMessage.  The MessageBus enforces that
all messages are Orchestrator-mediated — agents cannot message each other
directly.

Example::

    # Recon agent reports results back to the Orchestrator
    msg = AgentMessage.result(
        from_agent="recon",
        to_agent="orchestrator",
        engagement_id=eid,
        content={"hosts": [...]},
        parent_message_id=task_msg.id,
    )

    # Orchestrator tasks the Exploit agent
    msg = AgentMessage.task(
        from_agent="orchestrator",
        to_agent="exploit",
        engagement_id=eid,
        content={"task": "Test SQLi on http://target/login", "hosts": [...]},
    )
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MessageType(StrEnum):
    """Semantic type of an AgentMessage."""

    TASK = "task"
    RESULT = "result"
    QUERY = "query"
    RESPONSE = "response"
    STATUS = "status"
    ERROR = "error"


class AgentMessage(BaseModel):
    """Standard message envelope for all Clinkz inter-agent communication.

    Attributes:
        id: Unique message UUID, auto-generated.
        from_agent: Canonical name of the sending agent.
        to_agent: Canonical name of the recipient agent.
        message_type: Semantic type (task / result / query / response / status / error).
        content: Free-form payload dict (task details, findings, questions, etc.).
        engagement_id: UUID of the active engagement this message belongs to.
        parent_message_id: ID of the message this is a reply to, if any.
        timestamp: UTC timestamp of message creation, auto-generated.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_agent: str
    to_agent: str
    message_type: MessageType
    content: dict[str, Any]
    engagement_id: str
    parent_message_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # Factory helpers — one per MessageType
    # ------------------------------------------------------------------

    @classmethod
    def task(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create a TASK message instructing an agent to do work."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.TASK,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )

    @classmethod
    def result(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create a RESULT message carrying an agent's output."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.RESULT,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )

    @classmethod
    def query(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create a QUERY message asking for information or a decision."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.QUERY,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )

    @classmethod
    def response(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create a RESPONSE message answering a QUERY."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.RESPONSE,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )

    @classmethod
    def status(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create a STATUS message reporting agent state or progress."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.STATUS,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )

    @classmethod
    def error(
        cls,
        from_agent: str,
        to_agent: str,
        engagement_id: str,
        content: dict[str, Any],
        parent_message_id: str | None = None,
    ) -> AgentMessage:
        """Create an ERROR message reporting a failure."""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.ERROR,
            content=content,
            engagement_id=engagement_id,
            parent_message_id=parent_message_id,
        )
