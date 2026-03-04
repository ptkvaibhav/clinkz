"""Clinkz inter-agent communication layer.

All agent-to-agent communication is Orchestrator-mediated.
Agents send messages TO the Orchestrator; the Orchestrator routes them onward.
Direct agent-to-agent messaging is rejected at the bus level.

Typical usage::

    from clinkz.comms.message import AgentMessage
    from clinkz.comms.bus import MessageBus
    from clinkz.comms.protocol import ORCHESTRATOR, RECON
"""
