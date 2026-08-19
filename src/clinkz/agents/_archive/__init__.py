"""Agents that were built, wired, and never ran.

Nothing in this package is reachable from an engagement. It is not a staging
area for work in progress and it is not deprecated-but-supported: it is the
record of a component that existed in the architecture and produced nothing,
kept because deleting it would delete the evidence for why it is not there.

An archived module keeps its tests. A module nobody exercises rots quietly, and
a rotten module is worse than an absent one if it is ever reconsidered — the
next person would read code that no longer parses against its own models and
conclude the idea was wrong, when what was wrong was leaving it unbuilt.

What lives here, and why
------------------------

``critic`` — the CriticAgent. Registered in the lifecycle manager's
``_AGENT_CLASSES``, described in the README and CLAUDE.md as the component that
"validates findings before the report (CVSS, FP elimination, evidence, repro);
can reject back to Exploit", and **invoked in 0 of 2,774 recorded agent
steps**. The orchestrator's phase sequence is Recon → (Scan ‖ Research ‖
Exploit) → Report; no statement in it spins up a critic, and nothing sends it a
task. Being in ``_AGENT_CLASSES`` made it *constructible*, which is not the
same as being *called*, and the docs read the registration as a wiring.

The function it claimed is not missing from the engine — it moved, and it moved
somewhere better. False-positive elimination is
``_mark_false_positive_suspects`` plus ``_fp_deterministic_contradiction`` in
the Exploit Agent, where a demotion must name a deterministic contradiction in
the evidence rather than rest on a model's opinion; evidence and repro
sufficiency is ``verification_strength`` enforced at ``_persist_finding``; CVSS
is computed in the report. Every one of those is a deterministic gate on the
emitting path. An LLM reviewer sitting after them could only overrule them,
which is the direction the invariants forbid.

So the archive is the honest resting place: the idea was superseded by
something stricter, and the code is here to say so.
"""
