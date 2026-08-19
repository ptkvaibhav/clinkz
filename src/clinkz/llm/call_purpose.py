"""What an LLM call's answer BECOMES, and what a fallback there costs.

Routing v2 made Anthropic priority 1 for every call on every phase, and
:mod:`clinkz.llm.degradation` made a fallback a disqualifying event rather than
an invisible one. In ``baseline`` mode a fallback is refused outright. In
``client`` mode the run completes and the report is stamped — because a client
engagement should not die because a provider had a bad minute.

That answer is right for *most* calls and wrong for two kinds, and the
difference is what this module names.

A stamp discloses reduced coverage. It cannot disclose an absence
--------------------------------------------------------------------

``provider_degraded`` can honestly say "the exploit plan was written by a model
we did not ask for, so this run's coverage is not what a clean run's would
be". A reader can act on that: the *What was NOT tested* section is right
beside it, and the remedy is to re-run.

It cannot say the equivalent thing about a **suppression**. If a degraded
false-positive cross-check demotes a confirmed finding, that finding is not in
the report. There is no row to caveat, no section that names it, and nothing
in the deliverable distinguishes "the engine did not find it" from "a cheaper
model decided it was not real". The stamp describes the run; it cannot describe
what the run removed.

This is not hypothetical. Reading the traces that motivated routing v2: Gemini
served the exploit stage 12 times across 9 engagements — 6 exploit **plans**
and 6 **false-positive cross-checks**. The cross-check is the suppression path,
so the cheap tier had already been deciding which confirmed findings got
demoted, in reports that looked exactly like reports where it had not happened.

The same argument runs in the other direction for **emission**: a finding whose
evidence was shaped by a model nobody asked for is a claim in a client
deliverable with a provenance the deliverable does not carry.

So, in **every** mode:

* :attr:`LLMCallPurpose.PLANNING` — a fallback is permitted, recorded, and
  stamped. What it costs is coverage, and coverage is disclosable.
* :attr:`LLMCallPurpose.EMIT` and :attr:`LLMCallPurpose.SUPPRESS` — a fallback
  is **refused before the request leaves**. The call fails, its caller degrades
  the way it already degrades when a model is unreachable, and nothing is
  emitted or demoted on an answer from a provider the engagement did not choose.

The refusal raises :class:`~clinkz.llm.base.DecisionPathFallbackError`, an
ordinary :class:`~clinkz.llm.base.LLMError`, and that is deliberate. It is the
sibling of baseline mode's :class:`~clinkz.llm.base.ProviderPolicyError`, which
is a ``BaseException`` precisely so no broad handler can degrade past it —
because baseline mode wants the **run** to fail. This one wants only the
**call** to fail: the engagement should still complete, which is the whole point
of client mode. Making it uncatchable too would mean refusing one suppression
took the engagement down with it.

Failing the call is the conservative direction on both paths and that is not a
coincidence. A refused suppression leaves the finding standing, which is the
same direction the FP cross-check already fails in when the model is
unreachable (``_llm_analyze_results`` catches, logs, and returns an empty
analysis — no suspects, nothing demoted). A refused emission checkpoint leaves
the methodology on its deterministic build, which is where the invariant says
the verdict lives anyway.

Declaring a call site
---------------------

The purpose is a property of the **call site**, not of the agent role: the
exploit agent both writes the plan (planning) and runs the cross-check
(suppression) through the same client. So a call site declares it::

    with llm_call_purpose(LLMCallPurpose.SUPPRESS, site="exploit._llm_analyze_results"):
        response = await self.llm.generate_text(prompt)

Absent a declaration the purpose is :attr:`LLMCallPurpose.PLANNING` — the
permissive value — because that is what an un-migrated caller, a driver, a
replay or a direct methodology invocation is. An undeclared *agent* call site
is not left to that default by accident:
``tests/test_llm/test_call_purpose_classification.py`` reads the source of
``src/clinkz/agents/`` and ``src/clinkz/orchestrator/`` and fails on any LLM
call site missing from :data:`DECLARED_CALL_SITES` — the same shape as the
tool-wiring decision test, so "nobody classified it" is a red build rather than
a silent permission.

Being a :class:`~contextvars.ContextVar`, the declaration is per-task: the
concurrent phase runners each carry their own, and an ``await`` inside the
block cannot leak it to a neighbour.
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum

logger = logging.getLogger(__name__)


class LLMCallPurpose(StrEnum):
    """What this call's answer becomes in the deliverable."""

    #: The answer shapes what gets TESTED. A weaker model here costs recall,
    #: and reduced recall is disclosable: the stamp says the plan was degraded
    #: and the *What was NOT tested* section is right beside it.
    PLANNING = "planning"

    #: The answer shapes a finding that REACHES the report — its verdict, its
    #: evidence, its severity. A degraded answer here is a claim in a client
    #: deliverable produced by a provider the engagement did not choose.
    EMIT = "emit"

    #: The answer can REMOVE a finding from the report. Nothing downstream can
    #: disclose it: there is no row left to caveat.
    SUPPRESS = "suppress"

    @property
    def permits_fallback(self) -> bool:
        """Whether a provider other than the primary may serve this call."""
        return self is LLMCallPurpose.PLANNING


#: The declared purpose of every LLM call site under ``src/clinkz/agents/`` and
#: ``src/clinkz/orchestrator/``, keyed by ``module.function``. Every entry
#: carries the reason, because the reason is the part that has to survive
#: somebody moving the code.
#:
#: This table is the test's expectation, not the runtime's: the runtime reads
#: the context variable a call site actually set. Keeping them separate is
#: deliberate — a table the runtime consulted would make a call site that
#: forgot to declare *look* classified.
DECLARED_CALL_SITES: dict[str, tuple[LLMCallPurpose, str]] = {
    "exploit._llm_plan_exploits": (
        LLMCallPurpose.PLANNING,
        "Writes the exploit plan: which classes are tried against which endpoints. "
        "A degraded plan costs coverage, the class floor guarantees every applicable "
        "class a task regardless, and the truncation/ranking log plus the report's "
        "'What was NOT tested' section disclose what was reached for.",
    ),
    "exploit._llm_analyze_results": (
        LLMCallPurpose.SUPPRESS,
        "THE false-positive cross-check. Its false_positive_suspects list is the only "
        "LLM-authored input to _mark_false_positive_suspects, which DEMOTES confirmed "
        "findings out of the report. Six of these were served by a fallback provider "
        "across nine recorded engagements before anyone noticed.",
    ),
    "exploit._load_analysis_json": (
        LLMCallPurpose.SUPPRESS,
        "Re-prompts for valid JSON after the cross-check parse failed. It is the same "
        "suspect list arriving by a second route.",
    ),
    "exploit._llm_analyze": (
        LLMCallPurpose.EMIT,
        "The single funnel for all 24 methodology checkpoints — the reasoning that "
        "shapes a finding's verdict and evidence. Structurally it already cannot fall "
        "back: _build_methodology_llm pins override_chain=['anthropic'] so the chain "
        "has no tail. The declaration states the intent that pin encodes, and "
        "test_methodology_client_is_pinned asserts the pin so the two cannot drift.",
    ),
    "recon._llm_analyze_ports": (
        LLMCallPurpose.PLANNING,
        "Reads a port list into service hypotheses. An observation a later oracle "
        "re-derives from the live target, never a conclusion.",
    ),
    "recon._llm_extract_technologies": (
        LLMCallPurpose.PLANNING,
        "Reads fingerprint output into a technology list. Stack-conditioned branches "
        "are backed by a deterministic protocol artifact, never this list alone.",
    ),
    "recon._llm_synthesize": (
        LLMCallPurpose.PLANNING,
        "Writes the recon narrative handed to the next phase. Shapes what is looked "
        "at; emits nothing.",
    ),
    "scan._llm_plan_scan_strategy": (
        LLMCallPurpose.PLANNING,
        "Chooses which service-specific scan methods run. Coverage, disclosable.",
    ),
    "scan._llm_review_scan_results": (
        LLMCallPurpose.PLANNING,
        "Reads tool output for what to look at next. The deterministic coverage check "
        "runs regardless of what it says.",
    ),
    "scan._llm_check_coverage": (
        LLMCallPurpose.PLANNING,
        "Decides whether to expand via the crawl/fuzz fallback chains. More or less "
        "surface mapped — coverage again.",
    ),
    "research._llm_generate_search_queries": (
        LLMCallPurpose.PLANNING,
        "Search angles, logged and then superseded by one broad research call.",
    ),
    "research._llm_synthesize_techniques": (
        LLMCallPurpose.PLANNING,
        "The runbook is folded into the exploit plan, so it shapes what is TESTED. "
        "It is decision-bearing (CLAUDE_ONLY_ROLES marks it, and the register records "
        "it as such) but it emits nothing on its own: a technique it names still has "
        "to be confirmed by a P1-P7 oracle before any finding exists.",
    ),
    "research._llm_adapt_techniques": (
        LLMCallPurpose.PLANNING,
        "Pulls techniques out of the research text into the runbook. Same consequence "
        "as the runbook it feeds.",
    ),
    "runtime_research.research_technology": (
        LLMCallPurpose.PLANNING,
        "The research call itself. A CVE it names is a LEAD that must reach one of "
        "our own oracles before it can be a finding.",
    ),
    "orchestrator._handle_query": (
        LLMCallPurpose.PLANNING,
        "Routes a cross-phase query and answers it from engagement state. No agent "
        "has ever sent a QUERY message, so this is unreached in every recorded run; "
        "were it reached, it would decide which agent re-spins — coverage.",
    ),
    "base._react_loop": (
        LLMCallPurpose.PLANNING,
        "The BaseAgent ReAct step. No v2 phase agent runs free-form ReAct; the v2 "
        "agents are deterministic steps with named LLM checkpoints, each classified "
        "above.",
    ),
}


_CURRENT_PURPOSE: contextvars.ContextVar[LLMCallPurpose] = contextvars.ContextVar(
    "clinkz_llm_call_purpose", default=LLMCallPurpose.PLANNING
)

#: The site label that went with the current purpose, for the refusal message.
_CURRENT_SITE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "clinkz_llm_call_site", default=""
)


@contextmanager
def llm_call_purpose(purpose: LLMCallPurpose, *, site: str) -> Iterator[None]:
    """Declare what the calls made inside this block decide.

    Args:
        purpose: What the answer becomes.
        site: ``module.function`` of the declaring call site, quoted verbatim in
            the refusal so an operator reading the failure knows which call was
            refused rather than which agent.

    Yields:
        Nothing. Restores the previous declaration on exit, including when the
        body raises — a refusal is raised from inside the block.
    """
    purpose_token = _CURRENT_PURPOSE.set(purpose)
    site_token = _CURRENT_SITE.set(site)
    try:
        yield
    finally:
        _CURRENT_PURPOSE.reset(purpose_token)
        _CURRENT_SITE.reset(site_token)


def current_call_purpose() -> LLMCallPurpose:
    """What the innermost enclosing declaration said, or ``PLANNING``."""
    return _CURRENT_PURPOSE.get()


def current_call_site() -> str:
    """The innermost enclosing declaration's site label, or ``""``."""
    return _CURRENT_SITE.get()


__all__ = [
    "DECLARED_CALL_SITES",
    "LLMCallPurpose",
    "current_call_purpose",
    "current_call_site",
    "llm_call_purpose",
]
