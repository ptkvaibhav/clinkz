"""The deliverable states whether a model chose where the credential went.

"Did an LLM steer your login?" is not a question a client should have to infer
from a missing heading. So the Authentication section answers it on **every**
run — the same rule the crawl-budget disclosure follows (invariant 15): a bound
that decides coverage renders on a clean run too, because a disclosure that only
appears when the interesting thing happened teaches a reader to read its absence
as "nothing to see", which is exactly what it is not.

Three separated facts, because they are separate in the engine:

* WHICH layer seated the session — deterministic or adaptive;
* what the adaptive layer PROPOSED, and why;
* what it CONCLUDED, including when it concluded nothing.

A session the adaptive layer seated is still a session ``assert_authenticated``
proved, and the proof rendered above it is identical either way. That is the
point of separating them: the strength of the proof does not depend on which
layer found the destination, and a reader deciding how much to trust the
authenticated coverage is entitled to both facts rather than the stronger one
alone.
"""

from __future__ import annotations

from clinkz.agents.report import ReportAgent


def _episode(**overrides) -> dict:
    episode = {
        "role": "admin",
        "outcome": "abstained",
        "outcome_reason": (
            "2 credential POST(s) were dispatched and none produced session material"
        ),
        "llm_turns": 2,
        "proposals_refused": 1,
        "credential_posts_dispatched": 2,
        "reads_dispatched": 1,
        "attempts": [
            {
                "turn": 1,
                "proposal": {
                    "method": "POST",
                    "url": "http://t.test/session",
                    "rationale": "the form declares no action and the headers name the stack",
                },
                "taught": "HTTP 404; set no cookie",
            }
        ],
    }
    episode.update(overrides)
    return episode


class TestTheCleanRun:
    def test_a_run_the_layer_never_engaged_on_still_says_so(self) -> None:
        """The load-bearing case, because it is every ordinary engagement.

        Rendering nothing here would make the section's presence the signal, and
        a reader would have to know the section exists to read its absence.
        """
        lines = ReportAgent._render_adaptive_auth(
            {"adaptive_auth": [{"role": "admin", "outcome": "not_engaged"}]}
        )
        rendered = " ".join(lines)
        assert "not engaged" in rendered
        assert "no model was consulted" in rendered

    def test_a_bundle_that_predates_the_layer_renders_nothing(self) -> None:
        """An absent key is a bundle written before this existed, not a claim.

        The empty list and the missing key both mean "this record cannot answer
        the question", which is different from "the answer is no" — so neither
        is rendered as an answer.
        """
        assert ReportAgent._render_adaptive_auth({}) == []
        assert ReportAgent._render_adaptive_auth({"adaptive_auth": []}) == []


class TestAnEngagedRun:
    def test_it_names_the_layer_that_seated_the_session(self) -> None:
        lines = ReportAgent._render_adaptive_auth(
            {
                "adaptive_auth": [_episode(outcome="authenticated")],
                "seated_by": {"admin": "adaptive"},
            }
        )
        rendered = " ".join(lines)
        assert "could not seat a session for admin" in rendered
        assert "The model proposed; it did not decide." in rendered

    def test_it_states_the_gate_ran_before_anything_was_sent(self) -> None:
        """The client-facing statement of what bounded the proposals.

        Without it the section reads as "we let an AI pick where to send your
        password", which is both alarming and, as a description of what happened,
        wrong.
        """
        rendered = " ".join(
            ReportAgent._render_adaptive_auth(
                {
                    "adaptive_auth": [_episode(outcome="authenticated")],
                    "seated_by": {"admin": "adaptive"},
                }
            )
        )
        assert "engagement scope" in rendered
        assert "destructive-action classifier" in rendered
        assert "per-account credential budget" in rendered
        assert "anonymous-control assertion" in rendered

    def test_an_abstention_renders_the_proposals_and_the_reasoning(self) -> None:
        """An abstention is the most informative outcome this section has.

        "We reasoned this application authenticates at X and X answered 404" is
        something an operator can act on. A section that rendered abstentions as
        a single line saying "unsuccessful" would throw that away.
        """
        rendered = " ".join(ReportAgent._render_adaptive_auth({"adaptive_auth": [_episode()]}))
        assert "abstained" in rendered
        assert "http://t.test/session" in rendered
        assert "HTTP 404" in rendered
        assert "the form declares no action" in rendered

    def test_the_counts_distinguish_refused_from_dispatched(self) -> None:
        """A proposal the gate refused and a request the target answered are
        different events with different fixes, and a total collapses them."""
        rendered = " ".join(ReportAgent._render_adaptive_auth({"adaptive_auth": [_episode()]}))
        assert "2 credential POST(s)" in rendered
        assert "1 safe read(s)" in rendered
        assert "1 proposal(s) refused before dispatch" in rendered
