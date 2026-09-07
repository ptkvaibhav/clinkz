"""Two silences the deliverable used to keep, both of which read as good news.

Every entry in "What was NOT tested" answers a client asking what an absence of
findings means. These two were missing from it, and they are the two that most
look like a clean result:

* **A measurement that refused itself.** ``_test_brute_force``'s positive
  control sets ``INCONCLUSIVE`` when the attempts never reached the
  authentication handler. Emission requires ``auth_reached and not protected``,
  so an inconclusive series emits nothing — which is byte-identical, in the
  deliverable, to a login that was tested and was fine. Swept over the stored
  corpus: **136 of 369** recorded phase-3 verdicts are ``inconclusive``, across
  **75 engagements**, and the string "inconclusive" appears in **none of the
  4,169 stored reports**. Engagement ``01b8e683`` is the shape of it — the
  document carries "No Brute-Force Protection on /vulnerabilities/brute/" while
  the same run's ``/vulnerabilities/csrf/test_credentials.php`` login was
  inconclusive and dropped without a word.

* **A default-credential sweep the target stopped.** The stop is right and
  stays. What was wrong is that a truncated sweep and a completed one produced
  the same deliverable, in which the engagement reports no default credentials —
  a claim about every pair in the catalogue, made after some of them were never
  sent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from clinkz.agents.report import ReportAgent
from clinkz.models.finding import InconclusiveMeasurement
from clinkz.models.report import NotTestedCategory

_ENGAGEMENT = "00000000-0000-0000-0000-000000000000"

#: The rationale ``_deterministic_brute_force_analysis`` actually wrote, taken
#: from engagement ``01b8e683``'s trace rather than paraphrased. 75 of the 136
#: inconclusive verdicts in the corpus carry this exact shape.
_REAL_RATIONALE = (
    "8/8 attempts never reached the authentication handler (first at attempt 0: "
    "no response (transport failure or refused submission)). The absence of a lockout "
    "across requests that were never authenticated proves nothing — INCONCLUSIVE, not "
    "unprotected."
)


def _not_tested(**overrides: Any) -> list[Any]:
    agent = ReportAgent.__new__(ReportAgent)
    kwargs: dict[str, Any] = {
        "engagement_id": _ENGAGEMENT,
        "authorization": None,
        "scope_out": [],
        "safety": {},
        "authentication": {"authenticated": True, "multi_role": True},
        "finding_count": 0,
    }
    kwargs.update(overrides)
    return ReportAgent._build_not_tested(agent, **kwargs)


def _items(category: NotTestedCategory, **overrides: Any) -> list[Any]:
    return [item for item in _not_tested(**overrides) if item.category == category]


class TestAnInconclusiveMeasurementReachesTheClient:
    """The class ran, and may not speak. Both halves have to be in the document."""

    @staticmethod
    def _measurement() -> dict[str, Any]:
        return InconclusiveMeasurement(
            test_method="_test_brute_force",
            endpoint="http://172.20.0.2/vulnerabilities/csrf/test_credentials.php",
            reason=_REAL_RATIONALE,
            attempts=8,
        ).model_dump(mode="json")

    def test_it_is_listed_at_all(self) -> None:
        items = _items(
            NotTestedCategory.MEASUREMENT_INCONCLUSIVE,
            inconclusive_measurements=[self._measurement()],
        )
        assert len(items) == 1
        assert "test_credentials.php" in items[0].item
        assert "_test_brute_force" in items[0].item

    def test_the_reason_is_the_classifiers_own_words(self) -> None:
        """Not a re-description of it.

        Two vocabularies for one observation is how the looser reading ends up
        deciding — the rate-limit phantom in this very class came from exactly
        that, ``o.rate_limit_headers`` read raw beside ``classify_lockout``.
        """
        items = _items(
            NotTestedCategory.MEASUREMENT_INCONCLUSIVE,
            inconclusive_measurements=[self._measurement()],
        )
        assert _REAL_RATIONALE in items[0].reason

    def test_it_says_the_absence_is_of_a_measurement_not_of_a_flaw(self) -> None:
        items = _items(
            NotTestedCategory.MEASUREMENT_INCONCLUSIVE,
            inconclusive_measurements=[self._measurement()],
        )
        assert "the absence of a measurement, not the absence of a flaw" in items[0].reason
        # And how many requests went out, because "could not conclude" reads
        # very differently at 0 and at 8.
        assert "dispatched 8 request(s)" in items[0].reason

    def test_a_run_with_none_says_nothing(self) -> None:
        assert _items(NotTestedCategory.MEASUREMENT_INCONCLUSIVE) == []
        empty = _items(NotTestedCategory.MEASUREMENT_INCONCLUSIVE, inconclusive_measurements=[])
        assert empty == []

    def test_a_malformed_row_does_not_take_the_rest_with_it(self) -> None:
        items = _items(
            NotTestedCategory.MEASUREMENT_INCONCLUSIVE,
            inconclusive_measurements=["not a dict", self._measurement()],
        )
        assert len(items) == 1

    def test_the_category_renders_under_a_heading_of_its_own(self) -> None:
        """An orphan renders under its raw enum name, which is not a sentence.

        The section's own rule: dropping an entry because a renderer was not
        updated alongside the enum deletes a limitation from a deliverable.
        """
        from clinkz.models.report import PentestReport

        report = PentestReport(
            engagement_name="t",
            test_start=datetime.now(UTC),
            test_end=datetime.now(UTC),
            not_tested=_items(
                NotTestedCategory.MEASUREMENT_INCONCLUSIVE,
                inconclusive_measurements=[self._measurement()],
            ),
        )
        lines: list[str] = []
        ReportAgent._render_not_tested(lines, report)
        rendered = "\n".join(lines)
        assert "Tested, but the measurement could not support a conclusion" in rendered
        assert "[measurement_inconclusive]" not in rendered


class TestATruncatedSweepNamesWhatItNeverSent:
    """ "No default credentials" is a claim about pairs, not about the sweep."""

    @staticmethod
    def _stopped() -> dict[str, Any]:
        return {
            "login_url": "http://target/login.php",
            "stopped": True,
            "stopped_for_account": "admin",
            "stop_kind": "lockout",
            "stop_detail": "response body",
            "stop_marker": "account has been locked",
            "attempted": 3,
            "planned": 12,
            "untried": ["root (mysql)", "tomcat (tomcat)"],
        }

    def test_it_says_it_stopped_and_why(self) -> None:
        items = _items(NotTestedCategory.SWEEP_STOPPED, credential_sweep=self._stopped())
        assert len(items) == 1
        reason = items[0].reason
        assert "3 of 12 planned credential pairs" in reason
        assert "lockout" in reason
        assert "account has been locked" in reason
        assert "'admin'" in reason

    def test_it_names_the_pairs_it_never_tried(self) -> None:
        items = _items(NotTestedCategory.SWEEP_STOPPED, credential_sweep=self._stopped())
        assert "root (mysql)" in items[0].reason
        assert "tomcat (tomcat)" in items[0].reason
        assert "2 candidate pair(s) never sent" in items[0].item

    def test_it_never_names_a_password(self) -> None:
        """A pair that was never offered was never registered for redaction.

        ``register_secret`` runs in ``_attempt_login`` as a guess is offered, so
        the untried remainder is outside the one gate that catches secrets on
        the way into an artifact. The disclosure is account-and-technology only,
        and says so.
        """
        items = _items(NotTestedCategory.SWEEP_STOPPED, credential_sweep=self._stopped())
        assert "never registered for redaction" in items[0].reason

    def test_a_sweep_that_finished_leaves_no_claim_to_qualify(self) -> None:
        completed = {
            "login_url": "http://target/login.php",
            "stopped": False,
            "attempted": 12,
            "planned": 12,
            "untried": [],
        }
        assert _items(NotTestedCategory.SWEEP_STOPPED, credential_sweep=completed) == []

    def test_a_run_with_no_sweep_says_nothing(self) -> None:
        assert _items(NotTestedCategory.SWEEP_STOPPED) == []

    def test_the_category_renders_under_a_heading_of_its_own(self) -> None:
        from clinkz.models.report import PentestReport

        report = PentestReport(
            engagement_name="t",
            test_start=datetime.now(UTC),
            test_end=datetime.now(UTC),
            not_tested=_items(NotTestedCategory.SWEEP_STOPPED, credential_sweep=self._stopped()),
        )
        lines: list[str] = []
        ReportAgent._render_not_tested(lines, report)
        rendered = "\n".join(lines)
        assert "Stopped early on the target's own refusal" in rendered
        assert "[sweep_stopped]" not in rendered
