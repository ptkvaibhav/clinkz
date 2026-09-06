"""A cross-principal write is authorized by NAME, or it is not attempted.

Two independent gates, tested separately because they refuse for different
reasons and fail in different places:

* **The benchmark profile cannot permit the category.**
  ``CATEGORY_CROSS_PRINCIPAL_WRITE`` is never-overridable, beside session
  destruction and the security-posture toggle, and for the same argument: it
  damages the ENGAGEMENT and not only the target. B's own authorized read is the
  read oracle's attribution source, so a run that writes into B's collection
  corrupts the input of the class most likely to run after it. A throwaway target
  does not make a corrupted engagement worth having.
* **A wildcard authorization does not cover the class.** ``_test_write_crossing``
  is TERMINAL, and ``permits_all`` is how a client says "test everything" — not
  how they say "leave an object in another user's account that I have to go and
  find". The client names ``write_crossing`` explicitly or the class is withheld,
  and the report says so under its own "not tested" heading.

Both are observed REFUSING here. A rule nobody has watched refuse is a rule
nobody has tested.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.agents.exploit import TERMINAL_DISPATCH_CLASSES, ExploitAgent
from clinkz.models.engagement import (
    BENCHMARK_ACKNOWLEDGEMENT,
    AuthorizationRecord,
    BenchmarkProfile,
    never_overridable_categories,
    overridable_categories,
)
from clinkz.models.vuln_classes import for_method
from clinkz.safety.destructive import CATEGORY_CROSS_PRINCIPAL_WRITE


def _agent(permitted: list[str] | None) -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.exploit.write_crossing.auth")
    agent._permitted_techniques = permitted
    return agent


class TestTheBenchmarkProfileCannotPermitIt:
    def test_a_profile_naming_the_category_is_refused(self) -> None:
        with pytest.raises(ValueError, match="never be permitted") as raised:
            BenchmarkProfile(
                target_is_throwaway=True,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=[CATEGORY_CROSS_PRINCIPAL_WRITE],
                declared_by="Operator",
                declared_reference="LAB-1",
            )
        assert CATEGORY_CROSS_PRINCIPAL_WRITE in str(raised.value)

    def test_it_is_refused_even_beside_categories_a_profile_may_permit(self) -> None:
        """A valid profile does not carry an invalid category through with it."""
        with pytest.raises(ValueError, match="never be permitted"):
            BenchmarkProfile(
                target_is_throwaway=True,
                acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
                permitted_categories=["deletion", CATEGORY_CROSS_PRINCIPAL_WRITE],
                declared_by="Operator",
                declared_reference="LAB-1",
            )

    def test_it_sits_in_the_never_overridable_set_and_not_the_other_one(self) -> None:
        assert CATEGORY_CROSS_PRINCIPAL_WRITE in never_overridable_categories()
        assert CATEGORY_CROSS_PRINCIPAL_WRITE not in overridable_categories()

    def test_the_header_block_tells_the_client_it_stays_refused(self) -> None:
        """A refusal the deliverable does not state is a refusal nobody can check."""
        profile = BenchmarkProfile(
            target_is_throwaway=True,
            acknowledgement=BENCHMARK_ACKNOWLEDGEMENT,
            permitted_categories=["deletion"],
            declared_by="Operator",
            declared_reference="LAB-1",
        )
        rendered = "\n".join(profile.header_lines())
        assert CATEGORY_CROSS_PRINCIPAL_WRITE in rendered


class TestAWildcardAuthorizationDoesNotCoverIt:
    def test_the_class_is_withheld_under_a_wildcard(self) -> None:
        agent = _agent(["*"])
        assert AuthorizationRecord.model_construct(permitted_techniques=["*"]).permits_all
        assert agent._technique_permitted("_test_write_crossing") is False

    @pytest.mark.parametrize("wildcard", ["*", "all", "any"])
    def test_every_spelling_of_the_wildcard_withholds_it(self, wildcard: str) -> None:
        assert _agent([wildcard])._technique_permitted("_test_write_crossing") is False

    def test_naming_the_key_explicitly_permits_it(self) -> None:
        vuln_class = for_method("_test_write_crossing")
        assert vuln_class is not None
        assert vuln_class.key == "write_crossing"
        assert _agent([vuln_class.key])._technique_permitted("_test_write_crossing") is True

    def test_a_transient_class_is_still_covered_by_the_wildcard(self) -> None:
        """The rule must not widen: a wildcard still means everything else."""
        assert _agent(["*"])._technique_permitted("_test_sqli") is True

    def test_the_rule_is_keyed_on_the_terminal_table_not_on_this_class(self) -> None:
        """Computed domain, so a third terminal class is covered with no edit here."""
        agent = _agent(["*"])
        withheld = {
            method for method in TERMINAL_DISPATCH_CLASSES if not agent._technique_permitted(method)
        }
        assert withheld == set(TERMINAL_DISPATCH_CLASSES), sorted(
            set(TERMINAL_DISPATCH_CLASSES) - withheld
        )
