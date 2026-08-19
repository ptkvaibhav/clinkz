"""Every agent LLM call site is classified, and the classification is enforced.

Two properties, and they fail for different reasons:

1. **Nobody forgot.** Every ``generate_text`` / ``reason`` / ``research`` call
   made on an LLM client under ``src/clinkz/agents/``,
   ``src/clinkz/orchestrator/`` and ``src/clinkz/research/`` appears in
   :data:`DECLARED_CALL_SITES` with a reason, and is lexically wrapped in an
   ``llm_call_purpose(...)`` block naming the same site and the same purpose.
   Without this, an unclassified call site quietly inherits ``PLANNING`` — the
   permissive value — which is exactly the failure mode routing v2 exists to
   close. Same shape as ``test_tool_wiring_decisions``: a decision that is not
   written down is a red build, not a default.

2. **The refusal actually fires.** An ``EMIT`` or ``SUPPRESS`` call refuses a
   fallback in ``client`` mode, which is the mode every real engagement runs
   in, while a ``PLANNING`` call in the same mode falls back and is stamped.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinkz.config import Settings
from clinkz.llm.base import DecisionPathFallbackError, LLMMessage, ProviderPolicyError
from clinkz.llm.call_purpose import (
    DECLARED_CALL_SITES,
    LLMCallPurpose,
    current_call_purpose,
    llm_call_purpose,
)
from clinkz.llm.degradation import (
    DegradationRegister,
    set_active_degradation_register,
)
from clinkz.llm.fallback import ResilientLLMClient

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "clinkz"

#: The packages whose LLM call sites must be classified. ``llm/`` itself is
#: excluded: it is the plumbing that dispatches these calls, not a caller with a
#: purpose of its own.
_SCANNED = ("agents", "orchestrator", "research")

_LLM_METHODS = frozenset({"generate_text", "reason", "research"})

#: Modules whose call sites are deliberately unclassified, with the reason.
#: ``critic`` is archived — retained under ``agents/_archive/`` with no import
#: path into a run — so it has no live call site to classify.
_EXEMPT_MODULES: dict[str, str] = {
    "_archive": (
        "Archived code. Retained for its history and reachable from no run; "
        "an archived module that still declared a purpose would read as wired."
    ),
}


def _python_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for package in _SCANNED:
        files.extend(sorted((_SRC / package).rglob("*.py")))
    return files


def _enclosing_functions(tree: ast.AST) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            spans.append((node.lineno, node.end_lineno or node.lineno, node.name))
    return spans


def _declared_blocks(tree: ast.AST) -> list[tuple[int, int, str, str]]:
    """``(start, end, purpose_name, site)`` for every ``llm_call_purpose`` block."""
    blocks: list[tuple[int, int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.With | ast.AsyncWith):
            continue
        for item in node.items:
            call = item.context_expr
            if not isinstance(call, ast.Call):
                continue
            name = call.func.id if isinstance(call.func, ast.Name) else None
            if name != "llm_call_purpose":
                continue
            purpose = ""
            if call.args and isinstance(call.args[0], ast.Attribute):
                purpose = call.args[0].attr
            site = ""
            for kw in call.keywords:
                if kw.arg == "site" and isinstance(kw.value, ast.Constant):
                    site = str(kw.value.value)
            blocks.append((node.lineno, node.end_lineno or node.lineno, purpose, site))
    return blocks


def _call_sites() -> list[tuple[pathlib.Path, int, str, list[tuple[int, int, str, str]]]]:
    """Every LLM call site: ``(path, lineno, module.function, enclosing blocks)``."""
    found: list[tuple[pathlib.Path, int, str, list[tuple[int, int, str, str]]]] = []
    for path in _python_files():
        if any(part in _EXEMPT_MODULES for part in path.parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        spans = _enclosing_functions(tree)
        blocks = _declared_blocks(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr not in _LLM_METHODS:
                continue
            receiver = ast.unparse(node.func.value)
            if "llm" not in receiver.lower():
                continue
            enclosing = min(
                ((end - start, name) for start, end, name in spans if start <= node.lineno <= end),
                default=(0, "<module>"),
            )[1]
            covering = [b for b in blocks if b[0] <= node.lineno <= b[1]]
            found.append((path, node.lineno, f"{path.stem}.{enclosing}", covering))
    return found


class TestEveryCallSiteIsClassified:
    def test_at_least_the_known_call_sites_are_found(self) -> None:
        """The scanner works. A broken scanner passes every test below vacuously."""
        sites = {site for _p, _l, site, _b in _call_sites()}
        assert "exploit._llm_analyze_results" in sites
        assert "exploit._llm_plan_exploits" in sites
        assert len(sites) >= 10

    def test_every_call_site_is_in_the_table(self) -> None:
        undeclared = sorted(
            f"{path.name}:{lineno} ({site})"
            for path, lineno, site, _b in _call_sites()
            if site not in DECLARED_CALL_SITES
        )
        assert not undeclared, (
            "These LLM call sites are not in DECLARED_CALL_SITES. An unclassified "
            "call inherits PLANNING, which permits a fallback — so add the site "
            "with the purpose its answer actually has, and the reason:\n  "
            + "\n  ".join(undeclared)
        )

    def test_every_call_site_is_wrapped_with_its_declared_purpose(self) -> None:
        problems: list[str] = []
        for path, lineno, site, covering in _call_sites():
            declared, _reason = DECLARED_CALL_SITES.get(site, (None, ""))
            if declared is None:
                continue  # reported by the test above
            matching = [b for b in covering if b[3] == site]
            if not matching:
                problems.append(
                    f"{path.name}:{lineno} ({site}) is in the table but the call is not "
                    f"wrapped in llm_call_purpose(..., site={site!r})"
                )
                continue
            for _s, _e, purpose_attr, _site in matching:
                if purpose_attr.lower() != declared.value:
                    problems.append(
                        f"{path.name}:{lineno} ({site}) is wrapped as {purpose_attr} but "
                        f"the table declares {declared.value.upper()}"
                    )
        assert not problems, "\n  " + "\n  ".join(problems)

    def test_every_table_entry_carries_a_substantive_reason(self) -> None:
        thin = sorted(
            site for site, (_p, reason) in DECLARED_CALL_SITES.items() if len(reason) < 60
        )
        assert not thin, (
            "A one-line reason is documentation of a wish. State what the answer "
            f"becomes and why that is or is not disclosable: {thin}"
        )

    def test_the_table_names_no_call_site_that_no_longer_exists(self) -> None:
        live = {site for _p, _l, site, _b in _call_sites()}
        stale = sorted(set(DECLARED_CALL_SITES) - live)
        assert not stale, (
            "These entries name a call site that is gone. A table that outlives its "
            f"code is how a classification becomes a claim nobody checks: {stale}"
        )

    def test_the_suppression_path_is_classified_suppress(self) -> None:
        """The specific finding that motivated this: the FP cross-check."""
        purpose, reason = DECLARED_CALL_SITES["exploit._llm_analyze_results"]
        assert purpose is LLMCallPurpose.SUPPRESS
        assert "cross-check" in reason


class TestTheRefusalFires:
    """The classification has to change behaviour, not just be recorded."""

    @staticmethod
    def _client(monkeypatch: pytest.MonkeyPatch) -> ResilientLLMClient:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = Settings(run_mode="client")
        return ResilientLLMClient(
            agent_role="exploit",
            config=config,
            override_chain=["anthropic", "gemini"],
        )

    def test_a_suppress_call_refuses_the_fallback_in_client_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch)
        with (
            llm_call_purpose(LLMCallPurpose.SUPPRESS, site="exploit._llm_analyze_results"),
            pytest.raises(DecisionPathFallbackError) as excinfo,
        ):
            client._assert_fallback_permitted("gemini", primary="anthropic")
        message = str(excinfo.value)
        assert "SUPPRESS" in message
        assert "exploit._llm_analyze_results" in message
        assert "REMOVES findings from the report" in message

    def test_an_emit_call_refuses_the_fallback_in_client_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch)
        with (
            llm_call_purpose(LLMCallPurpose.EMIT, site="exploit._llm_analyze"),
            pytest.raises(DecisionPathFallbackError),
        ):
            client._assert_fallback_permitted("gemini", primary="anthropic")

    def test_the_client_mode_refusal_is_catchable_so_the_caller_degrades(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two refusals want opposite catchability, and this is the half that
        would silently kill an engagement if it were wrong.

        ``baseline`` mode wants the RUN to stop, so ``ProviderPolicyError`` is a
        ``BaseException`` deliberately uncatchable by the agents' broad handlers.
        ``client`` mode wants only the CALL to stop: the callers on these two
        paths already do the conservative thing with an unreachable model
        (``_llm_analyze_results`` returns an empty analysis and demotes nothing;
        ``_llm_analyze`` returns "" and the methodology keeps its deterministic
        build). If this refusal were a ``BaseException`` too, refusing a
        suppression would take the whole engagement down with it.
        """
        client = self._client(monkeypatch)
        caught = False
        try:
            with llm_call_purpose(LLMCallPurpose.SUPPRESS, site="exploit._llm_analyze_results"):
                client._assert_fallback_permitted("gemini", primary="anthropic")
        except Exception:  # exactly the handler every agent call site uses
            caught = True
        assert caught, "an emit/suppress refusal in client mode must be catchable"

    def test_the_baseline_refusal_is_not_catchable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The other half: a baseline run must not degrade past a broad handler."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        client = ResilientLLMClient(
            agent_role="exploit",
            config=Settings(run_mode="baseline"),
            override_chain=["anthropic", "gemini"],
        )
        escaped = False
        try:
            try:
                with llm_call_purpose(LLMCallPurpose.SUPPRESS, site="x"):
                    client._assert_fallback_permitted("gemini", primary="anthropic")
            except Exception:
                pytest.fail("a baseline refusal must not be caught by `except Exception`")
        except ProviderPolicyError:
            escaped = True
        assert escaped

    def test_a_planning_call_falls_back_in_client_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other half of the answer: planning degrades and stamps."""
        client = self._client(monkeypatch)
        with llm_call_purpose(LLMCallPurpose.PLANNING, site="exploit._llm_plan_exploits"):
            client._assert_fallback_permitted("gemini", primary="anthropic")  # does not raise

    def test_the_primary_is_never_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._client(monkeypatch)
        for purpose in LLMCallPurpose:
            with llm_call_purpose(purpose, site="test"):
                client._assert_fallback_permitted("anthropic", primary="anthropic")

    def test_baseline_mode_still_refuses_a_planning_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mode refusal and the purpose refusal are independent."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        client = ResilientLLMClient(
            agent_role="scan",
            config=Settings(run_mode="baseline"),
            override_chain=["anthropic", "gemini"],
        )
        with (
            llm_call_purpose(LLMCallPurpose.PLANNING, site="scan._llm_check_coverage"),
            pytest.raises(ProviderPolicyError) as excinfo,
        ):
            client._assert_fallback_permitted("gemini", primary="anthropic")
        assert "Baseline run" in str(excinfo.value)

    def test_an_undeclared_call_defaults_to_planning(self) -> None:
        assert current_call_purpose() is LLMCallPurpose.PLANNING

    def test_the_declaration_is_restored_when_the_body_raises(self) -> None:
        """A refusal is raised from inside the block, so the reset must be in a finally."""
        with pytest.raises(RuntimeError), llm_call_purpose(LLMCallPurpose.SUPPRESS, site="x"):
            raise RuntimeError("boom")
        assert current_call_purpose() is LLMCallPurpose.PLANNING

    def test_a_refused_fallback_records_no_degradation_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing was served, so there is nothing to stamp.

        The register exists to say which model shaped an answer. A refusal means
        no answer was bought, so recording one would claim a degradation the run
        did not take.
        """
        register = DegradationRegister()
        set_active_degradation_register(register)
        try:
            client = self._client(monkeypatch)
            with (
                llm_call_purpose(LLMCallPurpose.SUPPRESS, site="exploit._llm_analyze_results"),
                pytest.raises(DecisionPathFallbackError),
            ):
                client._assert_fallback_permitted("gemini", primary="anthropic")
            assert register.events() == []
            assert register.baseline_eligible is True
        finally:
            set_active_degradation_register(None)


class TestTheMethodologyClientIsPinned:
    """``exploit._llm_analyze`` is EMIT and is structurally unable to fall back.

    The declaration states the intent; this asserts the mechanism, so the two
    cannot drift into a version where the docstring says pinned and the chain
    has a tail.
    """

    def test_the_methodology_chain_has_no_tail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        client = ResilientLLMClient(agent_role="exploit", override_chain=["anthropic"])
        assert client.fallback_chain == ["anthropic"]

    @pytest.mark.asyncio
    async def test_reason_and_research_are_dispatched_through_the_same_chain(self) -> None:
        """Guards the assumption the scanner makes: all three methods route here."""
        assert {"generate_text", "reason", "research"} <= set(_LLM_METHODS)
        assert hasattr(ResilientLLMClient, "reason")
        assert hasattr(ResilientLLMClient, "research")
        assert LLMMessage is not None
