"""Keyless gate — the THIRD capability class (Log4Shell log-sink egress).

The thesis test: the class-generic discovery engine handles a class beyond
SSRF/file-read, with distinct machinery on all three axes, reducing to the built P6
primitive with zero new proof code. Against Vulhub ``log4j/CVE-2021-44228`` (Apache
Solr 8.11.0 + ``log4j-core`` 2.14.1), from real source, the engine surfaces a
``_test_log4shell`` Tier-A hypothesis at ``STATIC_HEURISTIC`` grade whose obligation
reduces to ``["P6"]`` (a JNDI/DNS callback bearing a fresh nonce).

Every Solr/log4j particular is learned from source (no literal in the engine —
grep-clean, like Solr/Flink):

  * the log sink — ``log().info("core create command {}", params)`` where ``params``
    is the request param bag (the general SLF4J/Log4j logging-call idiom),
  * the channel ``action`` — resolved from ``req.getParams().get(ACTION, …)`` via the
    ``ACTION = "action"`` constant (the two-arg ``.get(name, default)`` idiom),
  * the capability — armed only by a manifest-declared vulnerable ``log4j-core``
    (2.14.1 < 2.15), learned from ``pom.xml``.

The patched fixture (log4j-core 2.17.1, IDENTICAL source) proves the version gate:
no vulnerable token ⇒ the primitive is not active ⇒ NO hypothesis — N/A by
construction on a patched instance. No LLM, no container.
"""

from __future__ import annotations

import ast
from pathlib import Path

from clinkz.discovery import DiscoveryEngine
from clinkz.discovery.catalog import LOG4J_INTERPOLATION_JNDI, match_primitives
from clinkz.discovery.constants import LOG4J_VULNERABLE_TOKEN
from clinkz.discovery.models import PrimitiveClass, SoundnessGrade
from clinkz.discovery.source_ingest import JavaSourceIngestor

FIXTURE = Path(__file__).parent.parent / "fixtures" / "solr_log4shell"
PATCHED = Path(__file__).parent.parent / "fixtures" / "solr_log4shell_patched"
BASE_URL = "http://localhost:8983/solr/admin/cores"


# --- Source ingestion: the general log-sink + manifest idioms (learned) --------


def test_log_sink_idiom_surfaces_a_call_site() -> None:
    """A logging call whose argument is request-derived is a LOG_INTERPOLATION sink."""
    sm = JavaSourceIngestor().ingest_path(FIXTURE)
    log_sites = [c for c in sm.call_sites if c.primitive_class is PrimitiveClass.LOG_INTERPOLATION]
    assert log_sites, "no log-sink call site surfaced from real Solr source"
    # The whole-request bag sink (log().info(..., params)) uses the coarse marker.
    assert any(c.tainted_by == "*request*" for c in log_sites)


def test_action_channel_surfaced_via_two_arg_get() -> None:
    """Solr reads ``action`` via ``.get(ACTION, default)`` — the two-arg get idiom."""
    sm = JavaSourceIngestor().ingest_path(FIXTURE)
    assert any("action" in e.params for e in sm.entrypoints), "'action' channel not surfaced"


def test_manifest_gate_arms_only_the_vulnerable_version() -> None:
    """A vulnerable log4j-core (< 2.15) emits the token; a patched one does not."""
    vuln = JavaSourceIngestor().ingest_path(FIXTURE)
    patched = JavaSourceIngestor().ingest_path(PATCHED)
    assert LOG4J_VULNERABLE_TOKEN in vuln.technologies
    assert "2.14.1" in vuln.manifest_evidence
    assert LOG4J_VULNERABLE_TOKEN not in patched.technologies
    assert patched.manifest_evidence == ""


def test_manifest_gate_controls_primitive_activation() -> None:
    """The token gates ``match_primitives`` — patched source activates no primitive."""
    vuln = JavaSourceIngestor().ingest_path(FIXTURE)
    patched = JavaSourceIngestor().ingest_path(PATCHED)
    assert LOG4J_INTERPOLATION_JNDI in match_primitives(vuln, ["Java", "Solr"])
    assert LOG4J_INTERPOLATION_JNDI not in match_primitives(patched, ["Java", "Solr"])


# --- The engine chain: heuristic reachability + P6 reduction --------------------


def test_engine_surfaces_heuristic_log_sink_hypothesis() -> None:
    """The engine produces a heuristic log-sink hypothesis on the CVE's ``action``."""
    result = DiscoveryEngine().discover(str(FIXTURE), ["Java", "Solr"], BASE_URL)
    assert result.hypotheses, "no hypothesis from the vulnerable Log4Shell fixture"
    assert all(
        h.edge.soundness_grade is SoundnessGrade.STATIC_HEURISTIC for h in result.hypotheses
    ), "log-sink reachability must be heuristic (cross-function), not confirmed"
    params = {h.edge.channel_param for h in result.hypotheses}
    assert "action" in params, "the CVE's canonical 'action' channel was not surfaced"


def test_hypothesis_reduces_to_p6_with_no_carrier() -> None:
    """The obligation binds ``_test_log4shell`` / P6 and carries no carrier constraint."""
    result = DiscoveryEngine().discover(str(FIXTURE), ["Java", "Solr"], BASE_URL)
    action = next(h for h in result.hypotheses if h.edge.channel_param == "action")
    assert action.obligation.test_method == "_test_log4shell"
    assert action.obligation.confirmation_primitives == ["P6"]
    assert action.obligation.carrier_constraints == []  # string param value — no carrier


def test_lowered_task_targets_the_action_query_param() -> None:
    """The lowered ExploitTask hits ``/solr/admin/cores`` on the ``action`` query param."""
    result = DiscoveryEngine().discover(str(FIXTURE), ["Java", "Solr"], BASE_URL)
    tasks = [t for t in result.exploit_tasks() if "action" in t.endpoint_params]
    assert tasks, "no ExploitTask for the action channel"
    task = tasks[0]
    assert task.test_method == "_test_log4shell"
    assert task.endpoint_url == BASE_URL
    assert not task.carrier_constraints


def test_patched_is_na_by_construction() -> None:
    """Patched log4j-core (identical source) yields no active primitive, no hypothesis."""
    result = DiscoveryEngine().discover(str(PATCHED), ["Java", "Solr"], BASE_URL)
    assert result.active_primitives == []
    assert result.deltas == []
    assert result.hypotheses == []


def test_ranks_below_intra_function_confirmed() -> None:
    """A heuristic log-sink prior ranks strictly below a confirmed-taint hypothesis."""
    result = DiscoveryEngine().discover(str(FIXTURE), ["Java", "Solr"], BASE_URL)
    # 0.75 (no-guard EXPOSED) * 0.5 (heuristic) * 0.9 (bootstrapped) = 0.3375 < the
    # 0.6 an intra-function STATIC_CONFIRMED egress hypothesis scores.
    assert all(h.rank_score < 0.6 for h in result.hypotheses)


# --- Generality guard: no target literal leaked into the engine LOGIC ----------


def _non_docstring_string_literals(source: str) -> set[str]:
    """Every string CONSTANT in *source* that is not a module/class/function docstring.

    Comments and docstrings legitimately name the CVE / product / example param (the
    SSRF and file-read catalog entries do the same); a hardcoded target *param name*,
    by contrast, is a string literal in executable code — this surfaces exactly those.
    """
    tree = ast.parse(source)
    docstrings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    }


def test_target_param_and_version_not_hardcoded_in_engine_logic() -> None:
    """The CVE's ``action`` param / ``2.14.1`` version are learned, never hardcoded.

    Generality (§3.1): every Solr/log4j particular is resolved from source (the
    ``.get(ACTION)`` const, the ``pom.xml`` version) — none appears as a string
    literal in the discovery engine's executable code. Only the generic ``log4j-core``
    library name and the ``2.15`` threshold are code constants (the class is *about*
    that library, like EGRESS_FETCH is about ``openConnection``).
    """
    engine_dir = Path(__file__).parent.parent.parent / "src" / "clinkz" / "discovery"
    banned = {"action", "stream.url", "2.14.1", "CoreAdminHandler", "CoreAdminOperation"}
    for py in engine_dir.glob("*.py"):
        literals = _non_docstring_string_literals(py.read_text(encoding="utf-8"))
        leaked = banned & literals
        assert not leaked, f"{py.name} hardcodes target literal(s) in logic: {leaked}"
