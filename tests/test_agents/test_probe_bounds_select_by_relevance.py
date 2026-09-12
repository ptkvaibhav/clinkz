"""A bound that truncates a sorted collection selects by relevance, not spelling.

The measurement
---------------

``MAX_OPTIONS_PROBES = 40`` against cal.diy's 44 routes, selected as
``sorted(by_route)[:40]`` — lexicographic over the full URL. On a Next.js target
``_`` (0x5F) sorts before ``a`` (0x61), so every ``/_next/static/chunks/…``
bundle sorted ahead of every ``/api/…`` route:

* 32 of the 40 probes went to JS and CSS chunks, which can never declare a write
  verb;
* ``/api/book/event``, ``/api/logo`` and ``/api/trpc`` sat at sorted indices 33,
  34 and 35 — inside the budget **by six slots**;
* cal.com's login page alone references 31 chunks. A crawl that had found 41
  would have spent the whole budget on bundles and probed no application route
  at all, and ``learn_allowed_methods`` would have returned the same clean zero
  it returned here — "this target declares no write verb" — having asked nothing
  that could have said otherwise.

Why the domain is computed
--------------------------

Grepping for ``MAX_`` finds 79 bounded slices in this tree and almost all of
them are byte or character truncations of an evidence string, where spelling is
irrelevant. The bound that matters is the one where **the sort order decides
which members survive**, so the domain is exactly that: a bounded slice whose
operand is a ``sorted(...)`` call, or a local assigned from one, in the same
function. Nine sites, computed from the AST, and the classification below is the
hand-maintained half.

Both directions are asserted. A new sorted-then-sliced selection that nobody
classified fails the build, and a table entry whose site has gone fails it too —
a declaration that outlived its code is the same rot as code no declaration
covers.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"


class _Selection:
    """How a sorted-then-sliced site is classified."""

    #: The sort key is a relevance grade, so the survivors are the most relevant.
    RELEVANCE = "relevance"
    #: The sort key is a declared, meaningful ordering that is not spelling
    #: (a count, a privilege rank, a declared preference).
    DECLARED_KEY = "declared_key"
    #: The slice truncates a DISPLAY or a DIGEST, not a set of things to do.
    #: Spelling order is correct here, or at least costs nothing.
    PRESENTATION = "presentation"
    #: Selects by spelling and the members are work items — the defect's shape.
    #: Allowed only with a register entry saying why it is not fixed here.
    LEXICAL_REGISTERED = "lexical_registered"


#: ``file::function::line -> (classification, reason)``. Hand-declared, one entry
#: per site. A reason under six words fails on the same rule as every other
#: registry in this tree: "n/a" is not a classification.
DECLARED: dict[str, tuple[str, str]] = {
    "agents/_api_schema.py::_select_routes": (
        _Selection.RELEVANCE,
        "sorts on (crawl_visit_priority(route), route), so application and API routes are "
        "probed before static assets and the tie-break inside a grade is the route string "
        "rather than the crawl's emission order",
    ),
    "agents/scan.py::_enrich_endpoints_with_params": (
        _Selection.RELEVANCE,
        "the crawl enrichment budget orders by crawl_visit_priority with the normalised URL "
        "as the tie-break; this is the site the OPTIONS sweep was brought into line with",
    ),
    "agents/_business_logic.py::infer_intent": (
        _Selection.PRESENTATION,
        "truncates a field-name list inside an evidence SENTENCE, after the assertion has "
        "already been decided; which twelve names are quoted changes no verdict",
    ),
    "agents/_report_pdf.py::_scope_refusals": (
        _Selection.DECLARED_KEY,
        "orders refused hosts by refusal COUNT descending, so the fifteen rendered are the "
        "most-refused rather than the alphabetically first",
    ),
    "chaining/composition.py::credentials_in": (
        _Selection.DECLARED_KEY,
        "orders harvested credentials by (how, identity, secret) so the document's carried "
        "set is a deterministic function of what was harvested, not of dict order",
    ),
    "orchestrator/orchestrator.py::_find_login_url": (
        _Selection.DECLARED_KEY,
        "orders candidates by whether the path carries a login-shaped name — names ORDER the "
        "shape probing and never gate it, which is the login-discovery invariant itself",
    ),
    "observability/corpus_replay.py::build_baseline": (
        _Selection.PRESENTATION,
        "samples a committed regression baseline; a stable spelling order is what keeps the "
        "sample from churning on every re-record, and every member is replayed offline",
    ),
    "discovery/js_source_ingest.py::_read_files": (
        _Selection.LEXICAL_REGISTERED,
        "the gray-box source ingest caps at _MAX_FILES=2000 files chosen by filesystem path "
        "spelling, so a monorepo whose early directories are large could exhaust the budget "
        "before reaching the handlers. Registered as R10 rather than fixed here: source-path "
        "relevance is a grading function that does not exist yet, and guessing one starves "
        "the discoverer that the write-surface work is currently blocked on",
    ),
}


def _sorted_locals(fn: ast.AST) -> dict[str, ast.Call]:
    """Names in *fn* assigned from a ``sorted(...)`` call."""
    out: dict[str, ast.Call] = {}
    for node in ast.walk(fn):
        value = None
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            value, targets = node.value, list(node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value, targets = node.value, [node.target]
        if not isinstance(value, ast.Call):
            continue
        if not (isinstance(value.func, ast.Name) and value.func.id == "sorted"):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                out[target.id] = value
    return out


def _is_sorted_operand(node: ast.expr, sorted_locals: dict[str, ast.Call]) -> bool:
    """Whether slicing *node* slices something whose ORDER decided the members."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "sorted":
            return True
        # ``list(sorted(...))`` — one wrapper deep is all that occurs here, and a
        # deeper one should be declared rather than silently matched.
        if isinstance(node.func, ast.Name) and node.func.id == "list" and node.args:
            return _is_sorted_operand(node.args[0], sorted_locals)
        return False
    return isinstance(node, ast.Name) and node.id in sorted_locals


def _domain() -> dict[str, list[int]]:
    """``file::function -> line numbers`` of every sorted-then-sliced selection."""
    found: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover
            continue
        rel = path.relative_to(SRC).as_posix()
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            locals_ = _sorted_locals(fn)
            for node in ast.walk(fn):
                if not isinstance(node, ast.Subscript):
                    continue
                sl = node.slice
                if not isinstance(sl, ast.Slice) or sl.upper is None:
                    continue
                if not _is_sorted_operand(node.value, locals_):
                    continue
                found.setdefault(f"{rel}::{fn.name}", []).append(node.lineno)
    return found


def test_every_sorted_then_sliced_selection_is_classified() -> None:
    """A new bound that lets spelling decide coverage cannot land unnoticed."""
    domain = _domain()
    assert domain, "the AST reader found no sorted-then-sliced selection — it is broken"
    missing = sorted(set(domain) - set(DECLARED))
    assert not missing, (
        "these sites truncate a SORTED collection and are not classified in DECLARED: "
        f"{missing}. A bound whose sort order decides which members survive must say what "
        "it orders by — lexicographic selection over URLs sent 32 of 40 OPTIONS probes to "
        "JS chunks and would have sent all 40 on a slightly larger bundle set."
    )


def test_no_declaration_outlived_its_site() -> None:
    """The table is not larger than the code it classifies."""
    domain = _domain()
    stale = sorted(set(DECLARED) - set(domain))
    assert not stale, (
        f"these DECLARED entries no longer match any sorted-then-sliced site: {stale}. "
        "Remove the entry, or find where the selection moved to."
    )


def test_every_classification_is_in_the_vocabulary_with_a_real_reason() -> None:
    """An entry without a substantive reason is an unclassified site with a label."""
    vocabulary = {
        _Selection.RELEVANCE,
        _Selection.DECLARED_KEY,
        _Selection.PRESENTATION,
        _Selection.LEXICAL_REGISTERED,
    }
    for site, (classification, reason) in sorted(DECLARED.items()):
        assert classification in vocabulary, f"{site}: {classification!r} is not a classification"
        assert len(reason.split()) >= 6, f"{site}: the reason is too short to be one"


def test_a_work_item_selection_may_not_be_silently_lexical() -> None:
    """Only sites with a register entry may select work by spelling.

    The classification that needs watching. ``PRESENTATION`` covers a display
    truncation, ``DECLARED_KEY`` and ``RELEVANCE`` cover an ordering someone
    chose — but ``LEXICAL_REGISTERED`` is an acknowledged instance of the defect,
    so it has to point at where it is tracked. A silent one is what this file
    exists to prevent.
    """
    registered = {
        site
        for site, (classification, _reason) in DECLARED.items()
        if classification == _Selection.LEXICAL_REGISTERED
    }
    register = (
        Path(__file__).resolve().parents[2] / "docs" / "analysis" / "register.md"
    ).read_text(encoding="utf-8")
    for site in sorted(registered):
        module = site.split("::", 1)[0].rsplit("/", 1)[-1]
        assert module in register, (
            f"{site} is classified LEXICAL_REGISTERED — an acknowledged spelling-ordered "
            f"selection of work items — but docs/analysis/register.md does not mention "
            f"{module}. Either fix the ordering or register the defect; a label is not a fix."
        )
