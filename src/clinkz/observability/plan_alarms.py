"""What the exploit plan dropped, carried into the deliverable.

Part D's rule, applied to the one bound that was never reported: an operator
must be able to read what the run was allowed to do, and what it did not do,
off the artifact — not off a log line that scrolled past twenty minutes ago.

The rate cap, the concurrency cap, the window, the token cap and the spend cap
are stated before anything is dispatched. The **plan cap** is the sixth bound,
and it is the one that most directly decides what gets tested: candidate
``(class, endpoint)`` pairs are ranked and everything past the cap is dropped.
Four recorded D1 baseline runs each truncated ~1,500 candidates to 150.

That truncation has never been silent — ``_log_plan_truncation`` names every
dropped class, the count, the first omitted endpoint, and separately any
**ranking inversion** — but it has only ever been *loud in the log and the
trace*. The report says nothing, and the report is the artifact that reaches
the client. So a deliverable could say "we tested the target" over a plan that
dropped the one endpoint the class could have confirmed on, and the reader had
no way to know: reading ``trace.jsonl`` is not something a client does.

Two facts, held apart, because they have different fixes
--------------------------------------------------------

* **Truncation** — the cap removed a class's tail. The budget working as
  designed. The fix, if the operator wants those tasks, is a larger cap.
* **Ranking inversion** — a task was dropped from an endpoint where that
  class's *own* attack surface was observed, while lower-relevance tasks
  survived. That is the ordering failing, not the budget, and a larger cap does
  not fix it. It is the defect that cost D1 its weak-session and SQLi findings.

An inversion reads nothing like tail truncation and must not hide inside it —
the same reason the contribution ledger keeps ``DEAD_SEAM`` apart from
``SILENT``. So the summary reports them as separate numbers and the Markdown
renders the inversions with the grade each task was dropped at.

Rendered on a clean run too. "No class was truncated" is a claim; an absent
section is not — a run that fit inside its cap and a run whose truncation
nobody recorded would otherwise produce identical artifacts.

Absent by default, like the governor, the ledger and the scope-refusal log: a
directly invoked methodology, a replay or a driver installs no register, every
hook no-ops, and the black-box floor is byte-identical.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field, fields
from typing import Any

logger = logging.getLogger(__name__)

#: Most dropped endpoints to retain per class. The COUNT stays exact past this,
#: for the same reason the scope-refusal log keeps its tally exact: a truncated
#: record of a truncation is the failure this module exists to prevent.
MAX_RETAINED_PER_CLASS = 20


@dataclass(frozen=True)
class PlanTruncation:
    """One planning pass's cap outcome.

    Attributes:
        stage: Which pass reported ("deterministic" / "union").
        cap: The task cap in force **for this pass** — the configured cap minus
            whatever a reservation held back. Reported as the number that
            actually decided the truncation, because a reader reconciling a
            dropped tail against ``exploit_max_plan_tasks`` would otherwise be
            reading a bound that was never applied.
        reserved: Slots the configured cap held back from this pass for another
            plan source, and ``reserved_for`` names which. Rendered beside the
            cap rather than folded into it: "the cap dropped your tail" and "a
            reservation shrank the cap first" have different fixes, exactly like
            truncation and ranking inversion, and a single number cannot say
            which happened. ``0`` on every run with no reservation, which is
            what keeps the clean rendering unchanged.
        reserved_for: The plan source the reservation was made for, or ``""``.
        kept: How many tasks survived it.
        kept_by_class: Per class, HOW MANY of its tasks survived. The total
            above cannot answer the question the class-coverage account asks —
            a class that produced no finding either had every candidate dropped
            (the cap's fault, fixed by a bigger cap) or had tasks in the plan
            and never ran them (the dispatcher's fault, an entirely different
            bug). ``kept`` and ``dropped_by_class`` together leave those two
            indistinguishable, which is the same shape as every other total
            this codebase has had to break down into its parts.
        dropped_total: How many candidates the cap removed.
        dropped_by_class: Per class, the endpoints dropped (bounded by
            :data:`MAX_RETAINED_PER_CLASS`; the count above is exact).
        ranking_inversions: Dropped tasks that sat on an endpoint carrying
            their own class's observed surface. Each is
            ``{"test_method", "endpoint_url", "grade"}``.
    """

    stage: str
    cap: int
    kept: int
    dropped_total: int
    reserved: int = 0
    reserved_for: str = ""
    kept_by_class: dict[str, int] = field(default_factory=dict)
    dropped_by_class: dict[str, list[str]] = field(default_factory=dict)
    ranking_inversions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        """Whether the cap removed anything at all."""
        return self.dropped_total > 0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "stage": self.stage,
            "cap": self.cap,
            "reserved": self.reserved,
            "reserved_for": self.reserved_for,
            "configured_cap": self.cap + self.reserved,
            "kept": self.kept,
            "kept_by_class": dict(sorted(self.kept_by_class.items())),
            "dropped_total": self.dropped_total,
            "classes_truncated": sorted(self.dropped_by_class),
            "dropped_by_class": {
                name: endpoints[:MAX_RETAINED_PER_CLASS]
                for name, endpoints in sorted(self.dropped_by_class.items())
            },
            "ranking_inversion_count": len(self.ranking_inversions),
            "ranking_inversions": self.ranking_inversions[:MAX_RETAINED_PER_CLASS],
        }


@dataclass(frozen=True)
class CrawlBudgetTruncation:
    """What the crawl's enrichment budget never opened.

    The same rule as :class:`PlanTruncation`, one layer up the pipeline: **a
    bound that decides coverage is reported in the DELIVERABLE, not just the
    log.** The exploit plan cap decides which discovered endpoints get tested;
    this budget decides which discovered URLs ever BECOME endpoints, so it sits
    strictly upstream of everything the plan cap can see.

    On the first non-benchmark run 3,070 crawled URLs became 212 candidates and
    the budget opened 80 — **132 (62%) were never enqueued** — and that was
    visible only at INFO in the run log. Nothing in ``report.json`` said it, so a
    reader had no way to know that most of the discovered surface was never
    looked at.

    The refusal log inherits the same blind spot, which is worth stating: it
    records requests that were REFUSED, and this budget decides which candidates
    ever become requests at all. "75 refusals across 3 hosts" therefore
    describes the top-80 slice of the out-of-scope surface, not the surface.

    Attributes:
        budget: The visit budget in force.
        candidates: Distinct candidates after dedup and the safety filter.
        opened: How many were actually opened.
        duplicates_collapsed: Spellings that collapsed into an existing
            candidate — escape artifacts (``%5C``) and trailing slashes.
            Recorded because it is budget RECLAIMED: on the portfolio run one
            link arrived three times and consumed three of the eighty visits.
        first_omitted: The highest-priority URL the budget did not reach. Lets a
            reader check the ordering rather than take it on trust.
        opened_by_host: Per host, how many were opened.
        dropped_by_host: Per host, how many were not. Kept apart from the total
            for the reason every other total here is broken down: "this host was
            covered thinly" and "this host was never opened at all" are
            different facts, and a sum cannot tell them apart.
    """

    budget: int
    candidates: int
    opened: int
    duplicates_collapsed: int = 0
    first_omitted: str = ""
    opened_by_host: dict[str, int] = field(default_factory=dict)
    dropped_by_host: dict[str, int] = field(default_factory=dict)

    @property
    def dropped_total(self) -> int:
        """How many candidates the budget never opened."""
        return max(0, self.candidates - self.opened)

    @property
    def truncated(self) -> bool:
        """Whether the budget dropped anything at all."""
        return self.dropped_total > 0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "budget": self.budget,
            "candidates": self.candidates,
            "opened": self.opened,
            "dropped_total": self.dropped_total,
            "duplicates_collapsed": self.duplicates_collapsed,
            "first_omitted": self.first_omitted,
            "opened_by_host": dict(sorted(self.opened_by_host.items())),
            "dropped_by_host": dict(sorted(self.dropped_by_host.items())),
            "hosts_never_opened": sorted(
                host for host in self.dropped_by_host if not self.opened_by_host.get(host)
            ),
        }


@dataclass(frozen=True)
class ProbeBudgetTruncation:
    """What a surface-mapping sweep's probe budget never asked about.

    The third layer of the same rule, and the one where the bound decided what
    could be DISCOVERED rather than what could be tested. The plan cap decides
    which discovered endpoints get a methodology; the crawl budget decides which
    discovered URLs become endpoints; this budget decides which routes are asked
    what METHODS they accept — so it sits upstream of the write surface existing
    at all.

    Measured on cal.diy (``e4814440``): 44 routes, ``MAX_OPTIONS_PROBES = 40``,
    and the selection was ``sorted(by_route)[:40]`` — lexicographic over the full
    URL. On a Next.js target ``_`` (0x5F) sorts before ``a`` (0x61), so every
    ``/_next/static/chunks/…`` bundle sorted ahead of every ``/api/…`` route.
    **32 of the 40 probes went to JS and CSS chunks**, which can never declare a
    write verb, and the three application routes sat at sorted indices 33, 34 and
    35 — inside the budget by six slots. The login page alone references 31
    chunks; a crawl that had found 41 would have spent the entire budget on
    bundles and probed **no application route at all**, and the sweep would have
    returned a clean zero meaning nothing.

    Two facts, held apart, exactly as :class:`PlanTruncation` holds truncation
    apart from a ranking inversion:

    * **the budget was too small** — the tail was dropped, and a larger budget
      would probe it. Benign when the tail is static assets.
    * **the ordering was wrong** — a route that could have answered the sweep's
      question was dropped while one that structurally cannot was probed. A
      larger budget does not fix that, and it is what happened here.

    So the dropped routes are broken down by RELEVANCE GRADE
    (:func:`~clinkz.agents._url_shape.crawl_visit_priority`), and a drop at a
    grade the sweep exists to reach is recorded separately from a dropped static
    asset.

    Attributes:
        sweep: Which sweep reported — ``"options_methods"`` or
            ``"representation_schema"``. Named rather than merged: they probe
            different things with different budgets and a shared total would hide
            which one was starved.
        budget: The probe budget in force.
        candidates: Distinct routes eligible for this sweep.
        probed: How many were actually probed.
        first_omitted: The highest-priority route the budget did not reach, so a
            reader can check the ordering rather than take it on trust.
        probed_by_grade: Per relevance grade, how many were probed.
        dropped_by_grade: Per relevance grade, how many were not.
        relevant_dropped: Routes dropped at a grade this sweep exists to reach
            (an application or API route, not a static asset). Bounded by
            :data:`MAX_RETAINED_PER_CLASS`; the count above stays exact.
    """

    sweep: str
    budget: int
    candidates: int
    probed: int
    first_omitted: str = ""
    probed_by_grade: dict[int, int] = field(default_factory=dict)
    dropped_by_grade: dict[int, int] = field(default_factory=dict)
    relevant_dropped: list[str] = field(default_factory=list)

    @property
    def dropped_total(self) -> int:
        """How many eligible routes the budget never probed."""
        return max(0, self.candidates - self.probed)

    @property
    def truncated(self) -> bool:
        """Whether the budget dropped anything at all."""
        return self.dropped_total > 0

    @property
    def ordering_failure(self) -> bool:
        """Whether a route the sweep exists to reach was dropped.

        Separate from :attr:`truncated` and reported separately, because the two
        have different fixes. A dropped ``favicon.ico`` costs the sweep nothing;
        a dropped ``/api/trpc`` is the sweep failing at its own purpose while
        reporting a clean result.
        """
        return bool(self.relevant_dropped)

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "sweep": self.sweep,
            "budget": self.budget,
            "candidates": self.candidates,
            "probed": self.probed,
            "dropped_total": self.dropped_total,
            "first_omitted": self.first_omitted,
            # Stringified keys: this dict is serialised to JSON, where an int key
            # becomes a string anyway — doing it here means the built dict and the
            # round-tripped one compare equal instead of drifting at the seam.
            "probed_by_grade": {str(k): v for k, v in sorted(self.probed_by_grade.items())},
            "dropped_by_grade": {str(k): v for k, v in sorted(self.dropped_by_grade.items())},
            "ordering_failure": self.ordering_failure,
            "relevant_dropped_count": len(self.relevant_dropped),
            "relevant_dropped": self.relevant_dropped[:MAX_RETAINED_PER_CLASS],
        }


@dataclass(frozen=True)
class MethodProvenance:
    """How the engine knows each discovered endpoint's HTTP method.

    The fourth layer of the same rule, and the one furthest upstream of every
    bound. (:class:`UnreachableCallSites` sits further upstream still, but it is
    not a bound — it is about calls that never became endpoints to be bounded.)
    The
    plan cap decides which endpoints get a methodology; the crawl budget decides
    which URLs become endpoints; the probe budget decides which routes are asked
    what verbs they accept. **This one says whether the verb an endpoint carries
    was READ at all** — and it sits upstream of the others because a verb is what
    decides whether an endpoint has a write-family class to be capped out of.

    Why it is a disclosure and not just a field. Seven Tier-1 classes are gated
    on ``has_form or method in (POST, PUT, PATCH)``, and
    ``_applicable_methods_for_endpoint`` is the ONLY producer of their
    deterministic buckets. So an endpoint recorded ``GET`` is not a
    lower-priority candidate for those classes — it is absent from them
    entirely, not truncated, not out-ranked, not abstaining. A ``GET`` the engine
    READ and a ``GET`` standing in for a verb it could not read produce the same
    empty bucket and the same clean report, and nothing distinguished them.

    Measured live on cal.com: of 12 bundles read, the miner emitted 2 call sites
    (both ``GET``) while 7 call sites in those same bundles carried a config
    argument it cannot see into. Every one of the seven was planned as a ``GET``.

    Attributes:
        named: Endpoints whose verb the source or the protocol stated — a
            ``.post(`` token, ``{method: "PUT"}``, an OpenAPI operation, an
            ``Allow`` header, an HTML ``<form method>``.
        platform_default: Endpoints where no verb was named and none could have
            been, so the idiom's own default IS the verb: a bare ``fetch(url)``,
            a crawled link. A reading, not a guess.
        unread: Endpoints whose verb the engine could not read. ``GET`` is
            standing in for an absence, and any write surface on them is
            undiscovered rather than absent.
        unread_examples: A bounded sample, so a reader can check the claim rather
            than take the count on trust.
    """

    named: int = 0
    platform_default: int = 0
    unread: int = 0
    unread_examples: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Endpoints accounted for. The denominator, measured, never assumed."""
        return self.named + self.platform_default + self.unread

    @property
    def any_unread(self) -> bool:
        """Whether any endpoint's verb went unread."""
        return self.unread > 0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "total": self.total,
            "named": self.named,
            "platform_default": self.platform_default,
            "unread": self.unread,
            "unread_examples": self.unread_examples[:MAX_RETAINED_PER_CLASS],
        }


@dataclass(frozen=True)
class BundleFetchTruncation:
    """Chunk URLs the bundle walk discovered and never fetched.

    The sixth layer, and the one furthest upstream: every other disclosure here
    is about surface the engine had already READ. This one is about bytes it
    never opened, so it bounds all five of them at once — a call site in an
    unfetched chunk is not unresolvable, not unprobed and not unranked. It is
    absent, and absent looks exactly like a target that has no write surface.

    On cal.com both were true at once, which is why nothing surfaced it. The
    walk queued **53** chunk URLs, ``_MAX_BUNDLES`` fetched **12**, and the
    twelve it read named one write — so the run reported a write surface of one
    route, and a reader had no way to tell that from "this application declares
    one write". The 41 it never opened were not mentioned anywhere: not in the
    report, not in the trace.

    ``crawl_visit_priority`` grades every ``.js`` chunk ``2`` and cannot separate
    them, so this bound has no ordering signal to fix — measured in
    ``docs/analysis/register.md`` R17, where eight candidate signals were ranked
    over every chunk on two targets. The queue order is already at 93–95% of the
    read-everything ceiling and the best signal needs the body the bound exists
    to avoid fetching. So the fix is not a re-sort and not a larger cap: it is
    saying what was not read.

    Attributes:
        budget: The fetch bound in force (``_MAX_BUNDLES``).
        discovered: Distinct same-origin chunk URLs the walk queued.
        fetched: How many were actually retrieved and mined.
        first_omitted: The first queued URL the bound did not reach, so a reader
            can check the ordering rather than take it on trust.
        omitted_examples: Bounded samples of what went unread. Chunk URLs, which
            the target authored — they render through the same neutralisation as
            every other target string.
    """

    budget: int
    discovered: int
    fetched: int
    first_omitted: str = ""
    omitted_examples: list[str] = field(default_factory=list)

    @property
    def unread(self) -> int:
        """How many discovered chunks the bound never opened."""
        return max(0, self.discovered - self.fetched)

    @property
    def truncated(self) -> bool:
        """Whether the bound left anything unread."""
        return self.unread > 0

    @property
    def coverage(self) -> float:
        """Fraction of discovered chunks actually read, 0.0 when none were."""
        return (self.fetched / self.discovered) if self.discovered else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "budget": self.budget,
            "discovered": self.discovered,
            "fetched": self.fetched,
            "unread": self.unread,
            "truncated": self.truncated,
            "first_omitted": self.first_omitted,
            "omitted_examples": self.omitted_examples[:MAX_RETAINED_PER_CLASS],
        }


@dataclass(frozen=True)
class UnreachableCallSites:
    """HTTP calls the bundle declares that the miner could not turn into a route.

    The fifth layer, and the only one that is not about a bound. Every other
    disclosure here answers "how much of what we found did we get to" —
    :class:`MethodProvenance` answers "was this endpoint's verb read", the cap
    classes answer "did the budget reach it". This one answers a question none
    of them can: **how much surface did we SEE and fail to address at all.**

    An endpoint that never resolved is not an endpoint, so it appears in no
    count, carries no ``method_evidence``, and lands in no bucket. A bundle of
    nothing but ``fetch(e,n)`` and one of an application that makes no HTTP
    calls produce byte-identical output, and the first is a reach failure while
    the second is a fact about the target.

    Measured live. Juice Shop's Angular idiom resolves 88 of 89 call sites, and
    the one it does not is socket.io's polling transport — a genuine same-origin
    ``POST`` whose address is ``this.uri()`` one frame up. cal.com resolves 2 and
    leaves 7, one of which is the Next.js Server Action dispatcher:
    ``fetch(e.canonicalUrl, {method:"POST", ...})``. Every cal.com write goes
    through it, and its URL is the page's own address chosen at runtime, so no
    amount of reading the bundle recovers a route from it.

    ``naming_a_write`` is the number worth surfacing first: a call site we can
    see declares a state-changing verb, and cannot address, is directly the
    write surface the seven Tier-1 classes never receive.

    Attributes:
        seen: HTTP-certain call sites examined — by the callee's own name
            (``fetch``, ``axios``, XHR) or by a config argument's shape. A
            ``Map``'s ``.get(k)`` is not one and is never counted.
        resolved: Of those, the ones that produced a route.
        unresolvable: Of those, the ones that did not.
        naming_a_write: Unresolvable calls that named POST/PUT/PATCH/DELETE.
        by_reason: ``CallSiteRejection`` value → count.
        examples: Bounded samples, so the count can be checked rather than
            trusted. Each is the call as written, never a response body.
    """

    seen: int = 0
    resolved: int = 0
    unresolvable: int = 0
    naming_a_write: int = 0
    by_reason: dict[str, int] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)

    @property
    def any_unresolvable(self) -> bool:
        """Whether any HTTP call site went unaddressed."""
        return self.unresolvable > 0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "seen": self.seen,
            "resolved": self.resolved,
            "unresolvable": self.unresolvable,
            "naming_a_write": self.naming_a_write,
            "by_reason": dict(sorted(self.by_reason.items())),
            "examples": self.examples[:MAX_RETAINED_PER_CLASS],
        }


@dataclass
class PlanAlarmRegister:
    """Every planning pass's cap outcome, for the report.

    Thread-safe: the deterministic and union passes can report from different
    tasks.
    """

    _passes: list[PlanTruncation] = field(default_factory=list)
    _crawl_budgets: list[CrawlBudgetTruncation] = field(default_factory=list)
    _probe_budgets: list[ProbeBudgetTruncation] = field(default_factory=list)
    _method_provenance: list[MethodProvenance] = field(default_factory=list)
    _unreachable_call_sites: list[UnreachableCallSites] = field(default_factory=list)
    _bundle_fetches: list[BundleFetchTruncation] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, event: PlanTruncation) -> None:
        """Record one pass. A ranking inversion is always logged loudly."""
        with self._lock:
            self._passes.append(event)
        if event.ranking_inversions:
            logger.warning(
                "PLAN RANKING FAILURE recorded for the report — %d dropped task(s) sat on "
                "an endpoint carrying their own class's observed surface (stage=%s cap=%d).",
                len(event.ranking_inversions),
                event.stage,
                event.cap,
            )

    def passes(self) -> list[PlanTruncation]:
        """Every recorded pass, in the order it happened."""
        with self._lock:
            return list(self._passes)

    def record_crawl_budget(self, event: CrawlBudgetTruncation) -> None:
        """Record one enrichment pass's budget outcome."""
        with self._lock:
            self._crawl_budgets.append(event)
        if event.truncated:
            logger.info(
                "CRAWL BUDGET recorded for the report — %d of %d candidate URL(s) were not "
                "opened (budget=%d).",
                event.dropped_total,
                event.candidates,
                event.budget,
            )

    def crawl_budgets(self) -> list[CrawlBudgetTruncation]:
        """Every recorded enrichment pass, in the order it happened."""
        with self._lock:
            return list(self._crawl_budgets)

    def record_probe_budget(self, event: ProbeBudgetTruncation) -> None:
        """Record one surface-mapping sweep's budget outcome."""
        with self._lock:
            self._probe_budgets.append(event)
        if event.ordering_failure:
            logger.warning(
                "PROBE ORDERING FAILURE recorded for the report — the %s sweep dropped %d "
                "application/API route(s) the sweep exists to reach (budget=%d, "
                "candidates=%d). A larger budget does not fix an ordering defect.",
                event.sweep,
                len(event.relevant_dropped),
                event.budget,
                event.candidates,
            )
        elif event.truncated:
            logger.info(
                "PROBE BUDGET recorded for the report — the %s sweep left %d of %d route(s) "
                "unprobed (budget=%d); every one dropped was a static asset.",
                event.sweep,
                event.dropped_total,
                event.candidates,
                event.budget,
            )

    def probe_budgets(self) -> list[ProbeBudgetTruncation]:
        """Every recorded sweep, in the order it happened."""
        with self._lock:
            return list(self._probe_budgets)

    def record_method_provenance(self, event: MethodProvenance) -> None:
        """Record how the discovered surface's verbs came to be known."""
        with self._lock:
            self._method_provenance.append(event)
        if event.any_unread:
            logger.info(
                "METHOD PROVENANCE recorded for the report — %d of %d discovered "
                "endpoint(s) carry a verb the engine could not read.",
                event.unread,
                event.total,
            )

    def method_provenance(self) -> list[MethodProvenance]:
        """Every recorded provenance pass, in the order it happened."""
        with self._lock:
            return list(self._method_provenance)

    def method_provenance_summary(self) -> dict[str, Any]:
        """Render verb provenance for ``report.json``.

        Present on a clean run too. "Every endpoint's verb was read" is the claim
        that makes an all-GET surface meaningful, and a section that appears only
        when something went unread cannot be told apart from one nobody wrote.
        """
        events = self.method_provenance()
        named = sum(e.named for e in events)
        platform = sum(e.platform_default for e in events)
        unread = sum(e.unread for e in events)
        examples: list[str] = []
        for event in events:
            examples.extend(event.unread_examples)
        return {
            "measured": bool(events),
            "total": named + platform + unread,
            "named": named,
            "platform_default": platform,
            "unread": unread,
            "any_unread": unread > 0,
            "unread_examples": examples[:MAX_RETAINED_PER_CLASS],
        }

    def record_unreachable_call_sites(self, event: UnreachableCallSites) -> None:
        """Record one bundle walk's resolved/unresolvable split."""
        with self._lock:
            self._unreachable_call_sites.append(event)
        if event.naming_a_write:
            logger.warning(
                "UNREACHABLE WRITE SURFACE recorded for the report — %d of %d HTTP call "
                "site(s) could not be addressed, and %d of those NAMED a state-changing "
                "verb. Those routes reach no write-family methodology.",
                event.unresolvable,
                event.seen,
                event.naming_a_write,
            )
        elif event.any_unresolvable:
            logger.info(
                "UNREACHABLE CALL SITES recorded for the report — %d of %d HTTP call "
                "site(s) resolved to no route.",
                event.unresolvable,
                event.seen,
            )

    def unreachable_call_sites(self) -> list[UnreachableCallSites]:
        """Every recorded bundle walk, in the order it happened."""
        with self._lock:
            return list(self._unreachable_call_sites)

    def record_bundle_fetch(self, event: BundleFetchTruncation) -> None:
        """Record one bundle walk's fetch budget outcome."""
        with self._lock:
            self._bundle_fetches.append(event)
        if event.truncated:
            logger.info(
                "BUNDLE FETCH BUDGET recorded for the report — %d of %d discovered chunk "
                "URL(s) were never fetched (budget=%d). Any call site inside them is "
                "absent from every downstream count.",
                event.unread,
                event.discovered,
                event.budget,
            )

    def bundle_fetches(self) -> list[BundleFetchTruncation]:
        """Every recorded bundle walk, in the order it happened."""
        with self._lock:
            return list(self._bundle_fetches)

    def unreachable_call_site_summary(self) -> dict[str, Any]:
        """Render the resolved/unresolvable split for ``report.json``.

        Present on a clean run too. "Every HTTP call the frontend declares was
        turned into a route we can address" is the claim that makes a small
        endpoint set a statement about the target, and a section that appears
        only on failure cannot be told apart from one nobody wrote.

        Carries the fetch bound beside the split, because the two answer halves
        of one question and only together do they bound it. ``unresolvable`` is
        about surface we READ and could not address; ``bundle_fetch`` is about
        surface we never opened. A write surface of zero is a statement about the
        target only when BOTH are zero — hence
        :attr:`write_surface_indeterminate`, computed here rather than left to a
        renderer, so every consumer reads the same verdict.
        """
        events = self.unreachable_call_sites()
        by_reason: dict[str, int] = {}
        examples: list[str] = []
        for event in events:
            for reason, count in event.by_reason.items():
                by_reason[reason] = by_reason.get(reason, 0) + count
            examples.extend(event.examples)
        fetches = self.bundle_fetches()
        unread = sum(e.unread for e in fetches)
        discovered = sum(e.discovered for e in fetches)
        return {
            "measured": bool(events),
            "seen": sum(e.seen for e in events),
            "resolved": sum(e.resolved for e in events),
            "unresolvable": sum(e.unresolvable for e in events),
            "naming_a_write": sum(e.naming_a_write for e in events),
            "any_unresolvable": any(e.any_unresolvable for e in events),
            "by_reason": dict(sorted(by_reason.items())),
            "examples": examples[:MAX_RETAINED_PER_CLASS],
            "bundle_fetch": {
                "measured": bool(fetches),
                "budget": next((e.budget for e in fetches), 0),
                "discovered": discovered,
                "fetched": sum(e.fetched for e in fetches),
                "unread": unread,
                "truncated": any(e.truncated for e in fetches),
                "first_omitted": next((e.first_omitted for e in fetches if e.first_omitted), ""),
                "omitted_examples": [url for e in fetches for url in e.omitted_examples][
                    :MAX_RETAINED_PER_CLASS
                ],
                "walks": [e.to_dict() for e in fetches],
            },
            # Law 5 at the input layer: a zero measured over PART of the input is
            # INDETERMINATE, never a clean zero. The write surface a run reports
            # is a floor over the chunks it opened, and a run that opened 12 of 53
            # has not measured the application — it has measured 23% of it.
            "write_surface_indeterminate": bool(unread) if fetches else False,
            "indeterminate_reason": (
                f"{unread} of {discovered} discovered JS chunk(s) were never fetched "
                f"(bound: {next((e.budget for e in fetches), 0)}), so any HTTP call site "
                "inside them is absent from every count in this section"
                if fetches and unread
                else ""
            ),
        }

    def probe_summary(self) -> dict[str, Any]:
        """Render the surface-mapping budgets for ``report.json``.

        Present on a clean run too. "Every route was asked what methods it
        accepts" is a claim the deliverable should make explicitly — and on this
        sweep in particular, because a sweep that probed only static assets
        returns exactly what a sweep that found no write verb returns.
        """
        events = self.probe_budgets()
        return {
            "probe_truncated": any(e.truncated for e in events),
            "ordering_failure": any(e.ordering_failure for e in events),
            "sweeps_recorded": len(events),
            "candidates": sum(e.candidates for e in events),
            "probed": sum(e.probed for e in events),
            "dropped_total": sum(e.dropped_total for e in events),
            "relevant_dropped_count": sum(len(e.relevant_dropped) for e in events),
            "first_omitted": next((e.first_omitted for e in events if e.first_omitted), ""),
            "sweeps": [e.to_dict() for e in events],
        }

    def crawl_summary(self) -> dict[str, Any]:
        """Render the crawl budget for ``report.json``.

        Present on a clean run too, for the same reason the plan cap is: "the
        crawl fit inside its budget" is a claim the deliverable should make
        explicitly, and a section that appears only on truncation cannot be told
        apart from one nobody wrote.
        """
        events = self.crawl_budgets()
        opened_by_host: dict[str, int] = {}
        dropped_by_host: dict[str, int] = {}
        for event in events:
            for host, count in event.opened_by_host.items():
                opened_by_host[host] = opened_by_host.get(host, 0) + count
            for host, count in event.dropped_by_host.items():
                dropped_by_host[host] = dropped_by_host.get(host, 0) + count
        return {
            "crawl_truncated": any(e.truncated for e in events),
            "passes_recorded": len(events),
            "candidates": sum(e.candidates for e in events),
            "opened": sum(e.opened for e in events),
            "dropped_total": sum(e.dropped_total for e in events),
            "duplicates_collapsed": sum(e.duplicates_collapsed for e in events),
            # The first pass that actually dropped something owns the example: a
            # reader checks the ordering against it, so it has to be a URL that
            # was really omitted rather than the last pass's blank.
            "first_omitted": next((e.first_omitted for e in events if e.first_omitted), ""),
            "opened_by_host": dict(sorted(opened_by_host.items())),
            "dropped_by_host": dict(sorted(dropped_by_host.items())),
            "hosts_never_opened": sorted(
                host for host in dropped_by_host if not opened_by_host.get(host)
            ),
            "passes": [e.to_dict() for e in events],
        }

    def summary(self) -> dict[str, Any]:
        """Render for ``report.json``.

        Present even when nothing was truncated, because "the plan fit inside
        its cap" is a claim the deliverable should make explicitly.
        """
        passes = self.passes()
        classes: set[str] = set()
        planned: set[str] = set()
        for event in passes:
            classes.update(event.dropped_by_class)
            planned.update(event.dropped_by_class)
            planned.update(k for k, n in event.kept_by_class.items() if n)
        return {
            "plan_truncated": any(p.truncated for p in passes),
            "passes_recorded": len(passes),
            "dropped_total": sum(p.dropped_total for p in passes),
            "classes_truncated": sorted(classes),
            # Every class the plan held a candidate for, kept or dropped. The
            # class-coverage account reads this to tell "no applicable endpoint
            # existed" from "the plan had one and the class never ran".
            "classes_with_candidates": sorted(planned),
            "ranking_inversion_count": sum(len(p.ranking_inversions) for p in passes),
            "passes": [p.to_dict() for p in passes],
        }

    def reset(self) -> None:
        """Forget every pass. For process teardown and tests.

        The domain is COMPUTED from this dataclass's own fields rather than
        written out one ``.clear()`` per list, because a hand-maintained reset is
        the guard-domain law one level down: the question is not "does a new
        member get classified" but "does a new member get CLEARED", and a
        forgotten line is silent in exactly the direction that matters.

        What leaks is not abstract. Every accumulator here retains target-chosen
        strings — ``first_omitted`` is a URL off the client's application,
        ``omitted_examples`` and ``unread_examples`` are more of them — and they
        render in the next engagement's client-facing coverage section, under a
        different client's engagement id. A per-process register with five
        hand-written clears and no guard was one added field away from that; this
        landed as the sixth field was being added, which is how it was noticed.
        """
        with self._lock:
            for spec in fields(self):
                if spec.name == "_lock":
                    continue
                accumulator = getattr(self, spec.name)
                # Every field here is a list accumulator. `clear()` rather than
                # rebinding, because a frozen-ish shared register may be held by
                # reference in more than one place.
                accumulator.clear()


# ---------------------------------------------------------------------------
# The active register — absent by default
# ---------------------------------------------------------------------------

_active_register: PlanAlarmRegister | None = None


def set_active_plan_alarms(register: PlanAlarmRegister | None) -> None:
    """Install (or clear) the run's register.

    Args:
        register: The register, or ``None`` to detach.
    """
    global _active_register
    _active_register = register


def get_active_plan_alarms() -> PlanAlarmRegister | None:
    """The run's register, or ``None`` when nothing installed one."""
    return _active_register


def record_plan_truncation(event: PlanTruncation) -> None:
    """Record a planning pass against the active register, if there is one.

    Never raises and never creates a register: a plan built outside an
    engagement — a unit test, a replay — has no report to carry it.
    """
    register = _active_register
    if register is None:
        return
    register.record(event)


def record_crawl_budget(event: CrawlBudgetTruncation) -> None:
    """Record an enrichment pass against the active register, if there is one.

    Never raises and never creates a register: a crawl outside an engagement — a
    unit test, a driver — has no report to carry it.
    """
    register = _active_register
    if register is None:
        return
    register.record_crawl_budget(event)


def record_probe_budget(event: ProbeBudgetTruncation) -> None:
    """Record a surface-mapping sweep against the active register, if there is one.

    Never raises and never creates a register: a sweep run outside an engagement
    — a unit test, an offline driver — has no report to carry it.
    """
    register = _active_register
    if register is None:
        return
    register.record_probe_budget(event)


def record_method_provenance(event: MethodProvenance) -> None:
    """Record verb provenance on the active register, if one is installed."""
    register = _active_register
    if register is not None:
        register.record_method_provenance(event)


def method_provenance_summary() -> dict[str, Any]:
    """The active register's verb-provenance summary, or the clean shape."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().method_provenance_summary()
    return register.method_provenance_summary()


def record_unreachable_call_sites(event: UnreachableCallSites) -> None:
    """Record a bundle walk's resolved/unresolvable split, if a register exists."""
    register = _active_register
    if register is not None:
        register.record_unreachable_call_sites(event)


def unreachable_call_site_summary() -> dict[str, Any]:
    """The active register's call-site reach summary, or the clean shape."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().unreachable_call_site_summary()
    return register.unreachable_call_site_summary()


def probe_budget_summary() -> dict[str, Any]:
    """The active register's probe summary, or the clean shape when none exists."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().probe_summary()
    return register.probe_summary()


def crawl_budget_summary() -> dict[str, Any]:
    """The active register's crawl summary, or the clean shape when none exists."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().crawl_summary()
    return register.crawl_summary()


def plan_alarm_summary() -> dict[str, Any]:
    """The active register's summary, or the clean shape when none is installed."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().summary()
    return register.summary()


__all__ = [
    "MAX_RETAINED_PER_CLASS",
    "CrawlBudgetTruncation",
    "MethodProvenance",
    "PlanAlarmRegister",
    "UnreachableCallSites",
    "PlanTruncation",
    "ProbeBudgetTruncation",
    "crawl_budget_summary",
    "method_provenance_summary",
    "record_unreachable_call_sites",
    "unreachable_call_site_summary",
    "get_active_plan_alarms",
    "plan_alarm_summary",
    "probe_budget_summary",
    "record_crawl_budget",
    "record_method_provenance",
    "record_plan_truncation",
    "record_probe_budget",
    "set_active_plan_alarms",
]
