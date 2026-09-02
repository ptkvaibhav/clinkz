"""One authenticated Juice Shop engagement, graded by the target itself.

Juice Shop marks a challenge solved only when it is genuinely exploited and
exposes that state at ``/api/Challenges``, which makes the target the grader
rather than us. This harness runs the engagement between two scoreboard
snapshots and reconciles **two independent numbers that must not be conflated**:

  * **challenges solved** — what the target confirmed we did to it;
  * **findings emitted** — what the engagement reported.

Every mismatch means something different and none may be assumed away:

  * *solved but not reported* — a real vulnerability was exercised and nothing
    was emitted. A reporting gap, exactly as serious as the reverse.
  * *reported but not solved* — either a genuine finding **outside the challenge
    set** (Juice Shop's challenge list is not a complete vulnerability
    inventory) or a phantom. Which one it is has to be reasoned from the
    finding's own evidence, and this harness prints that evidence rather than
    guessing.

**The addressable denominator is DERIVED, not inherited.** A challenge is
addressable when its own category maps to a vulnerability class this engine
actually dispatches AND its difficulty is 3 or below — the point past which
Juice Shop's challenges turn into multi-step puzzles requiring domain knowledge
or out-of-band information rather than a reachable vulnerability. Both halves of
that rule are stated here and computed from the live target, so the number is
auditable. It is deliberately **not** forced to match any previously-quoted
figure.

**And the floor is what THESE principals trip.** ``solved_by_testing`` is
``solved_total`` minus what authenticating and crawling reach on their own, so
the floor is keyed by the credential set that measured it: adding ``jim`` beside
``admin`` adds whatever ``jim``'s own login trips, and subtracting the admin-only
floor would credit that to testing. :func:`record_floor` refuses five kinds of
run — one that tested, one whose dispatch count is unmeasurable, one whose model
stamp names a stage nothing served, one carrying no model stamp to read, and one
that does not say who it logged in as — and no floor that applies means
``solved_by_testing: None``, never zero. The fourth is the same guard as the
third and not a new one: an absent stamp used to coalesce to the empty list,
which reads as "every stage was served" and is what an outage mid-run actually
leaves behind.

Usage::

    python scripts/juiceshop_benchmark_run.py \\
        --authorization <auth.json> --benchmark-profile <bp.json> --creds <creds.json>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _artifact_io import write_redacted_json, write_redacted_text  # noqa: E402
from d1_consistency_runner import (  # noqa: E402
    OUTPUTS,
    newest_engagement_dirs,
    read_artifact_scan,
    read_report,
)
from regrade_stored_bundles import NO_ARM, REFUSED, SURVIVES, grade  # noqa: E402

# ``_artifact_io`` puts ``src/`` on the path, so the engine is importable from here.
# The exhausted-stage reader is the PRODUCER's own: "what does an LLM outage look
# like in a stored bundle" is one question with one answer, and a second copy of
# it inside a driver is a second thing to keep in step.
from clinkz.llm.degradation import stamp_exhaustion  # noqa: E402

BASE = "http://localhost:3000"
COMPOSE = ["docker", "compose", "-f", "docker/docker-compose.yml"]
RESULTS_DIR = Path("outputs/_juiceshop_benchmark")

#: Where the measured floor lives. Not a constant in this file: a hardcoded
#: floor set is a claim about the target that nobody re-measures, and it goes
#: stale the moment Juice Shop changes which challenges an authenticated crawl
#: trips. This file is WRITTEN by a run that dispatched zero methodology tasks
#: and carries the engagement id that produced it.
FLOOR_PATH = RESULTS_DIR / "benchmark_floor.json"

#: Schema version of :data:`FLOOR_PATH`. Version 1 was a single unkeyed record;
#: version 2 keys every record by the credential set that produced it. A v1 file
#: is readable and is applied to NOTHING — see :func:`read_floor`.
FLOOR_FILE_VERSION = 2

#: The key for a run whose report does not say who it authenticated as. It is
#: deliberately not a value any real run produces: nothing may be recorded under
#: it and nothing may be subtracted from it. An unknown credential set is not the
#: anonymous one, and treating the two alike is the same absence-read-as-a-zero
#: this whole section exists to remove.
UNKNOWN_CREDENTIAL_SET = ""

#: What a run that authenticated as nobody is keyed under. A real observation —
#: an anonymous crawl trips a floor of its own — and comparable, unlike the
#: unknown case above.
ANONYMOUS_CREDENTIAL_SET = "(anonymous)"


def methodology_dispatches(report: dict[str, Any]) -> int | None:
    """How many methodology tasks this engagement actually DISPATCHED.

    Read from the component ledger's per-class methodology components, whose
    ``items_contributed`` counts dispatches rather than findings — that is the
    declared contract at the one dispatch seam, chosen precisely so a clean
    class on a clean run does not read as a silent component.

    **A ledger carrying no methodology component at all is not a zero.** Those
    components are declared at engagement start by ``declare_all()``, so their
    absence means the bundle predates that registration and the count is
    UNMEASURABLE — the run may have dispatched hundreds. Four stored Juice Shop
    bundles have exactly that shape and between six and eleven findings each;
    read as zeroes they would each qualify as a floor observation, which is this
    engine subtracting its own results from itself by way of a missing key. It is
    the ledger's own law: a component the ledger never hears from is not
    measurable, and "declared and never invoked" is a different fact from "never
    declared".

    Args:
        report: A parsed ``report_<id>.json``.

    Returns:
        The total across every ``methodology:*`` component, or ``None`` when the
        ledger carries no such component. Zero means no ``_test_*`` method was
        invoked against any endpoint: whatever the target recorded as solved,
        this engine did not exploit it.
    """
    ledger = report.get("component_ledger") or {}
    rows = [
        component
        for component in (ledger.get("components") or [])
        if isinstance(component, dict)
        and str(component.get("component") or "").startswith("methodology:")
    ]
    if not rows:
        return None
    return sum(int(component.get("items_contributed") or 0) for component in rows)


def credential_set_key(report: dict[str, Any]) -> str:
    """The identity set this run authenticated as, as a comparable key.

    A floor is what authenticating and crawling trips **as those principals**.
    Adding a principal adds whatever its own login trips — supplying ``jim``
    beside ``admin`` adds ``loginJim`` — so a floor measured under one credential
    set understates the next one's, and every challenge it understates by is
    credited to testing. The floor is therefore keyed by this, and
    :func:`subtract_floor` refuses a floor whose key differs from the run's.

    Read from ``authentication.roles``, which the orchestrator DECLARES: it is
    the run's own record of the roles it holds session material for, present in
    the bundle, so the offline recorder and the live path read one fact from one
    producer. The role LABEL is used as an opaque identity, never for its
    meaning — nothing here reads a hierarchy, a privilege or a capability out of
    it, which is the read that ``_principal.privilege_order`` exists to refuse.

    Args:
        report: A parsed ``report_<id>.json``.

    Returns:
        ``role+role`` for an authenticated run, :data:`ANONYMOUS_CREDENTIAL_SET`
        for one that authenticated as nobody, and :data:`UNKNOWN_CREDENTIAL_SET`
        when the report has no authentication block to read.
    """
    auth = report.get("authentication")
    if not isinstance(auth, dict) or auth.get("roles") is None:
        return UNKNOWN_CREDENTIAL_SET
    roles = sorted({str(role).strip().lower() for role in auth["roles"] if str(role).strip()})
    return "+".join(roles) if roles else ANONYMOUS_CREDENTIAL_SET


def read_floor() -> dict[str, Any]:
    """The floor file, normalised to the keyed shape. Never a floor by itself.

    Returns the whole file — ``{"floors": {credential_set: record}}`` — because
    selecting a record and refusing a mismatched one are one decision, and
    :func:`subtract_floor` owns it. Two functions comparing the same key is two
    expressions of one fact, which drift.

    A version-1 file (one unkeyed record) is read and reported under
    ``unkeyed_legacy``, never under a credential set. It cannot be applied: it
    was measured under a credential set nobody wrote down, so "does it match this
    run" is unanswerable, and answering it anyway is a guess in the direction
    that inflates ``solved_by_testing``.
    """
    empty: dict[str, Any] = {"version": FLOOR_FILE_VERSION, "floors": {}}
    if not FLOOR_PATH.is_file():
        return empty
    try:
        stored = json.loads(FLOOR_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        # Type only. A JSONDecodeError quotes the bytes around the fault, and
        # this harness prints to a log an operator keeps.
        print(f"WARNING: could not read {FLOOR_PATH}: {type(exc).__name__}")
        return {**empty, "error": type(exc).__name__}
    if not isinstance(stored, dict):
        print(f"WARNING: {FLOOR_PATH} is not an object; ignoring it")
        return empty
    if isinstance(stored.get("floors"), dict):
        return {
            "version": int(stored.get("version") or FLOOR_FILE_VERSION),
            "floors": stored["floors"],
            **(
                {"unkeyed_legacy": stored["unkeyed_legacy"]} if stored.get("unkeyed_legacy") else {}
            ),
        }
    if stored.get("keys") or stored.get("recorded"):
        return {**empty, "unkeyed_legacy": stored}
    return empty


def floor_for(floor_file: dict[str, Any], credential_set: str) -> dict[str, Any] | None:
    """The record measured under *credential_set*, or ``None``.

    The unknown key never resolves: a run that did not say who it authenticated
    as cannot be matched to a floor, in either direction.
    """
    if credential_set == UNKNOWN_CREDENTIAL_SET:
        return None
    record = (floor_file.get("floors") or {}).get(credential_set)
    return record if isinstance(record, dict) else None


def record_floor(
    *,
    engagement: str,
    solved_keys: list[str],
    dispatches: int | None,
    challenge_index: dict[str, Any],
    credential_set: str,
    exhausted_stages: list[str] | None,
) -> dict[str, Any]:
    """Fold a zero-dispatch run's solved set into the floor for its credential set.

    A run that dispatched **zero** methodology tasks and still solved challenges
    solved them by authenticating and crawling. Those challenges are not
    evidence about this engine's exploitation, and counting them is how a "7 of
    49" becomes a number nobody should put in front of a client.

    The union is deliberate, one-way, and **within a credential set**: another
    zero-dispatch run under the same principals that trips a challenge the first
    did not has widened what crawling alone reaches, and the floor has to widen
    with it. Nothing here removes a key — a run that fails to reproduce a floor
    challenge is evidence about that run's crawl, not about whether the challenge
    is reachable without testing. Nothing here merges across credential sets
    either: an ``admin`` floor and an ``admin+jim`` floor are two measurements of
    two different things, and both are worth keeping.

    Args:
        engagement: The engagement id that produced this observation.
        solved_keys: What the target confirmed it solved.
        dispatches: This run's methodology dispatch count. Must be zero — and
            must not be ``None``, which is "unmeasurable", not "none".
        challenge_index: ``{key: challenge}`` for the names and categories.
        credential_set: :func:`credential_set_key` for this run.
        exhausted_stages: :func:`~clinkz.llm.degradation.stamp_exhaustion` for
            this run. Must be an empty list — ``None`` is "the bundle carries no
            model stamp", which is INDETERMINATE and refused, not clean. No
            default: a caller that may omit this argument is a caller that can
            record a floor without ever asking the question.

    Returns:
        The written record for *credential_set*.

    Raises:
        ValueError: The run is not a floor observation — it tested, its dispatch
            count is unmeasurable, it does not say who it authenticated as, an
            LLM provider outage means its crawl was not a complete crawl, or its
            bundle cannot say whether there was one.
    """
    if dispatches is None:
        raise ValueError(
            f"refusing to record a floor from engagement {engagement}: its ledger "
            f"carries no methodology component, so its dispatch count is unmeasurable "
            f"rather than zero"
        )
    if dispatches:
        raise ValueError(
            f"refusing to record a floor from engagement {engagement}: it dispatched "
            f"{dispatches} methodology task(s), so its solved set is not the "
            f"crawl-and-authenticate floor"
        )
    if credential_set == UNKNOWN_CREDENTIAL_SET:
        raise ValueError(
            f"refusing to record a floor from engagement {engagement}: its report does "
            f"not say who it authenticated as, and a floor that cannot be keyed to a "
            f"credential set cannot be safely applied to any later run"
        )
    if exhausted_stages is None:
        raise ValueError(
            f"refusing to record a floor from engagement {engagement}: its bundle carries "
            f"no model stamp, so whether every LLM stage was served is INDETERMINATE. An "
            f"absent stamp is exactly what an outage mid-run leaves behind, and reading it "
            f"as 'nothing was starved' is how the guard against a void floor passes one"
        )
    if exhausted_stages:
        raise ValueError(
            f"refusing to record a floor from engagement {engagement}: its model stamp "
            f"reports no provider served {', '.join(exhausted_stages)}, so its crawl was "
            f"not a complete crawl. An under-measured floor subtracts too little and "
            f"INFLATES solved_by_testing, which is the number the floor exists to deflate"
        )
    floor_file = read_floor()
    previous = floor_for(floor_file, credential_set) or {}
    keys = sorted(set(previous.get("keys") or []) | set(solved_keys))
    sources = list(previous.get("sources") or [])
    sources.append(
        {
            "engagement": engagement,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "methodology_dispatches": dispatches,
            "solved": sorted(solved_keys),
        }
    )
    record = {
        "recorded": True,
        "credential_set": credential_set,
        "_what": (
            "Challenges Juice Shop marks solved for a run that dispatched ZERO "
            "methodology tasks WHILE AUTHENTICATED AS THIS CREDENTIAL SET - i.e. what "
            "logging in as these principals and crawling trips on their own. Subtracted "
            "from solved_total to give solved_by_testing, and only for a run that "
            "authenticated as the same set."
        ),
        "keys": keys,
        "challenges": [
            {
                "key": key,
                "name": (challenge_index.get(key) or {}).get("name"),
                "category": (challenge_index.get(key) or {}).get("category"),
                "difficulty": (challenge_index.get(key) or {}).get("difficulty"),
            }
            for key in keys
        ],
        "sources": sources,
    }
    floors = dict(floor_file.get("floors") or {})
    floors[credential_set] = record
    write_redacted_json(
        FLOOR_PATH,
        {
            "version": FLOOR_FILE_VERSION,
            "_what": (
                "One measured crawl-and-authenticate floor per credential set. Keyed "
                "because a floor is what THESE principals trip: adding a principal adds "
                "whatever its own login trips, and subtracting the narrower floor would "
                "credit that to testing."
            ),
            "floors": floors,
            **(
                {"unkeyed_legacy": floor_file["unkeyed_legacy"]}
                if floor_file.get("unkeyed_legacy")
                else {}
            ),
        },
    )
    return record


def subtract_floor(
    solved_keys: list[str], floor_file: dict[str, Any], *, credential_set: str
) -> dict[str, Any]:
    """Split a solved set into what testing earned and what the floor supplies.

    Returns ``solved_by_testing: None`` whenever no floor applies — none has been
    measured, the only ones measured were measured under different principals, or
    this run does not say who it authenticated as. That is the honest answer and
    not a zero: without an applicable zero-dispatch observation there is nothing
    to subtract, and defaulting to "subtract nothing" reproduces the inflated
    number the floor exists to remove.

    Args:
        solved_keys: What the target confirmed this run solved.
        floor_file: :func:`read_floor`.
        credential_set: :func:`credential_set_key` for this run.
    """
    measured = sorted(k for k in (floor_file.get("floors") or {}) if k)
    unmeasured: dict[str, Any] = {
        "floor_recorded": False,
        "floor_keys": [],
        "credential_set": credential_set,
        "measured_credential_sets": measured,
        "solved_by_testing": None,
        "solved_by_testing_count": None,
    }
    if credential_set == UNKNOWN_CREDENTIAL_SET:
        return {
            **unmeasured,
            "note": (
                "This run's report does not say who it authenticated as, so no floor can "
                "be matched to it. A floor is what a given credential set trips; applying "
                "one to a run whose principals are unknown is a guess."
            ),
        }
    record = floor_for(floor_file, credential_set)
    if record is None:
        legacy = floor_file.get("unkeyed_legacy") or {}
        note = (
            f"No zero-dispatch run has been recorded for credential set "
            f"{credential_set!r}, so the crawl-and-authenticate floor is unmeasured for "
            f"this run and solved_total cannot be split. "
        )
        if measured:
            note += (
                f"A floor exists for {', '.join(repr(k) for k in measured)} and is NOT "
                f"applied: a floor measured under different principals understates this "
                f"run's, and every challenge it understates by would be credited to "
                f"testing. "
            )
        if legacy:
            note += (
                f"An unkeyed floor from before credential-set keying is also on file "
                f"({len(legacy.get('keys') or [])} challenge(s), from "
                f"{', '.join(str(s.get('engagement'))[:8] for s in (legacy.get('sources') or []))}"
                f"); it records no credential set, so it cannot be matched to anything. "
            )
        note += "Record one with `--record-floor <zero-dispatch engagement id>`."
        return {**unmeasured, "note": note}
    floor_keys = sorted(record.get("keys") or [])
    earned = [key for key in solved_keys if key not in set(floor_keys)]
    return {
        "floor_recorded": True,
        "floor_keys": floor_keys,
        "credential_set": credential_set,
        "measured_credential_sets": measured,
        "floor_sources": [s.get("engagement") for s in (record.get("sources") or [])],
        "solved_by_testing": earned,
        "solved_by_testing_count": len(earned),
        "solved_from_floor": [key for key in solved_keys if key in set(floor_keys)],
    }


#: Juice Shop's own category labels, mapped to whether this engine dispatches a
#: class that could confirm that kind of flaw. Every category the target ships is
#: listed: an unlisted one would silently drop out of the denominator, and a
#: challenge nobody counted is a challenge nobody has to explain.
CATEGORY_ADDRESSABLE: dict[str, str] = {
    "Injection": "sql_injection / nosql_injection / command_injection / ssti",
    "XSS": "xss_reflected / xss_stored / xss_dom",
    "Broken Access Control": "idor",
    "Broken Authentication": "brute_force / jwt / weak_session",
    "Sensitive Data Exposure": "secrets_exposure / lfi / idor",
    "Improper Input Validation": "input_validation / constraint_violation / mass_assignment",
    "Cryptographic Issues": "weak_cryptography",
    "Security Misconfiguration": "security_headers / secrets_exposure",
    "Unvalidated Redirects": "open_redirect",
    "XXE": "xxe",
}

#: Categories with no dispatching class, and the reason. Held OUT of the
#: denominator, and named in the output so the exclusion is visible.
CATEGORY_NOT_ADDRESSABLE: dict[str, str] = {
    "Vulnerable Components": (
        "a published CVE against a dependency is a LEAD in this engine, never a "
        "finding — it must reduce to one of our own oracles on the live target"
    ),
    "Miscellaneous": "no vulnerability class; mostly UI scavenger hunts",
    "Observability Failures": "logging and monitoring gaps; no dispatched class",
    "Broken Anti Automation": "captcha / anti-automation; insecure_captcha is unimplemented",
    "Security through Obscurity": "no dispatched class",
    "Insecure Deserialization": "no dispatched class",
}

#: The same categories, as the ``_test_*`` methods that could CLAIM a solve in
#: them. ``CATEGORY_ADDRESSABLE`` says the same thing in prose for a human
#: reader; this says it in the dispatcher's own vocabulary so the attribution
#: split below can be computed rather than asserted. The two are held in sync in
#: both directions by :func:`_assert_category_classes`, and every name is
#: checked against ``DISPATCHABLE_TEST_METHODS`` — a typo here would make a
#: category permanently unattributable, which reads exactly like an engine that
#: never claims it.
CATEGORY_CLASSES: dict[str, tuple[str, ...]] = {
    "Injection": ("_test_sqli", "_test_nosqli", "_test_cmdi", "_test_ssti", "_test_xxe"),
    "XSS": ("_test_xss_reflected", "_test_xss_stored", "_test_xss_dom"),
    "Broken Access Control": ("_test_idor",),
    "Broken Authentication": ("_test_brute_force", "_test_jwt", "_test_weak_session"),
    "Sensitive Data Exposure": ("_test_secrets_exposure", "_test_lfi", "_test_idor"),
    "Improper Input Validation": (
        "_test_input_validation",
        "_test_constraint_violation",
        "_test_mass_assignment",
        "_test_file_upload",
    ),
    "Cryptographic Issues": ("_test_crypto",),
    "Security Misconfiguration": (
        "_test_security_headers",
        "_test_secrets_exposure",
        "_test_csp",
    ),
    "Unvalidated Redirects": ("_test_open_redirect",),
    "XXE": ("_test_xxe",),
}


def _assert_category_classes() -> None:
    """Both directions of the map, plus every name against the dispatch table.

    The guard-domain law: the domain is computed from ``CATEGORY_ADDRESSABLE``
    rather than restated, so a category added there without classes here is a
    loud failure instead of a category that can never be attributed.
    """
    from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS

    declared = set(CATEGORY_CLASSES)
    computed = set(CATEGORY_ADDRESSABLE)
    missing = computed - declared
    extra = declared - computed
    if missing or extra:
        raise AssertionError(
            f"CATEGORY_CLASSES is out of sync with CATEGORY_ADDRESSABLE: "
            f"missing={sorted(missing)} extra={sorted(extra)}"
        )
    for category, methods in CATEGORY_CLASSES.items():
        unknown = sorted(set(methods) - set(DISPATCHABLE_TEST_METHODS))
        if unknown:
            raise AssertionError(
                f"CATEGORY_CLASSES[{category!r}] names methods this engine does not "
                f"dispatch: {unknown}"
            )


#: The surface each challenge NAMES, and the challenge's own words that name it.
#:
#: A category tells you what KIND of flaw a challenge is about. It cannot tell
#: one finding of a class from another of the same class, and that gap is not
#: hypothetical: run 3 of the variance envelope emitted ``_test_idor`` findings
#: at ``/rest/basket/:id`` AND at ``/api/Users/:p3``, and ``basketAccess`` read
#: as attributable from either — so removing the basket finding, the one the
#: challenge is actually about, left the positive reading standing on a sibling.
#: A positive reading that outlives its own evidence is a phantom wearing a
#: category label.
#:
#: So the binding is to the FINDING: a solve is attributable when a specific
#: surviving confirmed finding was DISPATCHED against the surface the challenge
#: names. Juice Shop's challenge records carry a category and a sentence, never
#: a route, so the route is declared here — with the sentence that sources it,
#: verbatim, so a reader can check the claim rather than trust it.
#:
#: **An undeclared challenge is unattributable, by construction.** That is the
#: safe direction and it is deliberate: a missing entry under-reports what this
#: engine can show, which costs a number, while a category-level match
#: over-reports, which costs the number's meaning. Declaring one is a line of
#: this table plus the sentence that justifies it.
CHALLENGE_SURFACES: dict[str, tuple[tuple[str, ...], str]] = {
    "basketAccessChallenge": (
        ("/rest/basket/*",),
        '"View another user\'s shopping basket." A basket is served at '
        "/rest/basket/<id>; a crossing anywhere else is a crossing on some other "
        "object.",
    ),
    "forgedFeedbackChallenge": (
        ("/api/feedbacks",),
        '"Post some feedback in another user\'s name." Feedback is written to the '
        "COLLECTION, /api/Feedbacks. The item route /api/Feedbacks/<id> is "
        "deliberately NOT listed: run 3 emitted a read crossing there, and a read "
        "crossing on an item is not the write this challenge names. "
        "Collection-vs-item is the finest distinction these records support, "
        "because a finding\'s target carries no method.",
    ),
    "redirectChallenge": (
        ("/redirect",),
        '"Enforce a redirect to a page you are not supposed to redirect to." The '
        "application's only redirector is /redirect?to=.",
    ),
    "loginAdminChallenge": (
        ("/rest/user/login",),
        '"Log in with the administrator\'s user account." A login is proven at '
        "the login handler, /rest/user/login.",
    ),
    "loginJimChallenge": (
        ("/rest/user/login",),
        '"Log in with Jim\'s user account." Same handler as loginAdmin; which '
        "principal was reached is the finding's business, not the surface's.",
    ),
}


def surface_shape(url: str) -> str:
    """The PATH shape a request was dispatched against, host and query dropped.

    Three things are normalised away, each because it varies without the surface
    varying:

    * the **origin**, because one service answers under more than one name — the
      same Juice Shop container is ``clinkz-juiceshop:3000`` and ``172.20.0.2:3000``
      in one run's findings, which is why ``_origin.OriginIdentity`` exists;
    * the **query string**, because ``/redirect?to=http`` and ``/redirect`` are
      the same route;
    * an **identifier segment**, whether it arrived as a template placeholder
      (``:id``, ``:p3`` — the name is whichever discoverer found the route, so
      two spellings of one route are routine) or as the concrete value the arm
      actually sent (``/rest/basket/2``).

    Returns:
        A leading-slash path with identifier segments replaced by ``*``.
    """
    split = urllib.parse.urlsplit(url if "//" in url else f"//{url}")
    segments = []
    for segment in (split.path or "/").split("/"):
        if not segment:
            continue
        segments.append("*" if segment.startswith(":") or segment.isdigit() else segment.lower())
    return "/" + "/".join(segments)


def _assert_challenge_surfaces(challenge_index: dict[str, dict[str, Any]]) -> None:
    """A declared surface for a challenge the target does not ship is stale.

    Only this direction is an error. ``computed - declared`` is the ordinary
    case — most of Juice Shop's 113 challenges have no entry here — and it fails
    safe as an unattributable solve rather than as a build break.
    """
    stale = sorted(set(CHALLENGE_SURFACES) - set(challenge_index))
    if stale:
        raise AssertionError(
            f"CHALLENGE_SURFACES names challenge(s) this target does not ship: {stale}. "
            f"An entry that outlived what it described attributes nothing and hides "
            f"that it attributes nothing."
        )


def attribute_solves(
    solved_by_testing: list[str] | None,
    challenge_index: dict[str, dict[str, Any]],
    report: dict[str, Any],
) -> dict[str, Any]:
    """Split the solves testing earned into attributable and target-confirmed-only.

    ``solved_by_testing`` is already the honest count of what this engine's
    traffic tripped — the floor has been subtracted. It is still not a list of
    things we can SHOW a client, because a solve is the TARGET's verdict on our
    traffic and a finding is ours. Run 3 of the envelope earned three solves and
    emitted a finding for two: ``basketAccess`` (an IDOR crossing) and
    ``redirect`` (an open redirect). ``forgedFeedback`` is a write crossing that
    carries another user's ``UserId`` in a POST body — mass-assignment shaped,
    and no dispatched class claims it. A solve we cannot point at a finding for
    is not something we can tell a client we did.

    **The binding is to a FINDING, not to a class.** A solve is attributable
    when some surviving confirmed finding satisfies BOTH halves:

    1. its class is one that could claim the challenge's own category
       (:data:`CATEGORY_CLASSES`), and
    2. it was DISPATCHED against the surface the challenge names
       (:data:`CHALLENGE_SURFACES`, compared as a path shape).

    The second half is what the earlier category-only rule was missing, and the
    gap was live rather than theoretical. Run 3 emitted ``_test_idor`` findings
    at ``/rest/basket/:id`` and at ``/api/Users/:p3``; the corrected anchored
    oracle refutes the first and keeps the second, and ``basketAccess`` stayed
    "attributable" across that change because Broken Access Control maps to
    ``_test_idor`` and a sibling of the class survived. The positive reading
    outlived the finding it was actually about — an acceptance-shaped number
    standing on evidence that had been removed, which is the same failure mode
    as grading an oracle by an external scoreboard (the acceptance-criterion law
    in ``.claude/skills/clinkz-dev/SKILL.md``).

    It is still deliberately **not** called proof that a particular finding
    solved a particular challenge: nothing in either record carries the request
    that tripped the scoreboard, and inventing it would be the same
    consumer-guesses-the-producer move this codebase keeps paying for. What it
    now supports is a claim a reader can check — *this engine emitted a confirmed
    finding of a class that could account for this solve, on the surface this
    challenge is about* — and the finding is NAMED beside the solve so removing
    it removes the claim.

    A challenge with no declared surface is target-confirmed-only whatever was
    emitted. That under-reports, which is the direction that costs a number
    rather than the number's meaning, and the fix is one table entry.

    Args:
        solved_by_testing: Keys testing earned, or ``None`` when no floor
            applies. ``None`` propagates — an unmeasured floor cannot be split
            any more than it can be counted.
        challenge_index: The target's own challenge list, keyed by challenge key.
        report: The parsed ``report_<id>.json``.

    Returns:
        The split: the attributable keys, the FINDING bound to each, and the
        unattributed keys with the reason each could not be bound.
    """
    if solved_by_testing is None:
        return {
            "solved_attributable": None,
            "solved_attributable_count": None,
            "solved_attributable_evidence": None,
            "solved_target_confirmed_only": None,
            "note": (
                "No floor applies to this run, so solved_by_testing is unmeasured and "
                "there is nothing to attribute."
            ),
        }

    from clinkz.models.vuln_classes import for_finding

    _assert_category_classes()
    _assert_challenge_surfaces(challenge_index)

    # Every confirmed finding, as (class, dispatched surface shape, title, target).
    # The class comes from the producer's own title resolution and the surface
    # from the finding's own target, so neither is guessed here.
    confirmed: list[tuple[str, str, str, str]] = []
    for finding in report.get("findings", []):
        if finding.get("status") != "confirmed":
            continue
        resolved = for_finding(
            str(finding.get("title") or ""), str(finding.get("description") or "")
        )
        if resolved is None:
            continue
        target = str(finding.get("target") or "")
        confirmed.append(
            (resolved.test_method, surface_shape(target), str(finding.get("title") or ""), target)
        )

    attributable: list[str] = []
    evidence: list[dict[str, Any]] = []
    unattributed: list[dict[str, Any]] = []
    for key in sorted(solved_by_testing):
        category = str((challenge_index.get(key) or {}).get("category") or "")
        methods = set(CATEGORY_CLASSES.get(category) or ())
        declared = CHALLENGE_SURFACES.get(key)
        surfaces = set(declared[0]) if declared else set()

        of_class = [row for row in confirmed if row[0] in methods]
        bound = [row for row in of_class if row[1] in surfaces]
        if bound:
            attributable.append(key)
            evidence.append(
                {
                    "key": key,
                    "category": category or "(unknown)",
                    "challenge_surface": sorted(surfaces),
                    "surface_source": declared[1] if declared else "",
                    "findings": [
                        {"title": title, "target": target, "class": method, "surface": shape}
                        for method, shape, title, target in sorted(bound)
                    ],
                }
            )
            continue

        if not methods:
            why = "no dispatched class claims this category"
        elif not surfaces:
            why = (
                "no surface is declared for this challenge, so no finding can be bound "
                "to it; a category-level match is not evidence about this challenge "
                f"(the classes that could claim {category!r} are {sorted(methods)})"
            )
        elif not of_class:
            why = (
                "the classes that could claim this category emitted no confirmed "
                f"finding this run: {sorted(methods)}"
            )
        else:
            why = (
                f"a confirmed finding of the right class exists but none was dispatched "
                f"against this challenge's surface {sorted(surfaces)} — emitted on "
                f"{sorted({shape for _, shape, _, _ in of_class})}"
            )
        unattributed.append({"key": key, "category": category or "(unknown)", "why": why})

    return {
        "solved_attributable": attributable,
        "solved_attributable_count": len(attributable),
        "solved_attributable_evidence": evidence,
        "solved_target_confirmed_only": unattributed,
        "solved_target_confirmed_only_count": len(unattributed),
        "challenge_surfaces": {
            key: {"surfaces": list(paths), "source": source}
            for key, (paths, source) in sorted(CHALLENGE_SURFACES.items())
        },
        "attribution_rule": (
            "a solve is attributable when this run emitted a confirmed finding whose "
            "class could claim the challenge's own category AND which was dispatched "
            "against the surface that challenge names; the finding is named beside the "
            "solve, so removing it removes the claim. It is still not a claim that a "
            "particular finding solved a particular challenge — the scoreboard does not "
            "record the request that tripped it. A challenge with no declared surface is "
            "target-confirmed-only whatever was emitted."
        ),
    }


#: Above this, Juice Shop challenges stop being reachable vulnerabilities and
#: become multi-step puzzles gated on domain knowledge or out-of-band facts.
MAX_ADDRESSABLE_DIFFICULTY = 3

_TIMEOUT = 30


def fetch_challenges(base: str = BASE) -> list[dict[str, Any]]:
    """The target's own challenge list."""
    url = f"{base.rstrip('/')}/api/Challenges"
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as response:  # noqa: S310 — local lab URL
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    data = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(data, list):
        raise SystemExit(f"{url} did not return a challenge list")
    return [c for c in data if isinstance(c, dict)]


def recreate_and_verify_zero() -> list[dict[str, Any]]:
    """Recreate the container and REFUSE to continue unless the scoreboard is 0.

    A benchmark graded by a delta is only meaningful from a known start. A
    non-zero board means either a previous run's state survived or something else
    is touching the target, and in both cases the delta would attribute solves
    this engagement did not make.
    """
    print("recreating clinkz-juiceshop …", flush=True)
    subprocess.run(  # noqa: S603 — list-form, fixed argv
        [*COMPOSE, "up", "-d", "--force-recreate", "juiceshop"],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    for _ in range(90):
        try:
            challenges = fetch_challenges()
            break
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            time.sleep(2)
    else:
        raise SystemExit("FATAL: Juice Shop did not come back up after the recreate")

    solved = [c for c in challenges if c.get("solved")]
    print(f"scoreboard: {len(solved)} solved of {len(challenges)}")
    if solved:
        raise SystemExit(
            f"FATAL: the scoreboard is not zero ({len(solved)} already solved: "
            f"{', '.join(c.get('key', '?') for c in solved[:8])}). A delta from a "
            f"dirty board attributes solves this engagement did not make. Stopping."
        )
    return challenges


def addressable(challenges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """The derived addressable set, and any category the mapping does not know."""
    unknown = sorted(
        {
            str(c.get("category"))
            for c in challenges
            if c.get("category") not in CATEGORY_ADDRESSABLE
            and c.get("category") not in CATEGORY_NOT_ADDRESSABLE
        }
    )
    chosen = [
        c
        for c in challenges
        if c.get("category") in CATEGORY_ADDRESSABLE
        and int(c.get("difficulty") or 99) <= MAX_ADDRESSABLE_DIFFICULTY
    ]
    return sorted(chosen, key=lambda c: (c.get("category", ""), c.get("key", ""))), unknown


def run_engagement(
    authorization: Path,
    benchmark: Path,
    creds: Path,
    *,
    scope: Path | None = None,
    token_cap: int | None = None,
) -> tuple[str | None, int, float]:
    """Run the real pipeline against Juice Shop; return (engagement, rc, seconds).

    ``scope`` carries the :class:`EngagementWindow` — a scope-file field, not an
    authorization-record one — and ``token_cap`` bounds the LLM spend, halting
    cleanly at the cap with the report still written.
    """
    before = newest_engagement_dirs()
    started = time.time()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    argv = [
        sys.executable,
        "-m",
        "clinkz",
        "scan",
        "--target",
        BASE,
        "--authorization",
        str(authorization),
        "--benchmark-profile",
        str(benchmark),
        "--creds",
        str(creds),
    ]
    if scope is not None:
        argv += ["--scope", str(scope)]
    if token_cap:
        argv += ["--token-cap", str(token_cap)]
    proc = subprocess.run(  # noqa: S603 — list-form, operator-supplied paths
        argv,
        capture_output=True,
        text=True,
        timeout=10800,
    )
    elapsed = time.time() - started
    # Captured stdout of a whole engagement, through the engine's redaction
    # chokepoint: whatever the run printed, this file keeps.
    write_redacted_text(
        RESULTS_DIR / "engagement_stdout.txt",
        proc.stdout + "\n=== STDERR ===\n" + proc.stderr,
    )
    new = newest_engagement_dirs() - before
    engagement = max(new, key=lambda n: (OUTPUTS / n).stat().st_mtime) if new else None
    return engagement, proc.returncode, elapsed


def authentication_proof(report: dict[str, Any]) -> dict[str, Any]:
    """What the engine PROVED about the session, flattened for the write-up.

    An authenticated benchmark run whose session silently did not establish
    produces a thin report that reads exactly like a clean result, so the proof
    is a headline number here rather than a detail in the report body. The
    discriminator is the load-bearing field: the engine accepts only a boundary
    signal (login redirect, status class, login form, session marker, identity
    echo) and refuses a body-length delta, so naming which one fired is what
    separates a proven session from an assumed one.
    """
    auth = report.get("authentication") or {}
    assertion = auth.get("assertion") or {}
    return {
        "authenticated": bool(auth.get("authenticated")),
        "mechanism": auth.get("mechanism"),
        "roles": auth.get("roles") or [],
        "discriminator": assertion.get("discriminator"),
        "url": assertion.get("url"),
        "authenticated_status": assertion.get("authenticated_status"),
        "anonymous_status": assertion.get("anonymous_status"),
        "evidence": assertion.get("evidence") or [],
        "session_losses_detected": auth.get("session_losses_detected") or 0,
        "control_responses_ignored": auth.get("control_responses_ignored") or 0,
        "session_checks_performed": auth.get("session_checks_performed") or 0,
        "session_false_alarms": auth.get("session_false_alarms") or 0,
        "reauthentications": auth.get("reauthentications") or 0,
    }


def friction_log(
    report: dict[str, Any],
    *,
    returncode: int,
    disclosure: dict[str, Any],
    ledger: dict[str, Any],
) -> list[str]:
    """Everything that got in the way, DERIVED from the run's own artifacts.

    A friction log written from memory is a narrative; this one is a reading.
    Each entry names a fact the bundle records — a halt, a degraded provider, a
    truncated plan, a component that contributed nothing, a bundle the
    disclosure gate would not certify — so the operator can check every line
    against the raw files rather than take it on trust.
    """
    entries: list[str] = []
    if returncode != 0:
        entries.append(f"clinkz scan exited {returncode} (0 = completed; see the exit-code table)")

    safety = report.get("safety_summary") or {}
    if safety.get("halted"):
        entries.append(
            f"HALTED: {safety.get('halt_reason')} — {safety.get('halt_detail')}. "
            "The report was still written."
        )
    refused = int(safety.get("state_changing_refused") or 0)
    if refused:
        entries.append(
            f"{refused} state-changing request(s) refused by the safety rails "
            "(each is named in the run's action log)"
        )

    # ``provider_degraded`` lives in ``provider_degradation``, the reconciled
    # register summary. This used to read ``model_stamp``, which is a
    # ``list[dict]`` — so ``or {}`` produced ``{}`` when the key was absent and
    # ``isinstance(stamp, dict)`` was False whenever it was present. The caveat
    # was unreachable by both routes at once and has never fired in any run this
    # harness has graded, which is indistinguishable from never having been
    # written. The absent-key case is kept separate on purpose: a bundle with no
    # degradation record has not claimed to be clean.
    degradation = report.get("provider_degradation")
    if not isinstance(degradation, dict):
        entries.append(
            "provider_degradation: this bundle carries no routing record, so whether a "
            "fallback served any call is INDETERMINATE — not a clean run"
        )
    elif degradation.get("provider_degraded"):
        fallbacks = int(degradation.get("fallback_count") or 0)
        absences = int(degradation.get("absence_count") or 0)
        starved = ", ".join(str(s) for s in (degradation.get("exhausted_stages") or []))
        entries.append(
            f"provider_degraded: {fallbacks} call(s) served by a provider other than the "
            f"one asked for and {absences} served by nobody at all"
            + (f"; nothing served {starved}" if starved else "")
            + ", so this run is permanently baseline-ineligible"
        )

    # A bundle with no ledger has not reported a clean degradation account; it
    # has reported nothing. Absent and empty are the same value here and only
    # one of them is a measurement.
    if not ledger:
        entries.append(
            "component_ledger: this bundle carries none, so whether any component "
            "degraded is UNMEASURED — not clean"
        )
    for alarm in ledger.get("alarms") or []:
        entries.append(
            f"ledger {alarm.get('kind')}: {alarm.get('component')} "
            f"(invocations={alarm.get('invocations')}, "
            f"contributed={alarm.get('items_contributed')})"
        )

    alarms = report.get("plan_alarms") or {}
    dropped = int(alarms.get("dropped") or 0) if isinstance(alarms, dict) else 0
    if dropped:
        entries.append(
            f"plan cap dropped {dropped} (class, endpoint) candidate(s) — coverage "
            "bounded by the cap, not by the surface"
        )
    inversions = int(alarms.get("ranking_inversions") or 0) if isinstance(alarms, dict) else 0
    if inversions:
        entries.append(
            f"{inversions} ranking inversion(s): an ordering defect, not tail truncation"
        )

    if not disclosure.get("clean", True):
        entries.append(
            "DISCLOSURE GATE FAILED — do not share this bundle until artifact-scan is clean"
        )

    return entries


def _finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every emitted finding, flattened to what a reconciliation needs."""
    rows = []
    for finding in report.get("findings", []):
        rows.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "target": finding.get("target"),
                "status": finding.get("status"),
                "description": (str(finding.get("description") or "").replace("\n", " "))[:400],
                "evidence_head": [
                    str(e).replace("\n", " ")[:220] for e in (finding.get("evidence") or [])[:3]
                ],
            }
        )
    return rows


def record_floor_offline(engagement: str = "") -> int:
    """Derive the floor from a stored zero-dispatch run. Sends nothing.

    Reads the scoreboard snapshot this harness already wrote beside the bundle
    and the bundle's own component ledger. Offline on purpose: the observation
    that defines a floor has already been made, and re-running the engagement to
    re-make it would cost an hour and a live target for a number that is sitting
    on disk.

    Args:
        engagement: The engagement id, or empty to use whichever one
            ``scoreboard_after.json`` names.

    Returns:
        A process exit code.
    """
    snapshot_path = RESULTS_DIR / "scoreboard_after.json"
    if not snapshot_path.is_file():
        print(f"FATAL: no scoreboard snapshot at {snapshot_path}")
        return 2
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    engagement = engagement or str(snapshot.get("engagement") or "")
    if not engagement:
        print(f"FATAL: {snapshot_path} names no engagement; pass --record-floor <id>")
        return 2
    if snapshot.get("engagement") and snapshot["engagement"] != engagement:
        print(
            f"FATAL: {snapshot_path} was captured for {snapshot['engagement']}, not "
            f"{engagement}. A floor read off somebody else's scoreboard is not a "
            f"measurement of anything."
        )
        return 2

    report = read_report(engagement)
    if not report:
        print(f"FATAL: no stored report for engagement {engagement}")
        return 2
    dispatches = methodology_dispatches(report)
    credential_set = credential_set_key(report)
    starved = stamp_exhaustion(report)
    print(
        f"engagement {engagement}: "
        f"{'unmeasurable' if dispatches is None else dispatches} methodology dispatch(es), "
        f"credential set {credential_set or '(not recorded)'}, "
        f"exhausted stage(s): "
        f"{'INDETERMINATE (no model stamp)' if starved is None else ', '.join(starved) or 'none'}"
    )
    solved = sorted(snapshot.get("solved") or [])
    index = {
        str(challenge.get("key")): challenge
        for challenge in (snapshot.get("newly_solved") or [])
        if isinstance(challenge, dict)
    }
    try:
        record = record_floor(
            engagement=engagement,
            solved_keys=solved,
            dispatches=dispatches,
            challenge_index=index,
            credential_set=credential_set,
            exhausted_stages=starved,
        )
    except ValueError as exc:
        print(f"FATAL: {exc}")
        return 2
    print(
        f"floor recorded at {FLOOR_PATH} under credential set {record['credential_set']!r}: "
        f"{len(record['keys'])} challenge(s)"
    )
    for key in record["keys"]:
        print(f"  - {key}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--record-floor",
        nargs="?",
        const="",
        dest="record_floor",
        metavar="ENGAGEMENT_ID",
        help=(
            "OFFLINE. Derive the crawl-and-authenticate floor from a stored "
            "zero-dispatch run and exit, keyed to the credential set that run "
            "authenticated as. Refuses a run that dispatched anything, one whose "
            "ledger carries no methodology component (unmeasurable, not zero), one "
            "whose model stamp names an unserved stage (its crawl was not a complete "
            "crawl), one carrying no model stamp at all (indeterminate, not clean), "
            "and one whose report does not say who it logged in as."
        ),
    )
    known, _ = parser.parse_known_args()
    if known.record_floor is not None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        return record_floor_offline(known.record_floor)

    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--benchmark-profile", required=True, type=Path, dest="benchmark")
    parser.add_argument("--creds", required=True, type=Path)
    parser.add_argument(
        "--scope",
        type=Path,
        help=(
            "Scope file carrying the EngagementWindow. Without one the run is "
            "unbounded in time and the report renders that fact."
        ),
    )
    parser.add_argument(
        "--token-cap",
        type=int,
        dest="token_cap",
        help="LLM token ceiling. Halts cleanly at the cap; the report is still written.",
    )
    parser.add_argument(
        "--skip-recreate",
        action="store_true",
        help="Reuse the running container (the zero check still runs and still refuses).",
    )
    args = parser.parse_args()
    for path in (args.authorization, args.benchmark, args.creds):
        if not path.is_file():
            raise SystemExit(f"FATAL: no such file: {path}")
    if args.scope is not None and not args.scope.is_file():
        raise SystemExit(f"FATAL: no such file: {args.scope}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. known-zero start ------------------------------------------------
    if args.skip_recreate:
        challenges = fetch_challenges()
        solved_now = [c for c in challenges if c.get("solved")]
        print(f"scoreboard (no recreate): {len(solved_now)} solved of {len(challenges)}")
        if solved_now:
            raise SystemExit("FATAL: the scoreboard is not zero. Stopping.")
    else:
        challenges = recreate_and_verify_zero()

    # Both hand-maintained tables, against the live target, before an hour of
    # testing rather than after it. A stale surface entry attributes nothing and
    # looks exactly like a table that simply did not match this run.
    _assert_category_classes()
    _assert_challenge_surfaces({str(c.get("key")): c for c in challenges})

    target_set, unknown_categories = addressable(challenges)
    if unknown_categories:
        print(
            "WARNING: categories this mapping does not classify (excluded from BOTH "
            f"lists, so they are visible rather than silently dropped): {unknown_categories}"
        )
    print(
        f"addressable denominator: {len(target_set)} of {len(challenges)} "
        f"(category maps to a dispatched class AND difficulty <= "
        f"{MAX_ADDRESSABLE_DIFFICULTY})"
    )

    before_snapshot = {c.get("key") for c in challenges if c.get("solved")}
    write_redacted_json(
        RESULTS_DIR / "scoreboard_before.json",
        {
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "total_challenges": len(challenges),
            "solved_count": len(before_snapshot),
            "solved": sorted(before_snapshot),
            "addressable_count": len(target_set),
            "addressable": [
                {
                    "key": c.get("key"),
                    "name": c.get("name"),
                    "category": c.get("category"),
                    "difficulty": c.get("difficulty"),
                }
                for c in target_set
            ],
        },
    )

    # --- 2. the engagement --------------------------------------------------
    print("\nrunning the engagement (authenticated, benchmark profile ON) …", flush=True)
    engagement, rc, elapsed = run_engagement(
        args.authorization,
        args.benchmark,
        args.creds,
        scope=args.scope,
        token_cap=args.token_cap,
    )
    print(f"engagement={engagement} rc={rc} {elapsed:.0f}s")
    if engagement is None:
        raise SystemExit("FATAL: no engagement directory was produced")

    # --- 3. after snapshot + delta -----------------------------------------
    after_challenges = fetch_challenges()
    after_by_key = {c.get("key"): c for c in after_challenges if c.get("solved")}
    newly = sorted(set(after_by_key) - before_snapshot)
    write_redacted_json(
        RESULTS_DIR / "scoreboard_after.json",
        {
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "engagement": engagement,
            "total_challenges": len(after_challenges),
            "solved_count": len(after_by_key),
            "solved": sorted(after_by_key),
            "newly_solved": [
                {
                    "key": k,
                    "name": after_by_key[k].get("name"),
                    "category": after_by_key[k].get("category"),
                    "difficulty": after_by_key[k].get("difficulty"),
                }
                for k in newly
            ],
        },
    )

    report = read_report(engagement)
    findings = _finding_rows(report)
    disclosure = read_artifact_scan(engagement)
    raw_ledger = report.get("component_ledger")
    ledger_present = isinstance(raw_ledger, dict) and bool(raw_ledger)
    ledger = raw_ledger if ledger_present else {}
    auth_proof = authentication_proof(report)
    friction = friction_log(report, returncode=rc, disclosure=disclosure, ledger=ledger)

    # Every confirmed finding graded against the control arm it actually carried.
    # On this run the arms were dispatched, so NO_ARM would mean a marker-bound
    # class emitted without the control `_persist_finding` demands — a defect,
    # not the "the question was never asked" that every stored bundle returns.
    control_rows = [
        grade("juiceshop", f) for f in report.get("findings", []) if f.get("status") == "confirmed"
    ]
    control_split = {
        SURVIVES: sum(1 for r in control_rows if r.verdict == SURVIVES),
        NO_ARM: sum(1 for r in control_rows if r.verdict == NO_ARM),
        REFUSED: sum(1 for r in control_rows if r.verdict == REFUSED),
    }

    addressable_keys = {c.get("key") for c in target_set}
    solved_addressable = [k for k in newly if k in addressable_keys]
    solved_outside = [k for k in newly if k not in addressable_keys]
    missed_addressable = [c for c in target_set if c.get("key") not in after_by_key]

    # --- 3b. the floor ------------------------------------------------------
    # A challenge that a zero-dispatch run trips is not evidence about this
    # engine's exploitation. Runs 2 and 3 of the variance envelope dispatched
    # NOTHING and still solved four - errorHandling, loginAdmin, securityPolicy,
    # weakPassword - purely by authenticating and crawling. Counting those makes
    # the headline number roughly twice what testing earned.
    dispatches = methodology_dispatches(report)
    credential_set = credential_set_key(report)
    starved = stamp_exhaustion(report)
    if dispatches == 0:
        # This run IS a floor observation. Recording it here rather than in a
        # separate pass is what keeps the floor measured instead of asserted:
        # the condition that defines one is exactly the condition just observed.
        # `record_floor` still owns every refusal — a run whose providers were
        # exhausted looks exactly like a zero-dispatch run from here, and both
        # zero-dispatch runs of the 2026-08-25 envelope were that.
        print(
            f"\nThis run dispatched ZERO methodology tasks; its {len(newly)} solved "
            f"challenge(s) are a candidate crawl-and-authenticate floor for credential "
            f"set {credential_set or '(not recorded)'}."
        )
        try:
            record_floor(
                engagement=engagement,
                solved_keys=newly,
                dispatches=dispatches,
                challenge_index=after_by_key,
                credential_set=credential_set,
                exhausted_stages=starved,
            )
        except ValueError as exc:
            print(f"  NOT RECORDED: {exc}")
    floor = read_floor()
    split = subtract_floor(newly, floor, credential_set=credential_set)
    by_testing = split.get("solved_by_testing")
    attribution = attribute_solves(by_testing, after_by_key, report)
    testing_in_addressable = (
        [k for k in by_testing if k in addressable_keys] if by_testing is not None else None
    )

    # --- 4. the reconciliation ---------------------------------------------
    print("\n" + "=" * 96)
    print("AUTHENTICATION PROOF")
    print("=" * 96)
    if auth_proof["authenticated"]:
        print("  state       : PROVEN")
        print(f"  mechanism   : {auth_proof['mechanism']}")
        print(f"  roles       : {', '.join(auth_proof['roles']) or '(none)'}")
        print(
            f"  discriminator: {auth_proof['discriminator']} at {auth_proof['url']} "
            f"(authenticated HTTP {auth_proof['authenticated_status']}, "
            f"anonymous control HTTP {auth_proof['anonymous_status']})"
        )
        for line in auth_proof["evidence"]:
            print(f"      {line}")
        print(
            f"  session     : {auth_proof['session_losses_detected']} loss signal(s), "
            f"{auth_proof['control_responses_ignored']} control response(s) ignored, "
            f"{auth_proof['session_checks_performed']} verification(s), "
            f"{auth_proof['session_false_alarms']} false alarm(s), "
            f"{auth_proof['reauthentications']} re-authentication(s)"
        )
    else:
        print("  state       : NOT ESTABLISHED — this run examined only anonymous surface.")
        print("  Every miss below is confounded by that; the denominator is not comparable.")

    print("\n" + "=" * 96)
    print("TWO INDEPENDENT NUMBERS")
    print("=" * 96)
    print(f"  challenges solved (target-confirmed) : {len(newly)}")
    print(f"    of which inside the addressable set: {len(solved_addressable)}/{len(target_set)}")
    print(f"    of which outside it                : {len(solved_outside)}")
    print(
        f"  methodology tasks dispatched         : "
        f"{'unmeasurable (no methodology row in the ledger)' if dispatches is None else dispatches}"
    )
    print(f"  credential set authenticated as      : {credential_set or '(not recorded)'}")
    if starved is None:
        print(
            "  LLM stages nothing served            : INDETERMINATE (this bundle carries "
            "no model stamp) — this run is VOID as a measurement"
        )
    elif starved:
        print(
            f"  LLM stages nothing served            : {', '.join(starved)} "
            f"— this run is VOID as a measurement"
        )
    if by_testing is None:
        print(f"  solved BY TESTING                    : unknown - {split['note']}")
    else:
        print(
            f"  solved BY TESTING                    : {len(by_testing)} "
            f"({len(testing_in_addressable or [])}/{len(target_set)} addressable)"
        )
        print(
            f"    floor subtracted                   : {len(split['floor_keys'])} "
            f"({', '.join(split['floor_keys']) or 'none'})"
        )
        print(
            f"    floor measured from                : "
            f"{', '.join(split.get('floor_sources') or []) or '(unknown)'}"
        )
        # What we can SHOW, held apart from what the target merely confirmed.
        # A solve is the target's verdict on our traffic; a finding is ours.
        print(
            f"    of which a finding claims          : "
            f"{attribution['solved_attributable_count']} "
            f"({', '.join(attribution['solved_attributable']) or 'none'})"
        )
        # The finding, named. A category label cannot be checked by a reader and
        # survives the removal of the finding it stood on; a title and a
        # dispatched surface can be checked against the findings list below.
        for row in attribution["solved_attributable_evidence"] or []:
            for hit in row["findings"]:
                print(f"      {row['key']:40s} <- {hit['class']} @ {hit['surface']}")
                print(f"      {'':40s}    {hit['title']}")
        unattributed = attribution["solved_target_confirmed_only"] or []
        print(f"    target-confirmed only, unclaimed   : {len(unattributed)}")
        for row in unattributed:
            print(f"      {row['key']:40s} [{row['category']}] — {row['why']}")
    print(f"  findings emitted (engagement-reported): {len(findings)}")
    print(f"  unproven leads                        : {len(report.get('unproven_leads') or [])}")
    print(f"  research leads                        : {len(report.get('research_leads') or [])}")
    print(f"  confirmed chains                      : {len(report.get('confirmed_chains') or [])}")

    print("\nNEWLY SOLVED (the target's own verdict)")
    for key in newly:
        c = after_by_key[key]
        marker = "in-set " if key in addressable_keys else "OUT-SET"
        print(f"  + [{marker}] {key:44s} d{c.get('difficulty')} {c.get('category')}")
    if not newly:
        print("  (none)")

    print("\nFINDINGS EMITTED (to be reconciled against the above, one by one)")
    for row in findings:
        print(f"  - [{row['severity']}] {row['title']}")
        print(f"      target: {row['target']}")
        for line in row["evidence_head"][:1]:
            print(f"      proof : {line}")
    if not findings:
        print("  (none)")

    print(f"\nADDRESSABLE BUT NOT SOLVED ({len(missed_addressable)}) — each needs a stated cause")
    for c in missed_addressable:
        print(
            f"  ? {c.get('key'):44s} d{c.get('difficulty')} {c.get('category'):28s} "
            f"{str(c.get('name'))[:40]}"
        )

    print("\nCONTROL SURVIVAL — would each confirmed finding survive its own control?")
    print(
        f"  confirmed={len(control_rows)}  SURVIVES={control_split[SURVIVES]}  "
        f"NO_ARM={control_split[NO_ARM]}  REFUSED={control_split[REFUSED]}"
    )
    for row in control_rows:
        if row.verdict == SURVIVES:
            continue
        print(f"  ! [{row.verdict}] {row.title} @ {row.target}")
        print(f"      class={row.test_method}  {row.detail}")

    print(f"\nFRICTION LOG ({len(friction)} entries, each derived from the run's own artifacts)")
    for entry in friction:
        print(f"  - {entry}")
    if not friction:
        print("  (nothing: no halt, no degraded provider, no ledger alarm, no plan truncation)")

    print("\nHONESTY CONTROLS")
    print(f"  artifact scan : {'CLEAN' if disclosure.get('clean') else disclosure}")
    alarms = ledger.get("alarms") or []
    print(f"  ledger alarms : {len(alarms) if ledger_present else '?(no component ledger)'}")
    for alarm in alarms:
        print(
            f"    ! {alarm.get('component')} [{alarm.get('kind')}]: "
            f"{','.join(alarm.get('alarms') or [])} "
            f"(invocations={alarm.get('invocations')}, "
            f"contributed={alarm.get('items_contributed')})"
        )

    out = RESULTS_DIR / "reconciliation.json"
    write_redacted_json(
        out,
        {
            "engagement": engagement,
            "returncode": rc,
            "seconds": round(elapsed, 1),
            "total_challenges": len(after_challenges),
            "addressable_count": len(target_set),
            "addressable_rule": (
                "category maps to a dispatched vulnerability class AND difficulty <= "
                f"{MAX_ADDRESSABLE_DIFFICULTY}"
            ),
            "solved_total": len(newly),
            "solved_keys": newly,
            "solved_in_addressable": solved_addressable,
            "solved_outside_addressable": solved_outside,
            # The number that goes in front of a client. ``solved_total`` counts
            # everything the target marked, including what authenticating and
            # crawling trip on their own; this is what testing earned. Held
            # apart rather than replacing it, because both are true and only one
            # is a claim about this engine.
            "methodology_dispatches": dispatches,
            # Who this run authenticated as, and whether any LLM stage went
            # unserved. Both decide whether the run is a measurement at all: the
            # floor is keyed by the first, and a run with the second is void.
            # ``null`` is the third answer for the second — the bundle carries no
            # model stamp and so cannot say — and it is not the empty list.
            "credential_set": credential_set,
            "exhausted_stages": starved,
            "solved_by_testing": split.get("solved_by_testing"),
            "solved_by_testing_count": split.get("solved_by_testing_count"),
            "solved_by_testing_in_addressable": testing_in_addressable,
            # Both are true and only one is a claim about this engine. A solve
            # nothing emitted a finding for is a solve we cannot show a client
            # our work for, so it is named rather than counted.
            **attribution,
            "benchmark_floor": split,
            "missed_addressable": [
                {
                    "key": c.get("key"),
                    "name": c.get("name"),
                    "category": c.get("category"),
                    "difficulty": c.get("difficulty"),
                }
                for c in missed_addressable
            ],
            "findings_emitted": findings,
            "authentication_proof": auth_proof,
            "friction_log": friction,
            "control_survival": {
                "confirmed_graded": len(control_rows),
                **control_split,
                "non_surviving": [
                    {
                        "verdict": r.verdict,
                        "title": r.title,
                        "target": r.target,
                        "class": r.test_method,
                        "why": r.detail,
                    }
                    for r in control_rows
                    if r.verdict != SURVIVES
                ],
            },
            "unproven_leads": report.get("unproven_leads") or [],
            "artifact_scan": disclosure,
            "ledger_alarms": alarms if ledger_present else None,
            # ``null``, not ``[]``, when the bundle carries no ledger: an empty
            # list here is a measurement ("every declared component ran"), and
            # an absent ledger has made no measurement at all.
            "ledger_present": ledger_present,
            "ledger_never_invoked": (
                list(ledger.get("never_invoked") or []) if ledger_present else None
            ),
            "category_addressable": CATEGORY_ADDRESSABLE,
            "category_not_addressable": CATEGORY_NOT_ADDRESSABLE,
            "unknown_categories": unknown_categories,
        },
    )
    print(f"\nwritten: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
