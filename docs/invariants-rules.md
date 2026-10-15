# Invariants — the full rule text

Moved verbatim out of `CLAUDE.md` on 2026-10-09, when the always-loaded file
reached 96% of its Gate-4 budget. `CLAUDE.md` keeps each invariant's headline
rule; this file keeps every clause, numbered identically. The incident behind
each rule is in [`invariants.md`](invariants.md). A `Detail →` pointer names a
path under the repo root.

**The rule is here; the incident that produced it is in `docs/invariants.md`,
same order, same numbering.** Read the detail when you are about to change the
code an invariant governs — not by default. A `Detail →` pointer names a path
under the repo root; the header table at the top of this file links them all.

1. **Deterministic steps + LLM checkpoints**; no free-form ReAct.
2. **Orchestrator-mediated comms** — agents never talk directly. The router is the
   deterministic phase sequence, NOT an LLM: `_handle_query`'s `RESPIN_*` branch
   has never fired, and `MAX_CROSS_PHASE_RESPINS` bounds a path nothing reaches.
3. **Agents are spun up/down on demand**, in the order the phase shape declares.
4. **Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a
   tool name or direct import.
5. **LLM-agnostic + per-agent providers** — never import a provider SDK outside
   `llm/`. Anthropic is priority 1 for every call on every phase; a discovered key
   confers *availability*, never a position.
6. **A fallback is a disqualifying event, and on an emit or suppress path it is
   refused outright — in BOTH run modes** (`llm/call_purpose.py`). A stamp can
   disclose reduced coverage; it cannot disclose a finding that was suppressed.
   Every call site declares its purpose; an unclassified one is a red build.
7. **A run where NOTHING answered is not a clean run** (`llm/degradation.py`).
   Three kinds degrade — `SUBSTITUTION`, `TERMINAL_EXCLUSION`, `CHAIN_EXHAUSTED`;
   `baseline_eligible` FOLLOWS `degraded` rather than re-deriving it. Two
   witnesses: the register, and `model_stamp` for a STORED bundle.
8. **A report about a run that did not happen must say so** — `run_completed` /
   `incomplete_reason`; incomplete + zero findings rates **`Not assessed`**, never
   "Informational", which is a verdict about the target.
9. **A capability lost to routing is STATED, never absorbed.** Research grounding
   is declared by the producer, reported as the WEAKEST any call ran under,
   carried on every runbook entry, and rendered either way. `undeclared` counts as
   ungrounded.
10. **A section that reads one field and contradicts the document's own contents
    is worse than a missing section** (`agents/_report_integrity.py`). Every
    reconciliation is pure, reads only engine-declared fields, only ever TIGHTENS,
    and runs at BOTH the build and render seams. **Detail →
    `docs/report-integrity.md`.**
11. **A session the engine GUESSED is still a session, and the record has to say
    so** — swept credentials file under `SWEPT_CREDENTIAL_ROLE`; `established`
    stays False, because holding session material and having PROVEN a session are
    different facts.
12. **A class the never-sent rule does not bind is not a class with no control —
    it is a class whose control is a DIFFERENT rule, and the row names it**
    (`VulnClass.control_arm.governing_rule` + `evidence_key`).
13. **An IDOR finding proves attribution with NAMES and FINGERPRINTS, never
    values.** The field NAME survives because it is schema, not data.
14. **A bound that decides coverage is reported in the DELIVERABLE, not just the
    log** (`observability/plan_alarms.py`). Truncation and ranking inversions stay
    separate numbers with separate renderings because they have different fixes;
    `kept_breakdown_present` is consulted FIRST, ahead of every benign branch.
15. **The crawl's enrichment budget is that same bound, one layer earlier**
    (`CrawlBudgetTruncation`) — rendered on a clean run too. One href is one
    candidate (`crawl_dedup_key`).
16. **Crawl-safety / session hygiene** — `is_state_changing_url` guards every
    crawl visit, endpoint emission and plan entry; `is_destructive_form_submission`
    guards every submit. **A probe never destroys target state**, and a field the
    methodology did not intend to set is omitted, never sent empty-but-present.
17. **A new injection *shape* gets a DEDICATED carrier**; leave the shared
    string-only `_send_probe` untouched.
18. **How a class READS the target is not the class's business** — a form-shaped
    class reads `_injectable_forms`, a probing class carries through `_send_probe`,
    never the raw layer beneath (`page.forms` is `[]` on any framework target).
    Enforced by an AST guard. `_test_javascript_attacks` is the one that does not
    migrate, and says why.
19. **An upload point is declared by a protocol artifact, never by a URL that
    sounds like one** — a declared `multipart/*` content type plus an
    upload-shaped field name.
20. **A body field is a PATH, not a name** (`agents/_json_body.py`). Only leaves
    are written and **every sibling keeps a benign value** — a rejected request
    never reaches the sink.
21. **Surface mapping never writes to the target.** Every API schema learner takes
    a probe restricted to `GET`/`HEAD`/`OPTIONS`, asserted at the seam.
22. **Stack-conditioned branches** are backed by a deterministic protocol artifact
    — never the flaky LLM tech list alone (LESSONS #28).
23. **P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES**
    (`src/clinkz/browser/`). Everything the page authors is evidence, never a
    verdict input. **A missing browser costs coverage, never honesty** — there is
    no path from a P7 verdict to demoting or suppressing anything. **Detail →
    `docs/methodology/client-side-execution-p7.md`.**
24. **An oracle must observe from a machine that can REACH the target.** The
    browser runtime is tied to `TOOL_EXEC_MODE`, never configured separately, so
    the one combination that silently fails every navigation cannot be selected.
25. **A browser is a new destructive surface, and its rails are structural** —
    scope before launch, the governor authorizes, every navigation logged. A safe
    method is not automatically safe. Nothing is clicked, filled or submitted.
26. **Deterministic skills as contracts** — if the vuln is present, the `_test_*`
    method MUST find it. **Never write an observation into evidence that was not
    made**; an unwitnessed effect is an `UnprovenExploitLead`.
27. **No marker oracle confirms without a dispatched control arm that REFUSED**
    (`agents/_control_arm.py`). The control must **round-trip like the payload**.
    `MARKER_ORACLE_CLASSES` / `DIFFERENTIAL_CONTROL_CLASSES` /
    `CONTROL_EXEMPT_CLASSES` partition every dispatchable class; an unclassified
    one is a red build. **Detail →
    `docs/methodology/never-sent-control.md`.**
28. **Every kill discloses, wherever it happens** — the lead is written inside
    `_run_control_arm`, the one seam every arm passes, so a class cannot forget
    because a class does not do it. The lead says the class could not PROVE the
    vulnerability, never that the endpoint is clean.
29. **The arm's lookup key is DECLARED by the emitting site, never re-derived.** A
    miss while a sibling arm exists on the same `(test_method, endpoint)` is a
    traced `control_arm_key_mismatch` that still refuses.
30. **An oracle confirms on its class's DEFINING effect, and the arm is what
    proves it does.** **Detail →
    `docs/methodology/defining-effect-oracles.md`.**
31. **Whose object is this? is a relation, not a property of a response** —
    four dispatched arms (`self` / `crossing` / `nonexistent` / `anonymous`) plus
    B's own authorized read. The control round-trips like the payload. Reflection
    is deliberately NOT covered by it and keeps its own guard. **Detail →
    `docs/methodology/idor.md`.**
32. **A class that needs two identities declares it in the registry, and the code
    READS the declaration** (`MultiPrincipalRequirement`). Tier 1 multi-role MAY
    CONFIRM; Tier 2 single-role MAY ONLY LEAD. A limitation only the report knows
    about is a disclaimer.
33. **`ref(A)` is a reference the CALLER owns, or the class abstains — and
    attribution comes off the OBJECT, never off a comparison.** `ref(A)` is
    DISCOVERED by probing as A; unanchorable ⇒ ABSTAIN. The claim rests on an
    OWNING FIELD; no owning field ⇒ ABSTAIN.
34. **An anonymous 200 on `ref(B)` is DISQUALIFYING, full stop.** An arm never
    DISPATCHED refused nothing and abstains.
35. **An acceptance test that reads only an external grader cannot detect an
    oracle that reached the right verdict by the wrong arm.** The criterion must
    assert the ARMS — which request went out, as whom, carrying what.
36. **A crossing arm is evidence only when it runs UPHILL, and which way is up is
    the operator's to declare.** A is the LEAST privileged identity; rank is
    DECLARED (`privilege`), never inferred from a role LABEL. Undeclared bounds
    the verdict to a lead (ground 10).
37. **A request carries the ENGAGEMENT's session, a NAMED principal's, or none —
    one field, three values** (`session_mode`). Only an `ambient` response is
    `session_bearing`. `_as_principal` is not re-entrant.
38. **A control arm's outcome is the PROOF, so a consumer must know WHICH arm it
    read.** The producer declares (`VulnClass.control_arm`); a guard reads only
    what the engine declared, never the `Response:` entry the host controls.
39. **An observation must be attributable to the payload that produced it.**
40. **A deterministic guard whose value is that it needs no model is never gated
    by one.** All **ten** grounds run unconditionally at `_persist_finding`. An
    LLM can no longer suppress anything the code did not already suppress, and
    every ground's `why_unconfirmed` must be in `UNPROVEN_WHY_UNCONFIRMED`.
41. **Silence from a detection path is not evidence of cleanliness.** A review
    that ANSWERED and named nothing is `correctly_empty`; one that never ran is
    `ALL_FAILED`. Both control-flow exceptions are `BaseException`; they differ in
    *who* catches them, not in whether anyone can.
42. **Suppress, never annotate** — a believed false positive is **demoted**, never
    emitted as confirmed carrying a caveat. Four shapes can never confirm: a
    conditional execution claim, a reflection inside a framework error page, a
    check that determines it is not applicable, and a description of a client-side
    control.
43. **One engagement is one target state, so a confirmation SUPERSEDES its lead.**
    Directional: a witnessed effect outranks the absence of one, and there is no
    path by which a lead suppresses a finding.
44. **The suppression runs the same direction as emission: an LLM never overrules
    a deterministic oracle.** The FP cross-check may demote ONLY by naming a
    deterministic contradiction the code itself verified.
45. **A veto that reads the model's PROSE applies only to an effect nobody
    witnessed.** Phase 5 records `literal_landing_witnessed`; a skipped veto is
    logged and traced.
46. **An execution-type branch is a CLAIM, and it confirms only on the observation
    that proves ITS effect.** A branch that cannot prove its effect must never
    pre-empt one that can.
47. **A thin-but-real measurement carries its own control** — a differential is
    proof when it is *reproducible*, not when it is large. Strengthen the proof
    rather than loosen the gate.
48. **Attack the handler, not the listing** — decided on **what came back**, never
    on the path.
49. **A deterministic observation gates the LLM's list, not just its verdict**,
    and severity is recomputed from the surviving set.
50. **A class whose input is fully observed asks no model, and a baseline carries
    the model that produced it.** `security_headers` phase 3 is deterministic end
    to end, asserted on the CALL. Ladder invariance is pinned on fixed
    observations, **and** the shared verdict is pinned.
51. **Coverage truncation is never silent** — per class, how many candidates were
    dropped and the first omitted endpoint; every applicable class is guaranteed
    one task before the cap. A drop on an endpoint carrying the class's **own**
    surface is a separate **RANKING FAILURE**.
52. **A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound on
    it is the fingerprint too** (`agents/_plan_ranking.py`). A ranking returns the
    order AND `supported`; `attempt_window` never truncates a supported type. The
    tail is never empty. **Detail →
    `docs/methodology/plan-ranking.md`.**
53. **The plan order is a function of the endpoint SET, never of the crawl's
    order** — a concurrent crawler emits a different sequence each run. Ties break
    on structural identity, never traversal order.
54. **`verification_strength` decides emission, and it is a closed vocabulary** —
    classified explicitly in both directions; a test fails on any unclassified
    literal.
55. **A guard never parses text the target controls.** A suppression primitive
    handed to the target is worse than the phantom the guard prevents.
56. **Persistent KB feedback loop (Layer-2)** — YES-only, a decayed corroboration
    prior that never gates emission.
57. **A CVE match on a version string is a LEAD, never a finding**
    (`knowledge/component_cves.py`). **Affected ranges are half-open**
    `[introduced, fixed)`, pinned as PROPERTIES over a generated universe.
    **Provenance gates the CLAIM, never the TEST.** A match becomes an
    `ExploitTask` for a class whose oracle can witness that effect, or an
    `UnprovenExploitLead`. A third outcome does not exist.
58. **The fourth plan source RESERVES its slots, and spends them by version
    provenance.** A run that matched no CVE reserves zero and plans
    byte-identically. Provenance is declared by the PRODUCER
    (`VersionProvenance`), ordered ahead of published severity.
59. **A plan source that gets no slots must still say so** — the tier-2/3 research
    source is always computed and its candidates join the truncation buckets.
60. **The PRODUCER declares what it fingerprinted, too** (`detected_components()`
    / `declares_components()`). A non-declaring wrapper is a loud `DEAD_SEAM`.
61. **A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the
    resolver reads the declared ORDER.**
62. **Resolving is not the same as being used, and an unused capability states its
    reason** — verified against the source so it cannot become documentation of a
    wish.
63. **One origin fence** (`agents/_origin.py`) — the host comparison is the
    obvious half, and each new call site re-derives only the obvious half.
64. **"Is this the same string" is the right question for a FENCE and the wrong
    one for a finding's IDENTITY** (`OriginIdentity`). The alias is OBSERVED,
    never inferred; **name-based virtual hosting fails SAFE**, because
    over-merging HIDES a finding and emitting one twice does not.
65. **A phase stopped at its own wall clock is not a run that did not happen.** A
    timeout WITH a result did its work; a timeout with NOTHING still trips the
    banner. **A banner that fires on a third of good runs is one a reader learns
    to skip.**
66. **A mock at a tool or parser seam returns the REAL output model.** A test that
    can only pass against a fiction is worse than no test, because it is counted
    as coverage.
67. **A guard's DOMAIN is computed from the same source of truth as the thing it
    guards; only the CLASSIFICATION is hand-maintained.** Both directions are
    asserted; an exemption is an allow-list entry with a substantive reason, never
    a silent skip. **And the domain is over the CALL whenever the property is a
    property of the call** — a control that is an optional parameter with a
    permissive default makes an oracle only as controlled as its least careful
    caller, and no domain computed over callee bodies can see a caller. **Detail →
    `.claude/skills/clinkz-dev/SKILL.md`.**
68. **Two confirmed findings do not imply the chain between them, and neither does
    a successful second request.** A carriage is proven against a decoy the target
    never issued. Decoy accepted too ⇒ a `ChainResearchLead`, never a finding with
    a caveat.
69. **A yield is what a class's confirmation PROVES, never what the class is named
    after** (`chaining/vocabulary.py::NO_YIELD_REASON`). The carried VALUE is
    excluded from serialisation.
70. **Business-logic intent must be EVIDENCED from the application's own surface**
    — unevidenced ⇒ a lead. **The status code is never the effect** — the
    read-back is.
71. **The destructive refusal is the contract, and the benchmark profile does not
    loosen it.** **Session destruction, security-posture toggles and
    cross-principal writes are never permittable on any target** — they damage
    the ENGAGEMENT, not the target.
72. **A total is not evidence about its parts** (`observability/ledger.py`). Four
    alarm classes stay apart because they have different fixes; *declared but
    never invoked* is tracked separately. **Absent by default**, and it never
    raises from the data path. **Detail →
    `docs/observability.md`.**
73. **A benchmark number a client sees must be what TESTING earned.** The floor is
    **measured, never declared**, KEYED by credential set, and no floor ⇒
    `solved_by_testing: null`, not zero. **A solve binds to a FINDING, not to a
    class** — a positive reading that outlives its own evidence is a phantom
    wearing a category label.
74. **A batch is unattended, so a credit lapse must stop it rather than fill it**
    (`scripts/three_run_envelope.py`). A terminal account state refuses the batch;
    an unserved stage ends it. **A metric no run REPORTED is `null`, not zero.**
75. **A recon component that RAISED must not look like a target with nothing to
    find.** Every `except` inside a component-bearing method must reach the ledger
    or carry an allow-list entry with its reason.
76. **A ledger VIEW is not a second population.** The distinction decides whether
    a consumer may SUM.
77. **"Correctly found nothing" is a fifth fact, and it is NOT an alarm.** The
    claim must be **falsifiable, never a self-assessment** — candidates found and
    none emitted is the ffuf shape and stays SILENT. **A permanent false alarm
    trains an operator to skim the section where a real one will appear.**
78. **A component the ledger never hears from is not measurable, so every
    component is DECLARED at engagement start**
    (`observability/component_registry.py`), over three **computed** domains plus
    one declared half held to a bidirectional AST assertion. Methodology `items`
    count DISPATCHES, not findings.
79. **"Declared and never invoked" has two opposite readings, so reachability is a
    COMPUTED PREDICATE and its TIMING is split from the declaration's.** Existence
    is knowable at engagement start; reachability is not. No predicate declarable
    ⇒ a build failure, not a runtime branch.
80. **A predicate may only be evaluated against a producer that SPOKE, so there is
    a FOURTH state: NOT DETERMINED.** A counter left at its default is
    byte-identical to one a producer set to zero. The gate is per-PREDICATE, not
    per-run, and is reconciled against the run-completion banner.
81. **The prompt cache is a ledger component like any other, because it degraded
    exactly like one** — invoked every run, succeeded every time, contributed
    zero. **OFF by default by measurement.** **A ledger where an alarm always
    fires teaches the operator to stop reading it.**
82. **A consumer never guesses a producer's field names.** Never
    `getattr(parsed, "field", default)` over a model — the default is what turns a
    typo into a permanently dead capability. **A mock mirrors the real model's
    contract**, never the consumer's assumption about it.
83. **A parser never assumes it owns the process's stdout, and the fixture must be
    the bytes the tool WRITES.** Whole-blob `json.loads` is correct ONLY for JSON
    the wrapper itself serialised; every parser declares which case it is.
84. **An auth bypass is a defining effect no injection oracle can see, so it gets
    its own indicator** (`agents/_auth_bypass.py`). Three arms; **never
    200-plus-a-cookie**. The identity suppression keys on credential POSSESSION,
    not identity coincidence. **Detail →
    `docs/methodology/auth-bypass.md`.**
85. **Execution traces** — each engagement writes `outputs/<id>/trace.jsonl`.
    `outputs/` is local-only by policy — never committed.
86. **Naming an oracle is half a claim; the other half is whether we can DELIVER
    the CVE's input to it** (`KnownComponentCVE.vector`, `CARRIABLE_VECTORS`).
    Lead-only is declared at WRITE time; three lead reasons, never merged; **Band
    C** is permanently lead-only. **Detail →
    `docs/methodology/sca-catalogue-breadth.md`.**
87. **When the payload's effect outlives the request, the CONTROL runs first**
    (`_run_control_arm_first`) — a control dispatched afterwards observes the change
    the payload made and kills the true positive it exists to license. The seam owns
    the order, not the class; write crossings hit the same constraint.
88. **A class whose effect outlives the RUN is TERMINAL, dispatched last, and a
    transient task after one is a stop-the-run condition**
    (`TERMINAL_DISPATCH_CLASSES` / `TRANSIENT_DISPATCH_CLASSES`;
    `assert_terminal_dispatch_order`). A wildcard authorization does not cover a
    terminal class; among them the order is the table's DECLARATION order.
    **Terminals DRAIN, they do not rotate** — rotation interleaves them by
    construction, so the tail narrows to ONE class until its queue is empty
    (`terminal_drain_order`). **Being last is what starves them, so they RESERVE
    plan slots in pass 0** — a floor, never a ceiling.
89. **A change TESTING made that the target cannot undo is stated in the
    client-facing document, naming the key** (`ResidualMutation`) — recorded on the
    WITNESSED effect, on every landed write whichever arm made it. **Detail →
    `docs/methodology/prototype-pollution.md`.**
90. **A write is a crossing when a SEPARATE read attributes the persisted object
    to another principal** (`agents/_write_crossing.py`) — never the status code,
    never the create's own body. Six probes in a DECLARED order, asserted on what
    was dispatched; every precondition ABSTAINS with nothing sent;
    `CATEGORY_CROSS_PRINCIPAL_WRITE` is never-overridable. **Detail →
    `docs/methodology/write-crossings.md`.**
91. **"The POST set no cookie" has TWO causes and a boolean collapses them** —
    an empty `Set-Cookie` delta beside a non-empty carried jar is `INDETERMINATE`
    (`LoginVerdict`) and DEFERS to `assert_authenticated`, bounded by
    `_session_survived`. A cookie the server issues to ANY caller is not evidence
    about a credential, and a guessed one may not ride the deferral. **A login
    declared failed names the evidence that was ABSENT and never asserts the
    credentials were wrong.** **Detail →
    `docs/methodology/authentication-shapes.md`.**
92. **A credential POST is bounded by the component that can see it, and the stop
    the TARGET declares outranks the budget WE assumed.** The governor slot is taken
    at each credential POST, which NAMES the account
    (`SafetyPolicy.max_credential_attempts_per_account`, default 8, keyed on
    origin+account). `safety/lockout.py` is the one lockout vocabulary; the sweep
    stops on the first evidence for ANY account. **Detail →
    `docs/methodology/credential-attempts-and-lockout.md`.**

93. **An absence that holds only up to N is reported WITH N, and N is ours**
    (`attempt_ceiling`). Title, description and evidence each name it, and the class
    may never render as "no protection exists". **A flag that cannot take its other
    value where it is read is a comment** — replaced by `BruteForceEmissionError`.
    **Detail → `docs/methodology/brute-force.md`.**

94. **A verdict rule with no correct live firing is a dead instrument, and the
    corpus decides which.** Every `_login_verdict` rule is replayable over stored
    curl dumps; the authenticated-page-marker rule fired 4 times in 762 POSTs, all
    four wrong — deleted. A zero meaning *not yet reachable here* gets a fixture.
    **Detail → `docs/methodology/authentication-shapes.md`.**

95. **A measurement that refused itself is not a clean result, and a truncated
    sweep is not a negative.** An `INCONCLUSIVE` series RAN, so it is declared
    (`InconclusiveMeasurement`) and rendered; a sweep the target stopped names that
    it stopped, why, and the pairs never sent — **by account and technology, never
    by password**, which was never registered for redaction.

96. **A bound the budget cannot SEE bounds nothing, so every credential sender is
    classified.** The per-account budget is spent only where an account is NAMED
    (`credential_account`, assigned once). `_test_brute_force` is EXEMPT
    deliberately, and the exemption is DECLARED over an AST-computed domain, because
    literal dict keys cannot see the variable-keyed loop that sends the most.
    **Detail →
    `docs/methodology/credential-attempts-and-lockout.md`.**

97. **A scope entry that names a port BINDS that port**
    (`models/scope.py::declared_port` / `_port_binds`). Only a port the operator
    TYPED binds; a dispatch naming no port is decided by host; the docker
    published-port match crosses a namespace and is a named exemption. A refusal
    NAMES which half refused (`refusal_reason`). **Detail →
    `docs/productization-engagement-safety.md`.**

98. **The authentication path gets the control arm the exploit path already
    has.** `_login_verdict` and `classify_lockout` both take a `control_body`, and a
    marker present in BOTH is discarded and NAMED. **Session material outranks a
    keyword**, and **identical byte length is its own verdict**, ahead of the
    INDETERMINATE deferral. The domain of every marker oracle is COMPUTED and
    classified. **Detail →
    `docs/methodology/authentication-shapes.md`.**

99. **A remedy the run's own observations contradict is worse than no remedy.**
    The deterministic pass carries its three login-page facts on `AuthResult`
    (`deterministic_observations()`), and the abort message drops "the credentials
    are wrong" whenever the POST demonstrably changed nothing.

100. **A marker that survives an UNBLOCKED response is the application's own
    vocabulary, not evidence of blocking** (`safety/governor.py`). The body arm
    takes a control that costs no dispatch and NAMES what it discarded; **status
    outranks keyword**; learning runs BEFORE the verdict. **A halt is an
    ABSENCE-GENERATING event** — the halt detail says the classes downstream are
    UNTESTED, not clean.

101. **A zero measured over PART of the input is INDETERMINATE, never NOT
    APPLICABLE** (`agents/_package_identity.py`). The denominator is measured before
    truncation, `indeterminate_reason` is consulted AHEAD of both benign branches,
    and `coverage_note` renders on a clean run too.

102. **A destination composed at runtime is not a reading problem, so the model
    PROPOSES and `assert_authenticated` DECIDES** (`engagement/auth_agent.py`),
    from two call sites both guarded by "no session was seated". **The model names
    FIELDS; the engine supplies every VALUE.** Eleven deterministic refusals gate every
    proposal; the episode carries its OWN jar, keyed by origin; an abstention names
    what was ABSENT. **The disclosure renders on a clean run too**, naming which
    layer seated the session. **Detail →
    `docs/methodology/adaptive-authentication.md`.**

103. **Session material has TWO carriers, and the response declares which** — a
    `Set-Cookie` or a body token (`DispatchResponse.session_headers`). A carrier
    the loop does not present is a session the oracle is told does not exist, and
    a token is redacted at the site that read it out by NAME, never left to shape
    matching. **A failure to obtain a model answer is three failures** —
    unreachable, CUT OFF (`stop_reason` the provider DECLARED, never inferred),
    and answered-but-unusable; only the last is a statement about the target.
    **Detail → `docs/methodology/adaptive-authentication.md`.**

104. **A gate refuses to grade evidence it does not hold, and an absent
    measurement is never a permissive one.** Every evidence parameter of a shared
    gate is three-state with NO default, because the two absences fail in
    OPPOSITE directions: an empty body disables a veto outright, while a `False`
    measurement licenses one about an effect nobody asked about. `None` is
    "this class does not hold this" and it REFUSES. A gate presented as shared
    that applies three of its four conditions to one of its three callers is
    grading on a default.

105. **A tool execution that leaves no invocation record is an unauditable run,
    and every execution mode is asserted to emit** (`tools/base.py::_emit_trace_records`
    / `_emit_inprocess_invocation`). The domain is COMPUTED from
    `config.TOOL_EXEC_MODES`; a mode that emits nothing is a red build, not a
    quiet gap. `transport` is declared with NO default and every reader branches
    on it — `--replay` refuses an in-process record, and the corpus parser does
    not hand an envelope to the curl parser. **Zero records beside non-zero
    executions is INDETERMINATE** (`observability/audit.py`), withdrawing
    `baseline_eligible` at the build and BOTH render seams, one-way. **Detail →
    `docs/observability.md`.**

106. **A bound that selects by SPELLING lets the alphabet decide coverage**
    (`agents/_api_schema.py::_select_routes`). Surface-mapping sweeps order by
    `crawl_visit_priority` and tie-break on the route, so no bundle set of any size
    displaces an application route; the drop is disclosed by relevance grade, and
    *truncated* stays a separate number from *ordering_failure* because a larger
    budget fixes only the first. The domain is every bounded slice over a `sorted()`
    result, AST-computed. **Detail → `docs/analysis/probe-bound-ordering.md`.**

107. **Registered, dispatched, and never able to begin is its own state.** A
    business-logic class that cannot evidence the application's intent declares an
    `InconclusiveMeasurement` — not a lead (it suspects nothing) and not
    `not_applicable` (the endpoint may well carry the rule). 164 dispatches across
    the corpus reached no verdict and said nothing. **Detail →
    `docs/analysis/business-logic-verdict-trace.md`.**

108. **A transformation applied to a whole structure distinguishes the
    structure's own vocabulary from the content it carries** — a KEY is schema, a
    value is data, and a walk that never asked has answered "content"
    (`engagement/secrets.py::_redact_key`). A key is rewritten only when a
    SINGLE redaction consumed it end to end; two registrations that TILE a key
    COLLIDE two fields into one. The domain is every recursive container walk,
    AST-computed, and exactly one member may rewrite keys. **A guard that damages
    the artifact it protects protects nothing**, and its positive control must
    exercise the real seam — `model_dump → redact → model_validate` over the
    model's OWN declared vocabulary, never a hand-picked key. **Detail →
    `.claude/skills/clinkz-dev/SKILL.md` §7.**

109. **A gate that needs evidence only passing the gate can produce is its own
    state — UNREACHABLE PRECONDITION, not unexercised and not not-applicable.**
    The domain is computed from precondition SOURCES: an attribute a gate reads
    whose every informative writer is downstream of a gate; an `= []` initialiser
    is an absence, not a source. The disclosure names WHOSE limit it is — a class
    that cannot begin is a capability the engine lacks, never a reading of the
    endpoint. **Detail → `docs/analysis/register.md` R13.**

110. **A registration is scoped to WHERE the secret can appear.** A swept guess
    is armed for its attempt and released when it fails (`provisional_secret`);
    one that WORKS is kept. The registry is COUNTED, so one source's release
    cannot disarm another's. The closed vocabulary the ENGINE declares is schema
    in a VALUE's position too, matched EXACTLY: containment would hand the target
    a suppression primitive. *Amended 2026-10-09 (register R30):* a credential
    that spells the engine's own schema is no longer refused at intake — the
    refusal existed only because redaction was a substring replacement, and
    invariant 119 retired that. **Detail → `.claude/skills/clinkz-dev/SKILL.md`
    §7, `docs/analysis/register.md` R14, R30.**

111. **A verb the engine could not READ is its own state, never a GET it
    measured** (`models/scan.py::MethodEvidence`; `NAMED` / `PLATFORM_DEFAULT` /
    `UNREAD`). `_applicable_methods_for_endpoint` is the ONLY producer of seven
    Tier-1 classes' buckets and it gates on the verb, so a `GET` standing in for
    an absence does not lower an endpoint's rank — it removes it. `UNREAD` never
    admits an endpoint to a write class; it gets the route ASKED (unread first
    in the `OPTIONS` sweep, **within its relevance grade**) and the gap
    DISCLOSED, on a clean run too. Every `Endpoint` producer declares, over an
    AST-computed domain. **Detail →
    `docs/analysis/spa-write-surface-blocker.md` §6.**

112. **A call site we SAW and could not address is a third state, and a route the
    source DECLARES is a different fact from a call it MAKES.** `MiningResult`
    carries resolved calls, `UnresolvedCallSite`s (three reasons; `naming_a_write`
    first) and `route_declarations` separately. The disclosure's domain is calls
    HTTP by the CALLEE's name or a config argument's SHAPE — `map.get(k)` is not
    one. **The guard that keeps prose out is a POSITIVE shape test, never a
    string-literal pre-pass**: quote-counting is unsound on minified JS and hid 30
    of 88 readable call sites. A `{path, method}` manifest entry is held to the
    call site's bar and claims NO body. **Detail →
    `docs/analysis/spa-write-surface-blocker.md` §7.**

113. **The target may not author the structure of the document that judges it**
    (`engagement/render_safety.py`). Neutralised at the PRODUCER — one pass at the
    report seam, so all **180** Markdown sites and every future sink inherit it;
    `_report_pdf`'s sink-side escaping stays a floor, because a sink-side fix is a
    guard whose domain is every future sink. **Keys untouched, and the JSON
    artifact untouched** — JSON encoding is already the guard and those bytes are
    what the replay drivers read. An inline value loses its line breaks; the one
    declared BLOCK field keeps them and its fence ADAPTS, so no content can close
    it. `ActionRecord` neutralises at construction: `clinkz actions` prints a
    target-chosen URL to a terminal, where an erase-line sequence scrolls the
    REFUSED rows off it. **Detail → `docs/analysis/register.md` R18.**

114. **A pattern-based exclusion fails toward LESS output, so it needs a
    DENOMINATOR control, not a shape control.** A quote-counting pre-pass hid 30 of
    88 call sites and read as a cleaner target. A shape control proves the pattern
    handles the case you thought of; only a count against an independently-known
    total proves it has not stopped handling the rest. **Detail →
    `docs/analysis/register.md` R20.**

115. **A regression check compares SETS, not counts** — every pair a baseline
    CONFIRMED must be PLANNED later, else `truncated`/`absent`; no record ⇒ NOT
    DETERMINED. **And NOT DETERMINED stays rare:** when the exploit agent never
    planned (never dispatched, raised, stopped first), the orchestrator writes an
    EMPTY plan-set record naming why (`unplanned_reason`), which a comparison can
    grade — an empty plan is a fact, a missing one is not. **Detail → `docs/analysis/r29-write-crossing-candidate-set.md`.**

116. **A session the operator SUPPLIED is proven by the same assertion and never trusted**
    (`RoleCredential.session`). Session-only ⇒ no credential is sent; an expiry
    mid-run HALTS (`supplied_session_expired`), because nothing renews it.
    **Detail → `docs/productization-engagement-safety.md`.**

117. **A credential goes only to a destination something OBSERVED to be a login** —
    a rendered password form's action, an operator declaration, or a route the
    adaptive layer proved. No base-URL fallback, no route list; an unobserved page
    is READ, never posted to (`no_login_surface`). Computed over every call into a
    credential sender (`test_credential_destination_domain.py`). **Detail →
    `docs/productization-engagement-safety.md`.**

118. **"The credentials are wrong" requires a refusal ATTRIBUTABLE to the
    credential** (`credential_refused`: a 401, or a marker the control lacks), and
    quotes it. Otherwise the abort names what was seen — no login surface, a POST
    that changed nothing, an off-scope sign-in, MFA, captcha, lockout.

119. **Redaction is decided by PROVENANCE, per occurrence, and fails closed**
    (`engagement/secret_provenance.py`; register R30). A registered value is the
    secret where the engine PLACED it — the value of a credential-named field,
    exact — and is redacted there unconditionally. It is NOT the secret inside a
    longer identifier (`password_new`), in a NAME position whose spelling a
    declared field or the engine's source uses, as a URL host label, as an HTML
    `type=` keyword, inside engine-authored source text, or in a unit the target
    served to a request that did not carry it (`observe_control`: the login GET
    and every `session_mode='none'` response). Anything no rule claims is
    redacted. An echo — a unit the anonymous target never produced — stays
    redacted, and its positive control is red with the default removed. A key is
    rewritten only by a shape, or when it IS a registered value nobody's schema
    spells. **Detail → `docs/analysis/register.md` R30.**

120. **The disclosure gate claims only what it checks, and the record's integrity is
    a second verdict** (`engagement/artifact_scan.py::scan_integrity`). CLEAN means
    no credential shape escaped and nothing went unread; it never meant the bundle
    is still the record of the run. A redaction marker where a value cannot be —
    glued to an identifier, as an HTML `type=` keyword, in a NAME position, as a
    URL host — makes the bundle CORRUPTED and NOT CERTIFIABLE whatever the leak
    check says, read off the bytes and never off the redactor. Exit 5 covers both;
    both verdicts are stated on every summary line. `e7bd146a` is the positive
    control (CLEAN, 1,134 sites CORRUPTED). **Detail → `docs/analysis/register.md`
    R30.**

121. **A session token is found by the response's STRUCTURE, and the adaptive
    layer's model sees a READ's SHAPE, never its text**
    (`engagement/token_locator.py`). A JWT by form, or a value under a
    token-naming key, at any depth; a refresh token is never the bearer; no
    benchmark's nesting appears in any list. The shape-only READ is an injection
    boundary, not a gap: the model's answer chooses where a credential goes, so
    target-authored text may not be in its prompt. **Detail →
    `docs/methodology/adaptive-authentication.md`.**
