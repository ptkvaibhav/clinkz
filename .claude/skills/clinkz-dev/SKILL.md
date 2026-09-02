---
name: clinkz-dev
description: "The Clinkz development + validation operating contract — goal/leverage, phantom-honesty discipline, real-validation standard, risk-tiered workflow, and git protocol. Reference it in a task prompt instead of restating any of this."
---

# Clinkz dev — operating contract

Standing contract for **any** Clinkz build / fix / diagnose task. It consolidates `CLAUDE.md` (architecture — the source of truth), `docs/architecture.md`, and `.claude/LESSONS.md` into what you must hold while working. Read it every task; it is meant to be skimmed.

When a task prompt and this file conflict: the prompt wins on *scope* (what to build); this file wins on *honesty + validation + git* — those are non-negotiable. Depth for building a specific methodology lives in `honesty-patterns.md` (per-vuln confirmation oracles + the phantom patterns that have actually bitten us) — read it then.

---

## 1 · Goal & leverage

**Mission (one chain):** scope-lock → surface map → port/service/version scan → methodology planning → crawl + OSINT → applicable + tech-specific attacks (NVD / bug-bounty / our own KB intel) → chaining + cross-tech → **novel** discovery → validate **real exploitability AND impact** → industry-standard report → KB of what worked / didn't.

**Leverage (why Clinkz wins):** trustworthy findings (**zero false positives, proven impact**) + attacker depth (chaining, cross-tech, novel) + cross-engagement learning (the KB compounds run over run).

**The generality law (load-bearing).** Every capability you build MUST be **general + honest + KB-ready — never target-specific.** A DVWA / Juice Shop endpoint is a *witness* that exercises a general primitive, never the thing you detect.
- Session-indirection is a general cross-request injection *carrier* (setter→session→trigger), wired to SQLi as its first consumer — **not** a "DVWA `sqli/high` detector."
- Proof of generality: the capability is **N/A by construction** on stacks where the vuln is absent (no signal → no candidate → nothing emits), and its **carrier is separated from its consumer** (a new injection *shape* gets a dedicated carrier; the vuln methodology just consumes it).
- **KB-ready** = every technique result, hit *or* miss, is recorded to `clinkz_knowledge.db`.

---

## 2 · Phantom / honesty discipline (the core)

A finding is a claim that we exploited something. **Emit only when your own evidence proves the DEFINING security effect — never a correlate.** Confirm on the state change, not the reflection.

| Vuln | Confirm on (defining effect) | NEVER on (phantom) |
|---|---|---|
| Upload | stored artifact fetched back **executes** (canary as interpreter output) | filename echoed / form re-rendered / merely retrievable |
| SQLi | DB-error signature, boolean row-set delta, or a UNION **data row in a *successful* (non-error) response** | a marker reflected in the body or inside an inline/4xx/5xx DB error |
| CMDi | command output in **command-output position** in a 2xx/3xx | echo-canary reflected in a 4xx/5xx / stack trace |
| Open redirect | **3xx `Location`** (browser-resolved) navigates off-site to the attacker host | attacker string reflected in body / JS / a same-host path |
| IDOR | an **authorization boundary actually crossed** (out-of-allotment id rejected; forged id serves another principal's record) | content-length / body delta with no boundary present |
| SSTI | arithmetic **product rendered** (absent from a benign baseline) / RCE canary in output position | the template literal reflected verbatim |
| XXE | **file-content signature we never sent** (embedded — wrapped-channel aware) | the payload echoed back |
| SSRF | internal/metadata **content** the app should not return | the internal URL echoed back |
| JWT | forged token **accepted like the valid baseline** (broken-sig rejected) | — fully in-band; a rejected token never confirms |

**For any vuln not in the table:** name the effect that occurs *only* when the vuln truly fires, baseline-anchor it, confirm on that. `honesty-patterns.md` has the full per-methodology oracle set.

**The guards that keep confirmation honest:**
- **Escaping-robust reflection guard.** Before ruling "reflection," blank the body's own echoed payload with **both** HTML-unescape **and** SQL/backslash de-escape (`\'`→`'`), collapse whitespace, then check if the marker survives *elsewhere*. A sink that `addslashes`/`htmlentities`-escapes your input still reflects it — a naïve substring check misses that.
- **Baseline-delta attribution.** The effect must be absent from a benign baseline and attributable to *your payload* — not page chrome, not a per-request CSRF token, not a value the app echoes on its benign/failure path. An acceptance marker must never be a substring the app also emits when it **rejects** you.
- **Status alone is not a guard.** An inline (HTTP 200) DB/parse error defeats a status-code-only reflection guard → guard on the **absence of an error signature**, not just on 2xx. Conversely some legitimate channels are 4xx (XXE's 410) → the reject rule is *content-shaped, per methodology*, never a blanket "4xx = reject."
- **The deterministic check GATES the LLM.** The LLM reasons / ranks / synthesizes; a **deterministic signal decides emission.** No LLM verdict emits on its own. When phase-2 has *empirically confirmed* the primitive, phase-4 **prefers the deterministic build and skips the LLM** for that type — an LLM that paraphrases/mangles a proven payload (e.g. appends a dead `%00`) is the bug.
- **Impossible-level = the honesty control.** Any finding at DVWA `impossible` (or any hardened control) is a **loophole in your oracle, not a catch**. A finding that confirms *identically at every security level* means the oracle is matching the app's benign response — treat **uniform-confirm-across-a-graded-control as a prime phantom signal**.
- **Suppress a true positive before you emit a false positive.** Zero-FP is the product. If a guard's only choice is "risk a phantom" vs "drop a real one," **drop the real one.** Verification-honest emission is the primary guard; the post-run FP-marking pass is advisory on top, never the safety net.
- **Never hardcode a target/benchmark value.** No DVWA string, no Juice Shop challenge constant baked into a methodology. Discover the app's own tokens at runtime (allowlist strings, form-field names, cookie setters). A hardcoded witness value is exactly how a "general" capability silently degrades into a target detector.

---

## 3 · Validation standard

**The false-green precedent (read this twice).** A keyless / silent-LLM / direct-invocation **harness pins the deterministic fallback path and never exercises the live-LLM path** — so it *structurally cannot* test any fix that lives in an LLM-override, synthesis, or verification-vocabulary path. Green there is **not evidence**. This has burned us repeatedly (the silent-LLM-fallback, LFI-`%00`, and upload-uniform-confirm lessons). **Never cite a keyless harness as merge evidence.**

**Two real-validation modes:**
- **Smoke gate — the default, during build.** A cheap real-container check: hit the **real target endpoint**, assert a **deterministic signal**. No full pipeline, no LLM in the loop where avoidable. Fast enough to run as you build. This is the proof for a self-contained methodology cell.
- **Full pipeline run — reserved.** `python -m clinkz scan --target <url>` end-to-end. Reserve for: **LLM-involved emission** paths, **crawl-reach / discovery integration** (does recon→scan→plan actually *deliver* the vulnerable page?), and **one final multi-level confirmation per batch**. A real run is validated by **reading the report + trace**, never a self-graded summary.

**Pre-flight before any "real run" claim (mandatory):**
1. **Keys present — count, never print:** `grep -c` the key names in the env/`.env` (Anthropic + Gemini); confirm non-zero. **Never echo a value.**
2. **Live-ping both providers:** one cheap real call each (Anthropic + Gemini) to prove the key works and quota isn't depleted (the credit-preflight rationale in `CLAUDE.md`).
3. **If it can't run real** (missing key, depleted quota, target down) → **STOP and report.** Never substitute a keyless/silent harness and call it validated. "Couldn't validate for real" is an honest, acceptable outcome; a harness-green stand-in is not.
4. The in-process HTTP path needs `TOOL_EXEC_MODE=local` when the `clinkz-tools` container isn't the path (docker mode curls inside a possibly-down container → silent status 0).

**Re-run scope = blast radius:**
- **New, self-contained module** → its own smoke cells **+ the impossible-level honesty check.**
- **Shared methodology / helper change** (the `_send_probe` family, a reflection guard, phase-5 verification, a signature table) → **re-run the WHOLE affected family across all levels.** The LFI regression came from trusting a unit-green shared-path change; a shared change that's only spot-checked is unvalidated.
- **A "justified non-finding" must be proven against an instance where the vuln is actually LIVE** (stand up `safetyMode=disabled`, enable the challenge, read the gate). "Challenge exists & unsolved" means *present*, not patched. A green unit suite over a mocked engine hides real detection bugs.

**Premise verification — step 0 of any build that leans on an asserted artifact.** The brief says "the target ships an OpenAPI spec / a `foo` header / an `open_redirect` module / an initialised DB" → **curl/probe the RUNNING target for it before building on it.** A frozen vuln-app image is often years behind the cheat-sheet; Juice Shop ships no parseable spec; a fresh DVWA container has no `users` table. **Confirm the data plane, not the claim.** If the premise is wrong, **STOP and report** — don't silently "fix" a different thing.

---

## 4 · Workflow & risk-tiering

**Plan first, always.** Every task opens with a brief plan that folds in the git-discipline standing items below. Consult `.claude/LESSONS.md` during planning **only** when the task resembles a past failure; append to it **only** after a real error worth not repeating.

**Risk-tier the work:**
- **Phantom-prone or novel-primitive cell** (new injection carrier; a shared verification/guard change; anything whose failure mode is a *false positive*) → strict **diagnose → design → fix** split. Do the design pass first, separate diagnosis from build, so a wrong premise surfaces before code.
- **Well-understood vuln on a known shape** → combine **diagnose + build** in one pass. Don't ceremony-tax a routine change.
- **Correct-and-stop:** if the premise is wrong or two instructions conflict, say so and stop — don't proceed on a bad premise or pick a side silently.

**Architecture invariants (from `CLAUDE.md` — non-negotiable; they are what make "general" possible):**
- LLM only through `llm/` (never import openai/anthropic/gemini in agent code); per-agent providers (Gemini recon/scan/report/research, Anthropic exploit; Exploit pinned).
- Tools only through `ToolResolver.find_tool(capability=...)` — never a tool name, never a direct import. Every tool **validates scope before any network activity**.
- Agents never talk directly — **all comms route through the Orchestrator.**
- **Deterministic steps + LLM at named checkpoints.** No free-form ReAct.
- Pydantic v2 for every model; async everywhere; structured logging at step boundaries. Any field an LLM populates that it might emit as objects is `list[dict[str, Any]]` with a coercing `@field_validator(mode="before")` — never `list[str]` (a broad `except` around model construction turns a schema mismatch into a silent feature outage).
- **A new injection *shape* gets a DEDICATED carrier** (`_cookie_send_probe`, `_session_send_probe`, `_http_post_xml`, …); leave the shared string-only `_send_probe` untouched.
- **Never poison the shared engagement session** — no crawl/plan/probe visits a state-changing link (WAF/security toggle, logout); `is_state_changing_url` is the chokepoint.
- **Stack-conditioned branches** (`_is_php_stack`, engine fingerprints, dialect) are backed by a **deterministic protocol artifact** (a `PHPSESSID` cookie, a `.php` path, a header) — never the flaky LLM tech list alone.
- Record every technique result (hit or miss) to the persistent KB.

**The guard-domain law (a guard's domain is COMPUTED, never hand-maintained).**

A guard — a test that asserts completeness, a partition, or "everything of kind X
is classified" — has two halves: the **domain** it iterates over and the
**classification** it checks each member against. The classification is what a
human must declare, entry by entry, with a reason. **The domain is not.** It must
be computed from the same source of truth as the thing being guarded.

> A partition asserted over a domain that excludes the unclassified members is a
> partition of whatever is left. The members that most need the guard are exactly
> the ones a hand-maintained domain forgets, because the same omission that put
> them outside the tables put them outside the domain.

This has now shipped **six times in six weeks**. The most recent:
`test_control_arm_registry.py::_dispatchable()` returned
`set(_CLASS_TRACE_SKILL) | set(_BUSINESS_LOGIC_CLASSES)` — 27 of the 30 names in
`DISPATCHABLE_TEST_METHODS`. The three missing were the three the dispatcher can
run and no table had classified: `_test_log4shell` (the engine's one CVE oracle),
`_test_tier2_technique`, `_test_tier3_technique`. They **exited** the
never-sent-control completeness assertion instead of failing it, and the guard
was green throughout. Same shape:
`test_vuln_classes.py::test_every_dispatched_class_has_a_client_label` used
`_CLASS_PATH_TOKENS` — a *ranking signal* table — as its domain, so the two
dispatchable classes with no registry entry at all were invisible to the check
whose entire purpose is finding them.

**How to tell the two apart.** Ask: *if somebody adds a new member and forgets
everything else, does this test go red?* If the answer depends on them also
remembering to edit a list inside the test, the domain is wrong.

| | Domain (the set iterated) | Classification (per member) |
|---|---|---|
| Where it comes from | **Computed** — the dispatch table, `TOOL_CHAINS`, a glob, an AST walk over the real modules | **Declared** by a human, with a reason |
| Hand-editing it | a defect | the point |
| A new member | fails the build until classified | is what the build is telling you to write |

**The pattern to copy** — both of these are already right, use them as the model:
- `tests/test_tools/test_tool_wiring_decisions.py`: domain is `set(TOOL_CHAINS)`,
  tables are `WIRED` / `DELIBERATELY_UNWIRED`, each with a substantive reason.
- `tests/test_tools/test_parser_input_assumptions.py`: domain is an AST walk for
  every `parse_output` under `tools/`; the table declares each parser's input
  assumption, and it asserts **both** directions (undeclared *and* stale).

**Assert both directions.** `computed - declared` catches the new member;
`declared - computed` catches the entry that outlived the thing it described.
A guard with only the first half rots into documentation of a wish.

**And an exemption is an allow-list entry with a reason, never a silent skip** —
the same rule as `artifact_scan._SKIP_ALLOWED` and
`test_mock_shape_audit._DELIBERATE_FICTIONS`. `len(reason.split()) < 6` is a
red build in the control-arm registry for exactly this reason.

**The guard-pattern law (same law, second face).** A guard's DOMAIN is one way
to exclude its own failure mode. Its PATTERN is the other, and it fails the same
way — silently, with a clean report.

> A sweep for absence-read-as-measurement used the regex
> `\bor (0|\[\]|\{\})\b`. `\b` needs a word character on one side, and after
> `]` or `}` the next character in real code is `)` or `,` — both non-word. The
> pattern could therefore never match two of its own three alternatives. It
> returned **65 of 865 hits** and reported clean on what it structurally could
> not see. The one alternative it did match, `or 0`, is the one ending in a word
> character.

Every guard this repo lost this month failed by having a **domain** that
excluded its failure mode; this one failed by having a **pattern** that did. The
correction is the same: derive, don't hand-write. The corrected sweep is an AST
walk for `BoolOp(Or)` whose last operand is an empty literal, bucketed by what
the coalesced value is USED for — so the domain is every such node the parser
finds, not every one a regex author remembered to spell.

**And the CORRECTED regex is still wrong — that is the actual lesson.** Run
side by side against the AST walk it returns **875** where the parser finds
**882**: a seven-hit gap, after the character-class bug that hid two thirds of
the domain was fixed. The residue is not another spelling to add. A regex reads
a line; the thing being hunted is a node, and the two disagree wherever the
source does not put them on the same line — a call broken across lines, a
coalescence inside a comprehension, an operand that is itself an expression —
and, in the other direction, wherever a *docstring or comment describing this
very defect* contains the characters and is counted as an instance of it.

So the lesson is not "fix the regex". It is that **a pattern-matched domain is a
guessed domain**: the author enumerates the shapes they can picture, and the
guard's coverage is silently bounded by that imagination rather than by the
language. The first regex was a guess that was obviously wrong once measured;
the second is a guess that was not, which is the more dangerous of the two,
because it looks correct and its remaining error is invisible without the AST
walk standing beside it to disagree. If the answer must be *complete*, parse.

**How to tell.** Ask of a pattern exactly what you ask of a domain: *if the thing
I am hunting appears in a new form, does this go red?* If matching depends on a
character class the author had to reason about, write the check against the
parsed structure instead. And **measure the denominator before trusting the
verdict**: a sweep that reports its own hit count against a total it never
computed cannot tell "nothing to find" from "nothing findable".

The seven defects that corrected sweep surfaced share one shape, which is the
thing worth recognising in review: **`X or <empty>` erases the difference between
a value that was measured and one that was never produced**, and every consumer
downstream then reads the absence as the measurement. It is only a defect where
something CLAIMS on the coalesced value — a guard, a count in a deliverable, a
verdict. Iterating an absent collection and an empty one are the same act; that
is the idiom, and it is most of the 865.

**The acceptance-criterion law (same family, third face).** A domain and a
pattern both fail by excluding the thing they hunt. An acceptance criterion
fails by measuring something *adjacent to* the thing it certifies.

> IDOR's acceptance criterion was **"a target-confirmed scoreboard solve plus an
> emitted finding of the matching class"**. On the 2026-08-31 Juice Shop
> envelope it passed, three runs running, over an oracle whose arms were
> **inverted**: the crawl saw `id=1`, principal A was jim — who is user **2** —
> phase 3 incremented 1 to 2, so the `self` arm read admin's basket and the
> `crossing` arm read A's own. Juice Shop marked `basketAccess` solved because
> our traffic really did fetch basket 1; the finding said we had crossed into
> basket 2, which is jim's. Every downstream arm cleared, because every one of
> them is a comparison and **a comparison does not know which side it is
> standing on**.

> The criterion could not have caught it. **The scoreboard grades the OUTCOME
> and the oracle grades the REASONING, and nothing compared them.** An external
> grader says a thing happened; it says nothing about which arm made it happen,
> and being right for the wrong reason is invisible from outside.

So: **an acceptance test that reads only an external grader cannot detect an
oracle that reached the right verdict by the wrong arm. The acceptance criterion
must assert the ARMS, not the outcome.**

The same three questions as the other two faces, asked of a criterion:

1. **What does this measure that the thing under test does not control?** A
   scoreboard, a CVE database, a challenge solve — these are outcome signals and
   they are worth having. They are corroboration, and they are never the claim.
2. **Could the component pass this while doing the wrong thing?** If yes, the
   criterion is adjacent, not sufficient. Write the arms down: which request was
   sent, as whom, carrying what, and what each one is required to show. Every
   one of those is an engine fact recorded in the run's own trace.
3. **Does a wrong answer look different from a right one HERE?** An acceptance
   criterion that passes identically on a working oracle and a broken one is
   measuring the target, not the engine.

**The IDOR acceptance criterion, restated in that form** (pinned in
`tests/test_agents/test_idor_four_arm_oracle.py`, and the shape to copy for any
class whose verdict rests on more than one request):

> A confirmed IDOR is accepted only when the run's own trace shows, for that
> `(endpoint, parameter)`:
> 1. `ref(A)` was ANCHORED — a reference the caller was observed to own, from a
>    record naming the caller by an identity read out of the caller's own
>    session material. Never a crawl-observed value.
> 2. `ref(self) != ref(crossing)`, and `ref(self)` is the anchored reference.
> 3. The crossing response carries an **owning field** naming a principal that
>    is not the caller. The owner's own authorized read is CORROBORATION and is
>    never the ground truth.
> 4. The anonymous arm was **dispatched** against `ref(B)` and was **not** served
>    the resource.
> 5. The never-issued control was dispatched and refused.
>
> A scoreboard solve satisfies none of these and is reported beside them, never
> instead of them.

**A note on which way a criterion may be wrong.** Both halves of a spec can be
individually reasonable and jointly contradictory, and that is worth hunting
for explicitly: this class required A to be the LEAST privileged principal (so
the crossing runs uphill) *and* attributed the crossing by matching B's own
authorized read — but a B that outranks A reads A's records too, so the second
test is satisfied by *B can also read this*, which is the feature. Direction and
attribution-by-comparison cannot both hold. When two rules in one spec are each
defensible, check whether the second is still discriminating **under the
conditions the first imposes**.

**Git protocol (every push):**
- **Before the first edit: is this branch already merged?** `git fetch origin --prune && git merge-base --is-ancestor HEAD origin/main` — exit 0 means HEAD is an ancestor of `origin/main`, the branch is already merged, and **no work may land on it**; re-branch with `git checkout -B <new> origin/main` before touching a file. Twice in three sessions (`feat/idor-crossing-direction`, then `feat/absence-is-not-a-measurement`): both were noticed after the fact, both cost a re-branch, and the second would have put an entire SCA feature on a dead branch. A merged branch looks exactly like a fresh one — clean tree, plausible name, commits in the log — so nothing surfaces it until the push, which is why the check is worth nothing run afterwards. One command, before the first edit. **Same rule for the PR body: before editing one, confirm the PR is open** (`gh pr view <n> --json state`). A merged PR's body edits exactly like an open one's and says nothing back, so #128's description was updated after it merged with work it does not contain — the same trap, second face. A merged PR is the record of what landed, and prose is the only part of that record still writable.
- Commit **per logical unit**; imperative `prefix(scope): summary` with **no trailing period**. Push to origin after each commit once gates pass. **No `--force`, no `--no-verify`.** **No attribution trailer** — this line used to ask for a `Co-Authored-By` one, which `.claude/settings.json` has suppressed at source since the session-link containment (`attribution: {commit: "", pr: "", sessionUrl: false}`). The point of that containment is that **nothing Claude-Code-generated lands in this repo's commit metadata**, so no recent commit carries the trailer and none should: a trailer added by hand is the one route past a suppression that has no other. Do not restore it.
- On Windows, multi-line commit/PR bodies go **via a file**: `git commit -F <file>` / `gh pr create --body-file <file>` — a `-m "$var"` with embedded `"` breaks PowerShell's arg parser.
- Maintain **one open PR** for the branch against `main`; update its description (the aggregate narrative) on every push. A **structural change** (adds/removes/renames a file, agent, tool, model, config option, or alters architecture) → update **ALL** affected docs (`README.md`, `CLAUDE.md`, `CLINKZ_V2_IMPLEMENTATION.md`, `docs/`, `CONTRIBUTING.md`) in the **same push**. Stale docs = task not done.

**The three pre-push gates (never bypass; fix the root cause — no blanket `# noqa`/`# type: ignore`, no skip/xfail to stay green):**
1. **Lint** — `ruff check src/ tests/` + `ruff format --check src/ tests/`; also clean up every file the diff touches (dead code, naming, stale comments, `None` guards, no hardcoded secrets).
2. **Keyless test gate** — `pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`. **Capture the exit code directly** — `pytest … > out.txt 2>&1; echo "EXIT=$?"` — **NEVER pipe through `tail`/`&&`** (that reports the *pipe's* exit — a false green). Container gate (separately, serially, when containers are up and the change touches scan/exploit/orchestrator): `pytest tests/test_integration/`, `pytest tests/test_skills_dvwa/ -m dvwa_smoke`, `pytest tests/test_skills_juiceshop/ -m juiceshop_smoke`, `pytest -m pipeline_smoke tests/test_pipeline_smoke/`.
3. **Security review** — `/security-review` on the diff when it touches `tools/`, scope, credentials, LLM I/O, HTTP/network/subprocess, deserialization, user-path file I/O, MCP, or report rendering. Resolve every finding. (Doc/config-only may skip 1–2; gate 3 still applies if runtime behavior can change.)

**Report results raw.** Give the **real** artifact paths — `outputs/<id>/report_<id>.json` / `.md`, `outputs/<id>/trace.jsonl` — with **no self-grading, no inflated coverage**. The raw artifacts are the evidence; let them speak. A live-pipeline "confirmed" is **not** proof: read the finding's own evidence (payload + where the indicator surfaced + status) and replay it against the live target before trusting the label.

---

## 5 · Prompt template

One line an author invokes instead of restating any of the above:

> **Apply clinkz-dev. [diagnose | build] `<cell/capability>`. Smoke-gate during build; [full-run at batch end | full-run this cell if LLM-involved]. Out of scope: `<…>`.**

Examples:
- `Apply clinkz-dev. build GraphQL-injection carrier. Smoke-gate during build; full-run this cell (LLM-involved emission). Out of scope: websocket/subscription transport.`
- `Apply clinkz-dev. diagnose the SSRF blind-deferred non-finding on Juice Shop. Smoke-gate only; full-run at batch end. Out of scope: wiring an OOB collaborator.`

That inherits the full generality law, honesty discipline, validation standard, and git protocol from this file — nothing else needs restating.
