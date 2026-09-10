# The default-control audit

**Measured 2026-09-10, on the tree at `b45b239`. Report only — nothing here is fixed yet.**

The law is `.claude/skills/clinkz-dev/SKILL.md` §6:

> A control supplied as an optional parameter with a permissive default makes an
> oracle only as controlled as its least careful caller. The default IS the
> absence.

This is the first rule in that file that predicts where to look rather than
explaining where we already looked, so this is the first sweep run *because of*
a law rather than *after* an incident.

---

## 1 · The domain, and how it was computed

Two AST walks over `src/clinkz/` (160 modules) and `scripts/`:

* every parameter carrying a default, with the default classified as
  **absence** (`None`, `""`, `0`, `False`, `[]`, `{}`, `()`, `frozenset()`,
  `list()`/`dict()`/`set()`, a pydantic `Field` whose default or
  default_factory is one of those) or **substantive**;
* every `Call` node whose callee name resolves to one of those functions, with
  the argument resolved through **both** keyword and positional passing.

No name vocabulary anywhere in the domain. An earlier pass filtered on
`control|baseline|marker|scope|session|…` and it is recorded here only as the
thing that was wrong with it: the pattern law in §4 already says a
pattern-matched domain is a guessed domain, and this one would have missed
`decoy`, `benign_markers` and `inverted` on their names alone.

### The denominator, measured first

| | count |
|---|---|
| defaulted parameters | **642** |
| of those, permissive (default == absence) | **551** |
| distinct permissive parameter names | 298 |

### The four tiers — computed from call-site agreement

| tier | count | meaning |
|---|---|---|
| **MIXED** | 172 | supplied at ≥1 site, omitted at ≥1 other — the domain proper |
| **NEVER** | 71 | every call site omits it; the parameter is a comment |
| **ALWAYS** | 215 | every call site supplies it; the default is unreachable |
| **UNCALLED** | 93 | no call site the graph can see |

**Both directions.** `computed − declared` is the whole of §3 below: this is the
first run, so nothing was declared and every member is new. `declared −
computed` is empty for the same reason, and becomes the half that matters the
moment §3 is turned into a table in a test — an entry that outlives the
signature it described.

### The audit's own blind spots, stated rather than papered over

A call graph matched on callee **name** cannot see four things, and each one is
the guard-domain law one level up:

| blind spot | instance found | consequence for this report |
|---|---|---|
| `getattr` dispatch | all 29 `_test_*` methods are dispatched by name from the plan runner | the 13 `auth_session=None` rows in the NEVER tier are an artifact — the real dispatcher is invisible to the walk |
| aliased import | `from ._prototype_pollution import grade as grade_pollution` | `grade(header_name="")` first read as NEVER-supplied; it is in fact supplied at `exploit.py:33199` |
| callable handed as a value | `in_scope=self._scope.contains` (invariant 97's own case) | not re-measured here; already covered by that guard |
| homonym methods | `record` on `ActionLog`, `ContributionLedger`, `ScopeRefusalLog`; `__init__` everywhere | counts for those rows are upper bounds, not exact |

Every number below that a blind spot touches is marked.

---

## 2 · The set — real findings

Five. Ordered by what the default costs.

### F1 · `_xss_confirmation_gate` — the same signature fails in both directions

`agents/exploit.py:20633`, three call sites.

```python
def _xss_confirmation_gate(
    self, *, payload, landing, char_map,
    rationale: str = "",
    expected_execution: str = "",
    verifying_body: str = "",              # 1 of 3 supplies
    literal_landing_witnessed: bool = False,  # 2 of 3 supply
) -> tuple[bool, str]:
```

| caller | `verifying_body` | `literal_landing_witnessed` |
|---|---|---|
| reflected — `exploit.py:19699` | `result.verifying_response` | `result.literal_landing_witnessed` |
| stored — `exploit.py:20048` | **omitted** | `result.literal_landing_witnessed` |
| DOM — `exploit.py:21438` | **omitted** | **omitted** |

**`verifying_body=""` is the permissive direction — it costs honesty.**
Condition 2 of the gate is
`_reflection_only_in_error_block(verifying_body, payload, _ERROR_BLOCK_MARKERS)`,
which is invariant 42's second never-confirm shape: *a reflection inside a
framework error page*. On `""` it returns `None` unconditionally, so **the
error-block veto does not exist for the stored or the DOM class.** Only
reflected XSS has it, and the gate's own docstring presents it as one of the
four conditions the shared gate exists to apply to all three.

**`literal_landing_witnessed=False` is the strict direction — it costs
coverage.** False makes the two prose vetoes (conditions 3 and 4) apply, which
is invariant 45 running the *wrong* way: a veto that reads the model's prose is
supposed to apply only to an effect nobody witnessed, and the DOM caller
asserts nobody witnessed one without ever asking. It cannot be silent, either:
that call site raises `RuntimeError` on rejection, so an over-applied prose
veto there is a crash, not a suppression.

**And neither is a call-site fix.** The producing models cannot supply what is
missing:

| model | `literal_landing_witnessed` | a response body |
|---|---|---|
| `XSSStoredMethodologyResult` | present | **absent** — carries `read_back_url`, never the read-back body |
| `DOMXSSMethodologyResult` | **absent** | **absent** |

This is question 2 of §6's classification, and it is the one that changes the
size of the work: the fix is in `models/methodology.py`, in the two
methodologies that populate those models, and only then at the call sites.

### F2 · `EngagementGovernor.authorize` — the engagement-wide gate sees 2 of the destructive classifier's 4 discriminators

`safety/governor.py:428` calls

```python
verdict = classify_request(verb, url, field_names=names, labels=labels)
```

`classify_request` declares four discriminators, all with permissive defaults:
`field_names`, `labels`, `field_types`, `values`. The governor passes two, and
`labels` is `None` at **every** call site of `authorize` (NEVER tier, 3 sites —
count is an upper bound, `authorize` is not a homonym but its callers were
matched by name).

What the two absent ones are for, in `classify_request`'s own words:

* `values` — "Non-label field values the PAGE shipped with (a hidden field's
  default, say)". `<input type="hidden" name="op" value="delete">` renders
  nothing at all; the value is the only place the semantics appear. The
  governor **has the body** and derives only `_body_field_names(body)` from it.
* `field_types` — "a `password` type is an authentication-material signal even
  when the field is named something opaque". The governor cannot know these
  from a body; only a form parser can, and `authorize` has no parameter to
  receive them.

**This is a degradation, not a hole.** `is_destructive_form_submission`
(`safety/destructive.py:799`) builds all four from a parsed form and is called
at five exploit-side submission sites, so the full vocabulary does run at the
submission gate. The governor is the second, weaker gate on the same
vocabulary — and CLAUDE.md's claim is that `safety/destructive.py` is the one
destructive vocabulary "consulted by both the navigation and submission gates",
which is true of the module and not of the discriminators.

### F3 · `llm:<provider>` components are declared with no reachability predicate

`llm/fallback.py:539`:

```python
declare_component(name=f"llm:{provider}", kind=ComponentKind.LLM_PROVIDER)
```

`declare_component(*, name, kind, reachability: str = "")` →
`ledger.declare(name, kind, reachability="")` → the record keeps
`declared_reachability = ""` → `resolve_reachability` skips it outright
(`if rec.invocations or not rec.declared_reachability: continue`).

So no `llm:<provider>` component is ever evaluated, and a declared-but-never-
invoked provider produces no reachability answer in either direction.
`component_registry.py` is explicit that this is the *only* declaration path:

> Not here on purpose: `llm:<provider>`, which `llm/fallback.py` already
> declares at the seam that knows which providers a run's chain actually holds

The delegation is right; it loses the reachability half on the way. Invariants
79–80 say reachability is a computed predicate, that "no predicate declarable ⇒
a build failure, not a runtime branch", and that a fourth state exists —
NOT DETERMINED — for the case where a producer said nothing. A `""` here is
none of those three states. It is silence that renders as absence.

The other declaration path, `component_registry.py:538`, passes
`component.reachability.value`. Textbook MIXED.

### F4 · `owning_fields(principal_values=frozenset())` — right by construction at both omitting sites

`agents/_idor_oracle.py:546`, 9 call sites, 2 omit. Route 2 of the function —
*the field VALUE is an identity WE hold* — is silently off when
`principal_values` is empty.

* `_write_crossing.py:541 owning_field_of` asks a **schema** question (which
  field does this collection name owners with), and route 2 answering it would
  admit `First name: bob` as a schema field. Omission is correct.
* `exploit.py:3638 _field_owns_reference` synthesizes
  `{name: "clinkz-owner-probe-value"}`; route 2 cannot fire against a literal
  we authored. Omission is correct.

Reported anyway, because "it happens to be right" is what a guard exists to
replace, and neither site says why it is right. Invariant 33 rests the whole
IDOR claim on an owning field; both routes into that vocabulary should be a
decision somebody wrote down.

### F5 · `StateStore.get_findings(validated_only=False)` — a parameter whose True branch is reachable only from an archived agent

`state.py:410`. Both engine callers pass `validated_only=False` explicitly
(`agents/report.py:437`, `engagement/resume.py:75`); the only `True` in the
tree is `tests/test_agents/test_critic.py`. The Critic is archived
(`agents/_archive/critic.py`, 0 invocations in 2,774 recorded steps), and the
`validated=1` column it filters on is written by nothing that runs.

Not a control defect — invariant 93's shape one door down: a flag that cannot
take its other value anywhere it is read.

---

## 3 · The set — measured and classified as SAFE

Declared here so the next run's `declared − computed` half has something to
check, and so a future reader does not re-derive them.

| site | parameter | why the default is not an absence |
|---|---|---|
| `exploit.py:33691 _run_control_arm` | `decoy=None` | **the shape to copy** — `None` MINTS a decoy (`mint_decoy`) rather than skipping the control. A differential class supplies its own shape; the seam still owns the record. 10 of 11 sites omit, correctly. |
| `exploit.py:33788 _run_control_arm_first` | `decoy=None` | same seam, same reason |
| `exploit.py:34105 _make_finding` | `control_arm_parameter=None` | falls back to `parameter`, which is the right arm key for every class that does not rename its vector between dispatch and emission. 35 of 37 omit, correctly; the docstring already says only a renaming class needs it. |
| `safety/lockout.py:157 classify_lockout` | `control_body=""` | both call sites supply — `exploit.py:27167` (`baseline_body`, brute force) and `governor.py:718` (forwarded, **positionally**). The first pass of this audit read the positional one as OMITTED; it is not. |
| `governor.py:680 observe_credential_response` | `control_body=""` | supplied at both sites (`auth.py:1084`, `http_client.py:482`) |
| `auth.py` `_login_verdict` / `_observe_credential_response` / `_try_api_login` / `_api_post_json` | `control_body=""` | supplied at every site with `login_html` or a forwarded control — this is the invariant-98 fix holding |
| `http_client.py:448 _observe_credential` | `control_body=""` | supplied with `self.credential_control_body` |
| `governor.py:1141 _looks_blocked` | `benign_markers=frozenset()` | supplied at its one site with `self._benign_block_markers()` |
| `auth_agent_dispatch.py:77 HttpToolDispatcher` | `control_markers=None` | supplied at its one site with `list(result.login_page_lockout_markers)` |
| `_prototype_pollution.py:256 grade` | `header_name`/`header_value=""` | supplied at `exploit.py:33199`; `effect_present` fails CLOSED on empty (returns False for the header gadget) |
| `_secret_exposure.py:231 operational_disclosure` | `baseline_body=""` | supplied at its one site |
| `exploit.py:26344 _idor_probe_arm`, `32661 _write_crossing_arm` | `anonymous=False` | an arm SELECTOR, not a control — False is "this is not the anonymous arm" |
| `_write_crossing.py:708`, `exploit.py:26517` `refuse` | `inverted=False` | local closure; False is "not inverted" |
| `exploit.py:11431 _submit_form_fields` | `carrier=None` | optional per-probe `host_override`; None is the ordinary path |
| `ledger.py` `record` / `record_contribution` | `not_applicable=""` | "" is *no N/A reason*, which is the honest default for a component that ran; the 7 supplying sites are the ones that measured a correct emptiness (invariant 77) |

`csp_nonce`, `gadget_path`, `gadget_param` on the P7 helpers are omitted at
several sites and are **coverage**, not control: without a nonce the witness
payload is refused by a strict CSP and P7 records a non-witness, which
invariant 23 already licenses ("a missing browser costs coverage, never
honesty"). Not carried as findings; noted so the next sweep does not re-raise
them.

---

## 4 · What is NOT fixed here

Nothing. Per the brief, the set is reported before anything moves. The order the
fixes want, when they are authorised:

1. **F1** — largest, and the only one that reaches models: two fields on
   `models/methodology.py`, the two methodologies that populate them, then the
   two call sites. It is also the only one on an emission path.
2. **F3** — smallest: a `ReachabilityKey` for `LLM_PROVIDER` and one argument.
   Needs a decision on what the predicate should say about a fallback provider
   that was correctly never reached.
3. **F2** — needs a design call, not a patch: whether `authorize` grows
   `field_types`/`values` parameters, or whether the governor is documented as
   the deliberately-weaker of the two gates.
4. **F4, F5** — comments and a deletion.

And the guard itself: the MIXED/NEVER/ALWAYS/UNCALLED walk belongs in
`tests/` with §3 above as its declared table, both directions asserted, the
four blind spots named in the module docstring rather than left for the next
reader to rediscover.
