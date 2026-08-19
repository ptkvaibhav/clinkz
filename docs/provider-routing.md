# Provider routing (v2)

> Referenced from `.env.example`. This is the file that document points at.

**Anthropic is priority 1 for every call, on every phase. Every other provider
is fallback only, and a fallback is a disqualifying event — never a preference.**

Everything below is a consequence of that sentence, or a bound on it.

---

## 1. Why v2 exists

Routing v1 was per-role and it read reasonably: the reasoning-heavy agents
(Exploit, Research) led with Claude; the high-volume agents (Recon, Scan,
Report) led with Gemini Flash. Nobody wrote down the rule that produced it,
because stated plainly it is not a rule anyone would defend — *the cheap tier
answers first on recon, scan and report.* It was a cost decision that quietly
became a routing decision.

Two measurements ended it.

**A model swap silently re-baselined a class.** Over 1,033 recorded phase-3
`security_headers` calls across 126 engagements, the same prompt on a
byte-identical header observation (`server='Apache/2.4.67 (Debian)'`,
`x-powered-by='PHP/8.5.6'`) produced the version-disclosure entries **27%** of
the time under one model and **80%** under another. Neither number is a security
property of the target. A run-to-run coin flip is bad; a coin flip whose bias
moves when the model changes re-baselines every comparison built on that class,
and it read as a posture regression on the DVWA ladder.

**The cheap tier was deciding which findings survived.** Gemini served the
exploit stage 12 times across 9 engagements. Six were exploit *plans*. The other
six were **false-positive cross-checks** — the suppression path. Every one of
those reports looked exactly like a report where it had not happened. That is
the observation §4 is built on.

## 2. Where priority is declared

`Settings.llm_provider_priority`, and nowhere else.

```python
llm_provider_priority: tuple[LLMProvider, ...] = ("anthropic", "gemini", "openai")
```

A validator refuses any order that does not lead with `anthropic`, because it is
a one-line edit away from being reversed and the reversal is invisible in every
artifact a run produces except the model stamp.

Three consequences worth stating separately:

**A discovered key is availability, never priority.** `llm/providers.py` detects
`<PROVIDER>_API_KEY` at startup, validates each with one cheap call, and
registers every one with the redaction chokepoint. It writes nothing to the
priority order. Auto-enrolling a discovered key is how a run gets a surprise
model swap — an operator adds `FOO_API_KEY` for one experiment on a Tuesday, and
the next engagement's exploit plan is written by whatever it belonged to. "Could
this provider be reached" and "should it be" are different questions, and only
the second is a decision.

**Profiles no longer disagree about who goes first.** `LLM_PROFILES` survives as
a trace label. `reasoning` and `fast` both resolve to
`settings.llm_provider_priority`; `reasoning_pinned` is Anthropic with no tail.
`AGENT_LLM_PROFILE` maps every role to `reasoning`. The mapping is kept rather
than deleted because it is where a future per-role divergence would be written.

**Per-agent overrides still exist, and all default to Anthropic.**
`LLM_PROVIDER_<ROLE>` is the documented seam for moving one role deliberately.
Using it does not exempt that role from anything below.

## 3. Run mode — what a fallback costs

`CLINKZ_RUN_MODE`, default `client`.

| Mode | A fallback |
|------|-----------|
| `client` | Completes. The report is stamped `provider_degraded` with every call site and both models, and the run is marked **permanently ineligible as a baseline**. |
| `baseline` | Is a **hard failure**, refused before the request leaves. |

`client` is the default because it is the one that cannot lose an engagement.
`baseline` exists because a recorded baseline is only worth the comparison it
supports, and a ladder served by two models is not a ladder — see the 27%/80%
measurement above, which was taken on a *scan-side call producing what looks
like a pure observation*. That is why baseline mode refuses a fallback on
**every** role, not only the decision-bearing ones: comparability is broken by
any stage.

Ineligibility is one-way. No code path clears it: the degraded call already
happened and its output is already inside the findings, so a later clean call
cannot un-shape it. `DegradationRegister.reset` is for process teardown, never
recovery.

The register is **absent by default**, like the governor and the ledger. A
directly invoked methodology, a replay or a driver installs none and every hook
no-ops, so the black-box floor is byte-identical.

## 4. Call purpose — the refusal that holds in *both* modes

`llm/call_purpose.py`.

Client mode's answer — degrade and stamp — is right for most calls and wrong for
two kinds, and the reason is what a stamp can and cannot express.

`provider_degraded` can honestly say *"the exploit plan was written by a model we
did not ask for, so this run's coverage is not what a clean run's would be."* A
reader can act on that; the *What was NOT tested* section is beside it and the
remedy is to re-run.

It cannot say the equivalent about a **suppression**. If a degraded
false-positive cross-check demotes a confirmed finding, that finding is not in
the report. There is no row to caveat, no section that names it, and nothing
distinguishes *"the engine did not find it"* from *"a cheaper model decided it
was not real."* The stamp describes the run; it cannot describe what the run
removed. The six Gemini-served cross-checks are the reason this rule exists.

The same argument runs the other way for **emission**: a finding whose evidence
was shaped by a model nobody asked for is a claim in a client deliverable with a
provenance the deliverable does not carry.

So a call site declares what its answer becomes:

| Purpose | Fallback | Because |
|---------|----------|---------|
| `PLANNING` | Permitted, recorded, stamped | Costs coverage, and coverage is disclosable |
| `EMIT` | **Refused, in every mode** | Puts a claim in the report |
| `SUPPRESS` | **Refused, in every mode** | Takes a claim out of it, disclosing nothing |

```python
with llm_call_purpose(LLMCallPurpose.SUPPRESS, site="exploit._llm_analyze_results"):
    response = await self.llm.generate_text(prompt)
```

Refusing is the conservative direction on both paths, which is not a
coincidence. A refused suppression leaves the finding standing — the same
direction `_llm_analyze_results` already fails in when a model is unreachable
(it catches, logs, and returns an empty analysis). A refused emission checkpoint
leaves the methodology on its deterministic build, which is where the invariants
put the verdict anyway.

**The two refusals want opposite catchability.** Baseline mode raises
`ProviderPolicyError`, a `BaseException`, so that none of the agents' broad
`except Exception` handlers can degrade past it — a baseline run wants the *run*
to fail, and there is no partial result worth keeping. The call-purpose refusal
raises `DecisionPathFallbackError`, an ordinary `LLMError`, because it wants only
the *call* to fail: client mode exists so an engagement completes, and making
this one uncatchable would mean refusing a single suppression took the whole
engagement down with it. Both are raised before the request leaves, so nothing is
bought and nothing is stamped — a degradation the run did not take must not
appear in the register.

Absent a declaration the purpose is `PLANNING`, the permissive value, because
that is what a driver or a direct methodology invocation is. An undeclared
*agent* call site is not left to that default by accident:
`tests/test_llm/test_call_purpose_classification.py` reads the source of
`agents/`, `orchestrator/` and `research/` and fails on any LLM call site
missing from `DECLARED_CALL_SITES` or wrapped with a purpose the table
disagrees with. Same shape as `test_tool_wiring_decisions` — a decision nobody
wrote down is a red build, not a default.

### The declared sites today

| Site | Purpose |
|------|---------|
| `exploit._llm_plan_exploits` | `PLANNING` |
| `exploit._llm_analyze_results` | **`SUPPRESS`** — the false-positive cross-check |
| `exploit._load_analysis_json` | **`SUPPRESS`** — the same suspect list by a second route |
| `exploit._llm_analyze` | **`EMIT`** — the funnel for all 24 methodology checkpoints |
| `recon.*`, `scan.*`, `research.*`, `runtime_research.*`, `orchestrator._handle_query`, `base._react_loop` | `PLANNING` |

`exploit._llm_analyze` is additionally pinned at the chain level:
`_build_methodology_llm` uses `override_chain=["anthropic"]`, so the chain has no
tail and the methodology layer cannot fall back regardless. The declaration
states the intent that pin encodes, and a test asserts the pin so the two cannot
drift.

## 5. What the run reports about its own routing

Four separate facts, kept apart because they have different fixes:

* **`model_stamp`** — which model *served* each LLM stage, read from the run's
  own `llm_call` trace events, never reconstructed from configuration. A
  fallback makes "asked" and "answered" different, and it is the one that
  answered which shaped the output. A recorded baseline without it is not a
  baseline.
* **`provider_degradation`** — whether anything fell back, the call sites, both
  models per event, and `baseline_eligible`. Present on a clean run too: "no
  fallback occurred" is a claim the deliverable should make, and a section that
  appears only on failure cannot be told apart from one nobody wrote.
* **`llm_spend`** — tokens and dollars against the caps the run declared. USD is
  a stated *lower bound* whenever a model in the chain has no declared rate,
  because clinkz ships no default rate card and a guess under the heading
  "actual API spend" is worse than an incomplete number.
* **The contribution ledger** — `llm:<provider>` is a component like any other.
  A provider that was invoked and contributed nothing trips `SILENT`; a
  rotation trips `FALLBACK_ACTIVATED`.

## 6. Credit pre-flight

`llm/fallback.py::preflight_provider_available`. With both an Anthropic and a
Gemini key present, one cheap Gemini probe runs at engagement start. A depleted
signal excludes Gemini from every fallback chain for the whole engagement.

Under v2 this is about the *fallback tier*, not the primary: Gemini answers only
when Anthropic could not. The point is unchanged — detect depletion once, up
front, rather than storming 429s mid-pipeline. The precedent is engagement
`f6a550a4`: 79 Anthropic attempts, 76 of them the same
`400 … credit balance is too low`, each a full round-trip to re-learn a fact the
first one established. An unexpected error is treated as retriable because we
would rather finish on a backup than halt on a transient quirk — the right rule
for a quirk and the wrong one for an account, so a terminal account condition
now disables that provider for the rest of the process.

## 7. Models

| Role | Provider | Model |
|------|----------|-------|
| Every phase, priority 1 | Anthropic | `ANTHROPIC_MODEL`, default `claude-sonnet-5` |
| Any call that fell back | Gemini | `GEMINI_MODEL`, pinned `gemini-3.7-flash` |
| Research, when it falls back | Gemini | `GEMINI_RESEARCH_MODEL`, same pin |
| Tail | OpenAI | `AGENT_MODEL` |

Pinned to exact strings, never floating aliases: an alias moves under a fixed
configuration and silently re-baselines every number a run contributes, which is
the same failure `model_stamp` exists to catch after the fact.

**Exploit does not run on Opus.** It is pinned to *Anthropic*, and the Anthropic
model is whatever `ANTHROPIC_MODEL` resolves to — `claude-sonnet-5` by default.
Documentation said Opus for a long time and no configuration ever selected it.

`GEMINI_THINKING_LEVEL` accepts `LOW | MEDIUM | HIGH`. `MINIMAL` is offered by
the SDK's `types.ThinkingLevel` enum and **rejected by the API** on 3.7 Flash,
so the SDK enum is not the contract and config refuses it at startup rather than
mid-engagement.

## 8. What v2 traded away: research grounding

Research led with Gemini Flash-Lite for one reason — native Google Search
Grounding. The Anthropic path has no equivalent, and the cross-provider hop that
used to supply it was removed for a separate and correct reason: `AnthropicClient.research`
imported `GeminiClient` directly and returned its answer, routing around the
fallback chain entirely. A research call the resilient client had resolved to
Anthropic was served by Gemini anyway, one layer below the layer that picks
providers, and no chain restriction could have seen it.

So under v2 a research answer is, by default, **a recollection of a training
corpus**. That is not a thinner answer. Every vulnerability disclosed after the
serving model's cutoff is invisible to it, and the text carries no signal that
anything is missing — a CVE list that looks complete and quietly stops. For a
security tool that is a correctness failure.

It is therefore **stamped, not absorbed**:

* `LLMClient.RESEARCH_GROUNDING` is declared by every shipped client
  (`live_search` / `training_data` / `undeclared`). The producer declares, like
  `ToolOutput.discovered_urls` and `detected_components()`.
* `ResilientLLMClient.research_grounding()` reports the grounding of the
  provider that **answered**, not the one that was asked.
* `ResearchResult.grounding` is the **weakest** grounding any call in the phase
  ran under — a phase where two calls were grounded and one fell back is a
  runbook where some entries saw the web and some did not, and the whole of it
  must not be described as grounded. `grounding_providers` keeps the mixed case
  legible.
* Every runbook `Technique` carries `grounding`, because a runbook entry
  persists to the cross-engagement KB: the claim outlives the run, so the caveat
  has to as well.
* The report renders a **Research grounding** section either way, stating what
  the limitation means and — explicitly — that it does not reach the findings.
  A CVE from research is a LEAD that must reach one of this engine's own oracles
  before it can be a finding, and no oracle consults the research text.

`undeclared` is treated as ungrounded. "We do not know whether this saw the web"
and "this did not see the web" license exactly the same claim in a deliverable.

The replacement, when the grounding is wanted back, is Claude's own `web_search`
server tool on the Anthropic client — grounding without a second provider — not
the reinstatement of a cross-provider call. That is not built.

## 9. Configuration reference

| Variable | Meaning | Default |
|----------|---------|---------|
| `LLM_PROVIDER` | Legacy top-level provider; last-resort fallback | `anthropic` |
| `LLM_PROVIDER_DEFAULT` | Default for any agent without an override | `anthropic` |
| `LLM_PROVIDER_RECON` / `_SCAN` / `_EXPLOIT` / `_RESEARCH` / `_REPORT` | Per-role override | `anthropic` |
| `CLINKZ_RUN_MODE` | `client` (degrade + stamp) or `baseline` (a fallback fails the run) | `client` |
| `ANTHROPIC_MODEL` | Model for every priority-1 call | `claude-sonnet-5` |
| `GEMINI_MODEL` / `GEMINI_RESEARCH_MODEL` | Model for a call that fell back to Gemini | `gemini-3.7-flash` |
| `GEMINI_THINKING_LEVEL` | `LOW` / `MEDIUM` / `HIGH` | `MEDIUM` |
| `GEMINI_MAX_RPM` | Per-client Gemini rate ceiling | `30` |
| `LLM_REQUEST_TIMEOUT` | Hard per-call timeout (seconds) | `120` |
| `LLM_MAX_OUTPUT_TOKENS` | `max_tokens` for one call (covers thinking **and** text) | `16000` |
| `CLINKZ_VALIDATE_KEYS` | Run the startup key-validation probes | on |

`ANTHROPIC_API_KEY` is required in practice — it is priority 1 for every call.
With no key at all, startup fails naming the variables.

## 10. The rules, restated

1. Anthropic is priority 1 for every call on every phase.
2. Priority is declared in config and validated. A discovered key never changes it.
3. A fallback is disqualifying: hard failure in `baseline`, stamped and
   baseline-ineligible in `client`.
4. On an **emit** or **suppress** path a fallback is refused in *both* modes,
   because a stamp cannot disclose an absence.
5. A model that answered is recorded by the run, never inferred from config.
6. A capability lost to routing is stated in the deliverable, not absorbed.
