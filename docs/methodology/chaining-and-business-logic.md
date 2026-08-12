# Chaining and business logic

Phase 4 — the two capabilities that distinguish a pentester from a scanner, and
the reason the Δ model exists.

---

## Part A — Chaining

### The model

A chain is an **ordered composition of confirmed steps** where step N's OUTPUT
becomes step N+1's INPUT or precondition. It is graded by its **weakest link**
(`compose_soundness`, reused from cross-service reachability rather than
reinvented), and it is emitted as CONFIRMED only when **every link is
independently confirmed by a P1–P7 oracle**. Any link resting on inference makes
the whole chain a `ChainResearchLead` naming that link.

```
src/clinkz/chaining/
├── vocabulary.py    # what each class YIELDS / REQUIRES — the substrate
├── models.py        # artifact, link, composition evidence, chain
├── harvest.py       # finding -> artifact, driven by the DECLARED yield
├── planner.py       # which chains exist, in what order
├── composition.py   # THE ORACLE — the decoy-substitution control
└── impact.py        # escalation, from what was DEMONSTRATED
```

### The substrate: yields and requires

`CLASS_YIELDS` / `CLASS_REQUIRES` declare, per methodology class, the artifact
its confirmation puts in our hands and the artifact it can consume. Two rules
keep the table honest, both enforced by `tests/test_chaining/test_vocabulary.py`:

* **Every dispatchable class is accounted for** — it declares a yield, or it
  appears in `NO_YIELD_REASON` with a substantive sentence. A class silently
  absent would be invisible to chaining forever, which is the silent-degradation
  shape the contribution ledger exists to catch.
* **A yield is what the confirmation PROVES, never what the class is named
  after.** Reflected XSS is *about* stealing a session, and this engine has never
  demonstrated exfiltrating one — its P7 oracle witnesses script execution, which
  is not a token in our hands. So it declares no yield and says why. Declaring
  the aspiration would make every XSS finding the head of a chain whose second
  link could never be carried, and **a chain that cannot be carried cannot be
  falsified.**

### The zero-FP core: the decoy-substitution control

**Two confirmed findings do not imply the chain between them, and a successful
second request does not either.** An endpoint that accepts everything accepts our
carried credential too; a login form that 200s on every POST "accepts" a password
we never recovered. So a carriage is proven the way every other oracle here is —
against a control:

> the real artifact is **ACCEPTED** and an **equivalently-shaped decoy** the
> target never issued is **REFUSED**.

The decoy preserves length, character classes and every separator (so a JWT
decoy keeps its three dot-separated segments and their lengths), is derived by a
one-way digest from the real value (so it is deterministic across runs and can
never accidentally BE the real value), and for an internal address is a reserved
`.invalid` name — never another IP literal, which could reach a live host the
client never authorised.

If the decoy is *also* accepted, the endpoint accepts the **shape** rather than
the **value**, we have learned nothing about what we recovered, and the honest
outcome is a lead naming that link — never a finding with a caveat attached.

**The carriage link's confirmation primitive is P4** — "forged input accepted
exactly as a valid baseline while a broken control is rejected". That is
precisely the decoy oracle, so chaining introduces **no new confirmation
primitive** and inherits the existing zero-FP boundary rather than widening it.

### The four compositions

| kind | carries | accepted means | decoy |
|---|---|---|---|
| `CREDENTIAL_TO_ACCESS` | a recovered credential | the authenticated-state boundary discriminator flips | same-shaped password |
| `FILE_READ_TO_CREDENTIAL` | a credential parsed out of recovered content | same | same |
| `TOKEN_TO_IMPERSONATION` | a recovered/predicted session token | the application serves a principal's own view | same-shaped token |
| `FETCH_TO_INTERNAL_REACH` | an in-scope internal address | content the address serves comes back | same-shaped non-resolving `.invalid` address |

`FETCH_TO_INTERNAL_REACH` is the escalation the brief names. Every SSRF this
engine has confirmed proves the FETCH and stops there — the target was
loopback-self or a collaborator we mounted. Pointing the same channel at an
internal address is a **second observation**, and it is what turns "the server
fetches a URL I choose" into "the server reaches a service the network places out
of my reach".

### State carriage — one seam, not twenty-four

Artifacts are harvested at `_persist_finding`, driven by the class's **declared**
yield. A methodology cannot forget to register, and the harvester cannot invent a
kind the class never claimed. This is the discovery contract's rule — the
PRODUCER declares what it contributes — applied one layer up.

**The carried value never reaches anything a human reads.** `ChainArtifact.value`
is excluded from serialisation; the evidence quotes a shape description and a
salted fingerprint. A chain carries exactly the material a report must not
reproduce, so a chain finding that quoted it would be the report becoming the
disclosure.

### Impact escalation

Escalation is a function of a **confirmed composition** and nothing else. It
never escalates a candidate, never escalates on the strength of a chain kind
alone, and **never lowers a severity a single link already earned** — the
component findings keep exactly what their own oracles gave them, and the chain
is emitted alongside them rather than rewriting them.

### Guarantees

* A chain **only ever ADDS**. Nothing in the chain phase can demote, re-grade or
  suppress a finding the single-step oracles produced.
* The chain phase runs **after** the false-positive pass, so a demoted finding
  can never become a chain's head link.
* The plan order is a **function of the finding SET**, never of the order
  findings arrived in — findings come from a concurrent phase, so any tie broken
  by arrival order would make the engagement non-reproducible.
* Truncation is **never silent**: every candidate beyond the carry budget is
  recorded as a lead saying nothing was sent for it.
* The chain planner reports to the **contribution ledger** as a `COMPOSER`, whose
  degradation shape is distinct: invoked every run, succeeded every run, composed
  nothing — which reads exactly like a healthy run against an application with no
  chains.

---

## Part B — Business logic

Δ = Capability(technology) − Intent(developer), applied where the developer's
intent is **the application itself**. An API exposing a checkout, a discount, a
quantity and a state transition has declared what it is for; the flaw is where
capability exceeds that declaration.

### The honesty rule, and why it is stricter here

Business logic is where a tool most easily hallucinates a vulnerability out of
**unusual-but-intended** behaviour. A subscription that lets you set a negative
balance may be a credit note. An order that can ship before payment may belong to
an invoiced customer. So:

> **Intent must be EVIDENCED from the application's own surface.** Not from what
> an application "should" do — from a field in the server's own representation of
> its own objects, from the range of values that representation actually shows,
> or from the application's own words when it rejects something. Where intent
> cannot be evidenced, the result is a research lead, never a finding.

Every finding states three things — the inferred intent, the **evidence** for
that inference from the app's own surface, and the observation showing capability
exceeded it. `BusinessLogicVerdict.evidence_lines()` builds all three at one
seam, so an emit site cannot ship two of them.

**The LLM checkpoint is gated the same direction as everywhere else.** Reading an
API surface and saying what an application is FOR is what a good model is strong
at; deciding is not its job. `verify_proposed_intent` keeps a proposal only when
the code can VERIFY its subject against the surface — the field it names has to
exist in the server's own representation, or the route it names has to exist on
the discovered surface. A proposal about a field the application does not have is
not a weak signal; it is about a different application.

### The three classes

| class | defining effect | controls |
|---|---|---|
| `_test_state_sequence` | a terminal state reached with the prerequisite skipped, **read back** | the same request in correct sequence, plus a malformed request the endpoint refuses |
| `_test_constraint_violation` | a **persisted record** carrying a value the app's own data forbids | the boundary value the app's own records show as normal, plus a malformed request it refuses |
| `_test_repeatability` | a single-use action applied twice, the **second effect observed** | the app's own refusal of an invalid instance |

Each read-back is load-bearing:

* An API that answers `200` and performs no transition is behaving correctly, and
  a status-only oracle would call that a workflow bypass on every well-built
  application it met.
* An API that accepts `quantity=-1` and stores `1` has **enforced** the
  constraint. Only reading the record back tells that apart from one that stored
  `-1`.
* An idempotent handler answers `200` to a replay and changes nothing, which is
  correct behaviour and indistinguishable from a real double-apply by status code
  alone. So the two effects are compared and confirmation needs them to DIFFER.

### What remains untested, and said so

`business_logic_domain_specific` stays in `UNIMPLEMENTED_CLASSES` with a rewritten
limitation naming what IS now covered and what is not: abuse depending on domain
knowledge the HTTP surface does not carry — pricing and discount interactions,
fraud and abuse-of-function flows, and any rule that exists only in a contract.
Those need a human tester with domain context, and this engine makes no claim
about them rather than inferring what the application ought to do.

---

## Part C — The benchmark profile

Chaining and business logic need state-changing requests, and the destructive
blocklist correctly refuses `DELETE` and identity change. **The client-safe
default is untouched**: `SafetyPolicy` still carries no switch that disables the
destructive refusal, because that refusal is the contract with the client rather
than a tunable.

What is added is a separate, fully explicit declaration
(`models/engagement.py::BenchmarkProfile`) that ONE target is a disposable
benchmark.

**It cannot be enabled implicitly.** There is no `enabled` flag and no
partially-populated shape — constructing the model at all requires:

* `target_is_throwaway=True` (`False` is a validation error, because "a disabled
  profile" is spelled by not having one);
* `acknowledgement` reproducing `BENCHMARK_ACKNOWLEDGEMENT` **verbatim** — a
  long, specific sentence, because a boolean can be set by a config template
  somebody copied and this cannot be typed by accident;
* at least one category, each named **one by one** (there is no wildcard);
* a named declaring party and a reference.

**Two categories can never be permitted, on any target** — session destruction
and security-posture toggles. The line is not "how bad is it": every category a
profile CAN permit is bad for the client, which is what a throwaway target makes
acceptable. The line is **who it damages**. These two damage the ENGAGEMENT
rather than the target: destroying the shared session or flipping the
application's security posture mid-run makes every later observation a
measurement of a different application, and a disposable target does not make a
corrupted engagement worth having.

**Permission is by the category that DECIDED the refusal, never an alias.** A
bare `DELETE` refuses under `unsafe_method` (the verb is the harm), not under
`deletion` (a token match). Treating one as implying the other would permit a
category the operator did not write down.

**Audited.** The classifier still runs and still names the category and the
deciding signal; the profile is applied to its verdict afterwards. So every
request a profile permitted lands in the action log tagged
`benchmark_permitted:<category>`, carrying the signal that would otherwise have
refused it and the declaring party — visible via `clinkz actions <id>` — and the
profile is rendered in the report header as prominently as the authorization it
lives on, including the categories that remain refused so nobody reads it as "all
rails off".

**Absent by default**, arranged exactly like the governor: `None` unless an
engagement installed one, so a directly-invoked methodology, a smoke cell or a
replay is byte-identical to before this module existed.

---

## The seven NEEDS_CHAINING challenges

`tests/fixtures/needs_chaining_classification.json` classifies seven multi-step
Juice Shop challenges by the LINKS each needs and this engine's coverage of each
link, validated by `tests/test_chaining/test_needs_chaining_classification.py`
against the engine's own tables — so the coverage column cannot quietly drift.

**Premise status: UNVERIFIED AGAINST A LIVE INSTANCE.** The repository contains
no pre-existing `NEEDS_CHAINING` list (grepped: no match anywhere in `src/`,
`tests/`, `docs/`). The classification was derived from the chain-kind taxonomy
plus Juice Shop's published challenge set. Which challenges a given build ships,
and whether each solves the way described, is a question about a running target
and is deferred to the Phase-5 live gate.

The file lives in `tests/fixtures` rather than `src/` on purpose: a methodology
must never carry a benchmark's vocabulary, and a test asserts the chaining
package stays free of it.

| challenge | chain kind | uncovered link | blocking gap |
|---|---|---|---|
| Login Support Team | credential_to_access | — | — |
| Forgotten Developer's Backup File | file_read_to_credential | — | — |
| Forged Signed JWT | token_to_impersonation | — | — |
| Forged Coupon | credential_to_access | — | checkout is a state-changing flow the client-safe rails refuse; reachable only under a benchmark profile |
| Reset a named user's password via their security answer | credential_to_access | link 1 (`no_methodology`) | OSINT association between application content and a person's security answer — no methodology, and a guess would send reset requests against a real account |
| Manipulate another user's basket | credential_to_access | — | composes through an identifier, not a carried secret, so the decoy oracle does not apply (an equivalently-shaped decoy identifier may name a real object) — planned and reported as a lead |
| SSRF reaching an internal service | fetch_to_internal_reach | — | — |
