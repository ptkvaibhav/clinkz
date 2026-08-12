# Phase 3 — five classes, and the control each one confirms against

Five methodology classes added together, and the reason to document them
together is that four of the five are the same shape: **an effect that is
trivially observable, and a control that decides whether the observation means
anything.** Each section below leads with the control, because in every case the
control is the part a naive implementation omits and the part that would have
prevented the corresponding phantom.

The fifth (CSP bypass) is different in kind: its oracle already existed, and what
was missing was the discipline about what *no route found* is allowed to mean.

---

## CSP bypass — `_test_csp`

**Defining effect.** Script executed in the target origin *under the policy this
response actually served* — witnessed by P7: a Clinkz-minted nonce returned by a
call from inside the page's JS context, with a second nonce minted alongside and
injected nowhere staying silent. `bypass_csp` is asserted OFF and recorded, so
the verdict answers "did script run under the served policy" rather than "under
no policy at all".

**Why it is not the security-headers class.** That class answers *is a policy
present and what does it say*. These come apart in both directions: a policy full
of `'unsafe-inline'` is not a bypass unless something executes, and a policy that
reads strictly can still be defeated by a same-origin gadget it fully permits.
Header presence is a property of a response; bypassability is a property of how a
browser resolves it.

**The route ladder** (`browser/csp_policy.py::select_bypass_route`), ordered by
strength of the resulting claim rather than by convenience:

1. no policy governs script → plain inline;
2. `'unsafe-inline'` **and** no nonce/hash → plain inline (a browser ignores
   `'unsafe-inline'` when a nonce or hash is present, so reading the directive as
   a word list would attempt and fail this route);
3. a nonce that was **byte-identical across two independent responses** → nonced
   inline. Two fetches, because one observation cannot distinguish a per-response
   nonce from a published constant, and that distinction *is* the finding;
4. `'self'` without `'strict-dynamic'`, plus a discovered same-origin endpoint
   that reflects a parameter into its own JavaScript response → gadget include.

**The refusal, which is the point.** When no route applies, the class emits an
`UnprovenExploitLead` carrying `CSPBypassRoute.unreachable_note`. "We found no
way in" and "there is no way in" are different sentences and only the first is
true. Likewise a route that was attempted and did not execute is recorded as a
statement about *the one shape attempted* — a bypass through a shape this engine
cannot synthesize looks exactly the same from here.

**Per level.** Because the policy is re-read from the response at probe time and
recorded verbatim as `policy_in_force`, the verdict is per-response and therefore
per-level by construction: a graded control that tightens its policy produces a
different `policy_in_force` in the evidence of each level's result.

---

## Cryptography — `_test_crypto`

**Defining effect**, in one of two forms, each *performed* rather than observed:

* **Recoverable plaintext** — the token decoded, under a named reversible scheme,
  to content containing a value **this engagement supplied at login**.
* **Forgery accepted** — a token rebuilt under that same recovered scheme with
  the anchor swapped was honoured, while a random token of the same shape was
  refused.

**The control is the anchor.** A properly generated session id base64-decodes
perfectly and reveals random bytes; confirming on "it decoded" would confirm on
every well-built session cookie in existence. So a recovery must surface a value
we know — and the known values are the identity the orchestrator handed over
(`authenticated_as`), never a dictionary of likely usernames. An anchor drawn
from a guess makes the recovery a coincidence.

**The password is deliberately not an anchor** and must not become one. The
identity is not a secret and is safe in evidence; the password is credential
material, and a recovered plaintext quoting it would put the operator's own
credential into the deliverable.

**The shadow key.** A single-byte XOR has a second key differing by `0x20` — the
ASCII case bit — whose output is the same text in the opposite case. Both decode
to printable text, both contain the anchor case-insensitively, and because XOR is
symmetric **both re-encode to the original token byte for byte**. No property of
the token separates them; a round-trip check does not either (this was tried
first, and the suite caught it reporting key 10 for a token built with key 42).
The anchor settles it: an application stores the identity as it was given, so the
exact-case decode is preferred and the case-insensitive pass is a fallback for an
application that normalises on the way in.

**What it never says.** A token it could not recover is reported as *not
recovered*, never as strong. Absence of a recovery under five reversible
encodings is not a cryptographic assessment.

---

## Input validation — `_test_input_validation`

**Defining effect.** The server **accepted** a value the application itself
declares invalid. The declaration is read from the page's own validation
attributes, so the finding quotes the application about its own field rather than
asserting our opinion of what it ought to accept.

**The control is the whole design.** A 200 proves acceptance only if this
endpoint can reject anything. A SPA shell answers 200 to every path; a route that
does not exist does too. So every probe carries a control: a request of the same
shape carrying a value malformed in a way any validating handler must refuse. If
the control is *also* accepted, the endpoint has demonstrated no validation, we
have learned nothing about this constraint, and the result is a lead.

The asymmetry is deliberate: **this class can only confirm on an endpoint that
has proven it validates**, which is exactly the endpoint where "it accepted my
invalid value" is a real statement.

**Status is not acceptance.** An API answering `200` with `{"error": ...}` has
rejected the request, and a form re-rendering with a validation message is a 200
that rejected. `response_accepted` requires a 2xx *free of a rejection
signature*.

**The control is malformed, not hostile** — no injection metacharacters — so a
WAF cannot be the thing that answers the control's question.

**What it will not probe.** A constraint we cannot concretely violate is skipped
rather than approximated. Constructing a guaranteed non-match for an arbitrary
regex is not decidable in general, and a wrong construction would send a *valid*
value and read the acceptance as a finding.

---

## Secrets & configuration exposure — `_test_secrets_exposure`

**Defining effect.** Credential material, or privileged operational content,
**served to a request that carried no session at all**.

**The control is structural.** The probe uses `no_session`, which tells the HTTP
chokepoint the shared engagement jar is neither read nor written. Passing an
empty `cookies` dict would not be enough — the jar is ambient, and an
"anonymous" probe carrying our own session is precisely the trap
`engagement/auth_state.py` exists to avoid on the authenticated side. A class
whose entire claim is *served to someone who never authenticated* cannot afford
to get this wrong.

**The self-echo guard.** A response containing the bearer token we just sent is
the target quoting us back. Confirming on it would report the operator's own
credential as the target's leak — on every echoing endpoint of every engagement.
Shapes whose fingerprint matches material we supplied are discarded, and because
the fingerprint is a salted hash the comparison never handles the secret itself.

**Reusing the disclosure gate's vocabulary.** Detection is
`engagement/credential_shapes.py` — the same definite vocabulary
`artifact_scan.py` uses on our own bundles, so a shape the redactor removes is a
shape we look for in the target's. Its **entropy heuristic is deliberately left
behind**: an entropy rule over a minified bundle flags every hash, sourcemap and
build id. `Set-Cookie` is excluded — the application issuing a session is the
feature working.

**The baseline.** Operational markers that also appear on the site root are page
chrome, and are subtracted. A single internal hostname inside a large document is
a build artifact; the bar is two distinct markers, below which the result is a
lead.

---

## Mass assignment — `_test_mass_assignment`

**Defining effect.** A create request carrying a field the client never offers is
**honoured** — confirmed by reading the created object back **and** by a control
object created by an otherwise identical request that omitted the field.

**Distinct from IDOR**, which tests object *access*: whether principal A can read
principal B's record. This tests object *creation*: whether a property may be set
that the application never exposes, because the handler binds the whole request
body onto its model.

**Why three requests.** Each cheaper shape confirms something else:

| shape | what it actually proves |
|---|---|
| `201 Created` | the endpoint exists |
| the field echoed in the response | the handler reflects its input — many do, before discarding it |
| read-back without a control | the field has that value, not that **we** set it |

Most frameworks return 201 and drop the extra field silently, so a status-only
implementation would confirm on every framework behaving correctly.

**Candidates are derived from both sides, never guessed.** The field set comes
from the server's own representation of the object (a `GET` of the collection);
subtracting what the client offers is what makes a field *unofferable*, which is
the whole claim — a field the form already has is not mass assignment, it is the
form. A field the server never shows is not proposed at all, because a write
whose outcome cannot be interpreted is target state changed for nothing.

**Probe values are unmistakable and harmless.** `clinkz-probe-role`, `0.01`,
`true`. A payload that would grant real privilege is not needed to prove binding.

**This class writes to the target** — the only one that does outside the
established submission paths. Every request passes the destructive-submission
gate, the records created are ordinary application records, and each write is
state-changing and therefore lands in the action log, so `clinkz actions <id>`
answers "what did it do to my app?" with the exact list. The per-endpoint cap is
deliberately tight (3 fields, 4 requests each).

---

## The ranking signals

Three of the five rank on an **observed** precondition rather than on a path
word, for the reason `_CLASS_PRECONDITIONS` exists: a route named `/csp/` that
serves no policy is not that class's surface, and the site root that serves a
strict one is.

| Class | Observed precondition | Why |
|---|---|---|
| `_test_csp` | `serves_csp` (new) | bypassability is only a question where a policy was served |
| `_test_crypto` | `sets_cookies` | a token can only be recovered where one was issued |
| `_test_input_validation` | `has_form` | the declaration this class reads is an HTML validation attribute |
| `_test_mass_assignment` | `has_form` | a write is what it binds onto |
| `_test_secrets_exposure` | — (path tokens) | a secret is served by a *document*; its own anonymous fetch is the filter |

`body_param` was tried on the two write classes and **removed**: on an API target
nearly every write endpoint carries one, so the precondition would grade almost
the whole application as those classes' surface — the defect LESSONS #46
describes. The guard
`test_body_param_is_only_given_to_the_generic_injection_classes` caught it.
