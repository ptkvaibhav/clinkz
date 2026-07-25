# Out-of-band confirmation (P6)

`src/clinkz/oob/` + `_ssrf_oob_*`. Design in
[docs/p6-oob-design.md](../p6-oob-design.md); live validation in
[docs/discovery-engine-p6-oob-validation.md](../discovery-engine-p6-oob-validation.md).

The sixth confirmation primitive — a blind capability is confirmed when an inbound
callback bearing a Clinkz-minted, single-use nonce reaches a Clinkz-owned
collaborator within a wait window.

## Zero-FP by construction (§P6.2.2)

The nonce is minted at dispatch and embedded ONLY in the one outbound probe, so a
packet bearing it can only exist if something that received the probe executed the
egress — there is no reflection channel to the collaborator, so the
input-reflection confounder every in-band guard fights is *structurally absent*.

## The collaborator (`oob/collaborator.py::OOBCollaborator`)

A **receive-only** DNS (UDP) + HTTP listener — the HTTP leg returns a static 200
and never connects out; the DNS leg answers only its own advertised address, so it
can never be steered into an SSRF relay. It holds a bounded+redacted per-engagement
event log, a per-probe nonce→hypothesis correlation table, a preflight
**health-check** (mint a token, self-hit BOTH legs, confirm the round-trip — the
gate: only a healthy collaborator may turn a non-confirmation into a research-lead),
and a **fire-and-reap** shared-window reaper (§P6.3.2 — send all blind probes up
front, reap concurrently against one window, so K hypotheses cost one window not K).
Provisioned/torn-down per engagement in the Orchestrator preflight
(`_provision_collaborator`, disabled by default → unchanged black-box floor), wired
onto the Exploit agent via the lifecycle.

## The structural exfil guardrail (§P6.7.4 — the load-bearing safety property)

OOB payloads are built ONLY from CLINKZ-OWNED per-class templates
(`oob/templates.py`) — a methodology/LLM *selects* a template
(`BLIND_SSRF_URL`/`JNDI_LDAP`/`DNS_LOOKUP`), it **never authors the payload
string**. `build_oob_payload()` interpolates ONLY a validated `[a-z0-9]{16,64}`
nonce (`mint_nonce` = base32-of-`secrets`, metacharacter-free); it has **no
parameter** for target/LLM/source data and **rejects** any nonce/zone that is not
shape-valid, so an exfil template (`${env:X}.<nonce>`, a subdomain-encoded file
byte) is *structurally impossible to emit* — enforced at the carrier, not by
convention (`test_oob/test_templates.py`). P6 proves the capability *fired*; it
never moves target data over the channel.

## Raw-auditable (§P6.2.4)

A confirmed finding carries the `ConfirmationEvidence` pair `outbound_probe` (the
probe carrying the nonce) + `confirming_excerpt` (the inbound callback bearing the
SAME nonce) + a control (a fresh nonce minted but never sent → no callback).

## Isolation-validated (§P6.6)

End-to-end vs a **live GeoServer 2.19.1 + live collaborator + live Anthropic
exploit LLM** (`scripts/live_oob_ssrf_validation.py`, engagement `0b993c1e`): the
same SSRF confirmed in-band is ALSO confirmed via the OOB path — in-band
unregressed + P6 confirm (raw-auditable) + zero-FP (egress denied by dropping the
Host carrier → no callback → no finding) + the exfil guardrail (every
`${env:...}`/traversal/target-host attempt refused).

## Log4Shell is BUILT on this primitive (the flagship, §P6.5)

See [docs/discovery-engine-log4shell-class.md](../discovery-engine-log4shell-class.md).
A nonce-only `JNDI_DNS` template (`${jndi:dns://<dns-authority>/<nonce>}`) +
`OOBCollaborator.dns_authority()` carry it: the JNDI DNS provider queries the nonce
**directly** at the collaborator's DNS-leg authority (`host:dns_port`), the
reliable docker-mode channel with no wildcard-DNS delegation / port 53 (§P6.5.4 —
a documented paper-vs-live divergence from the `ldap://` shape, LESSONS #31). The
`_ssrf_oob_send` helper was generalized to `_oob_send(…, template_id)` (default
`BLIND_SSRF_URL` keeps SSRF byte-identical) so Log4Shell reuses the exact same P6
machinery — zero new proof code. The `DNS_LOOKUP` template exists for carrier
genericity, not wired to a methodology.
