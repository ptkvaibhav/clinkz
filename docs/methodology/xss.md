# XSS — `_test_xss_reflected` / `_test_xss_stored` / `_test_xss_dom`

Part of the adaptive **payload-injection family** (six-phase reflection /
fingerprint / synthesize / verify / emit with LLM-driven payload synthesis; see
[README](README.md) for the shared pattern).

## Emission rule

- **Stored XSS** emits only when phase-5 verification confirms the payload
  reflects **unescaped in an executable position**; a synthesized-but-unverified
  payload emits nothing.
- Reflected XSS confirms on the reflected payload landing unescaped in an
  executable context, anchored on a benign baseline.

## Reflected-XSS verifying-response capture (report-integrity BUG 1, DVWA f7a761a1)

`_run_xss_reflected_methodology` threads the phase-5 verifying response (anchored
on the reflected payload, `_xss_evidence_snippet`) onto
`MethodologyResult.verifying_response`, and `_xss_phase6_emit` renders THAT as the
Response evidence — never the old hardcoded `(response unavailable)` placeholder.

**Honesty guard**: `verified` but no captured response ⇒ emit returns `None`
(verification ran blind — never a silently-verified finding), the same "reject on
missing evidence, not on a label" discipline as CMDi/LFI phase-5; this stopped the
FP-suppression pass from flagging a genuine Low reflected XSS.
