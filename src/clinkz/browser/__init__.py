"""P7 — the client-side execution oracle.

The sixth primitive (P6) proves a *blind server-side* capability fired, by having
a Clinkz-minted nonce leave in a payload and return through a Clinkz-owned
out-of-band collaborator. P7 proves a *client-side* one the same way: the nonce
leaves in the injected payload and returns through a Clinkz-owned channel that
**only executing JavaScript can reach**.

Three vulnerability classes were unconfirmable by construction before this
module existed — DOM-based XSS, a reflected/stored XSS whose landing context is
client-rendered, and a CSP whose real-world bypassability is a browser question.
Each recorded an honest
:class:`~clinkz.models.finding.UnprovenExploitLead` saying execution was never
witnessed. P7 is the missing witness, and nothing else about those classes
changes: they gain a confirmation path, they do not gain a new claim.

Modules:
    templates: The CLINKZ-OWNED witness payload carrier (the P7 analogue of
        :mod:`clinkz.oob.templates`).
    witness: The verdict types — what was observed, and what it licenses.
    csp_policy: Reading a served Content-Security-Policy and deciding which
        witness shape, if any, that policy leaves reachable.
    oracle: The headless-browser tool itself.
"""

from __future__ import annotations

from clinkz.browser.csp_policy import (
    CSPBypassRoute,
    CSPPolicy,
    parse_csp,
    select_bypass_route,
)
from clinkz.browser.templates import (
    ClientWitnessTemplateId,
    MarkupBreakout,
    build_witness_expression,
    build_witness_payload,
    mint_binding_name,
)
from clinkz.browser.witness import (
    ExecutionWitness,
    WitnessRefusal,
    WitnessVerdict,
)

__all__ = [
    "CSPBypassRoute",
    "CSPPolicy",
    "ClientWitnessTemplateId",
    "ExecutionWitness",
    "MarkupBreakout",
    "WitnessRefusal",
    "WitnessVerdict",
    "build_witness_expression",
    "build_witness_payload",
    "mint_binding_name",
    "parse_csp",
    "select_bypass_route",
]
