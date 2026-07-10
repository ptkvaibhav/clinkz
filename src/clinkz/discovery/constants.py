"""Discovery-engine constants shared with the proof engine.

Deliberately a **leaf module** (no intra-package imports) so
``agents/exploit.py`` can import the carrier-constraint identifier without
pulling in the whole discovery package — keeping the proof engine free of any
discovery import cycle.
"""

from __future__ import annotations

# Per-instance carrier constraint an SSRF proof obligation may carry, telling the
# probe to rewrite the request ``Host`` header to the host of the injected ``url``
# value. Required by targets whose fetch guard compares the ``url`` host to the
# request ``Host`` header (GeoServer TestWfsPost / CVE-2021-40822): both are
# attacker-controlled, so aligning them satisfies a bypassable guard. Opt-in
# (empty ``carrier_constraints`` ⇒ unchanged behaviour) so it never fires where a
# host rewrite would break routing.
CARRIER_ALIGN_HOST: str = "align_host_with_injected_url_host"
