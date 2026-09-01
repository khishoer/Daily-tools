# 🛡️ mTLS CA Bundle Worker & Flapping Monitor (`ca-bundle-worker`)

> **Production-grade mTLS CA Trust Store Maintenance, Acceptable CA Probing, and Intermittent Cloud Flapping Monitor.**

`ca-bundle-worker` is a specialized command-line utility built for Network Engineers, DevOps, and SREs to audit mutual TLS (mTLS) client verification bundles, safely mutate CA trust stores (append/remove), probe server-advertised acceptable client CAs, and continuously monitor live endpoints for cloud drops and CA drifting.

---

## 📑 Table of Contents

1. [Key Capabilities](#-key-capabilities)
2. [Command Reference](#-command-reference)
3. [Deep mTLS Health & Security Audit (`audit`)](#-deep-mtls-health--security-audit-audit)
4. [Mutating CA Bundles (`append` & `remove`)](#-mutating-ca-bundles-append--remove)
5. [Probing Online Acceptable Client CAs (`probe`)](#-probing-online-acceptable-client-cas-probe)
6. [Continuous Flapping & Drop Monitor (`monitor`)](#-continuous-flapping--drop-monitor-monitor)
7. [Split & Merge Utilities](#-split--merge-utilities)

---

## ⚡ Key Capabilities

* **Deep mTLS Health & Security Audit**:
  * ❌ Detects **Expired CAs** and **Expiring-Soon CAs** (<30d).
  * ❌ Detects **Duplicate CAs** (identical SHA-256 fingerprints).
  * ⚠️ Detects **Subject CN Collisions** (different certificates sharing the same Common Name).
  * 🚨 Detects **Non-CA Leaf Certificates Accidentally Bundled** (`basicConstraints: CA:FALSE` — a major security/mTLS misconfiguration).
  * 🚨 Detects **Weak Hashes** (SHA-1 / MD5).
  * ⚠️ Detects **Inadequate Key Usage** (CA missing `Certificate Sign` / `keyCertSign`).
  * 📊 Computes an **Executive Health Score** (0–100) with prioritized actionable fixes.
* **Safe CA Appending & Pruning**:
  * **`append`**: Validates candidate CAs and rejects duplicates before adding to the bundle.
  * **`remove`**: Specifically prunes CAs by Common Name (`--cn`), SHA-256 fingerprint (`--fingerprint`), or prunes all expired CAs in bulk (`--expired`).
* **Online Acceptable CA Probing (`probe`)**:
  * Connects to live TLS endpoints to extract the server-advertised **`Acceptable client certificate CA names`** sent in TLS `CertificateRequest` messages.
  * Cross-references against a local mTLS bundle to verify if your client certs will be accepted by the server.
* **Continuous Cloud Flapping & Intermittent Drop Monitor (`monitor`)**:
  * Polls an online FQDN every 2 seconds (or custom interval) over `N` seconds.
  * Detects **Backend Pod Drift / Load Balancer Flapping** (e.g. Pod A advertising CA bundle 1 vs Pod B advertising CA bundle 2).
  * Measures live handshake latency (min/avg/max) and generates a **Flapping & Stability Summary Card**.

---

## 🛠️ Command Reference

```bash
ca-bundle-worker <COMMAND> [OPTIONS] [ARGUMENTS]
```

| Command | Purpose | Example |
| :--- | :--- | :--- |
| **`audit`** | Deep health & security audit of an mTLS CA bundle | `ca-bundle-worker audit mtls-ca-bundle.pem` |
| **`append`** | Safely add a new CA (with validation & duplicate checks) | `ca-bundle-worker append mtls-bundle.pem new-subca.crt` |
| **`remove`** | Remove CAs by CN, Fingerprint, or prune all expired CAs | `ca-bundle-worker remove mtls-bundle.pem --cn "Old Root CA"` |
| **`probe`** | Probe online FQDN for server-advertised client mTLS CAs | `ca-bundle-worker probe api.internal.corp:443` |
| **`monitor`** | Poll endpoint every 2s to detect CA flapping and drops | `ca-bundle-worker monitor api.corp:443 --interval 2 --duration 60` |
| **`split`** | Extract every certificate in a bundle into individual files | `ca-bundle-worker split bundle.pem ./extracted-cas/` |
| **`merge`** | Consolidate multiple certs/dirs into one deduplicated bundle | `ca-bundle-worker merge -o combined.pem cert1.pem ./ca-dir/` |

---

## 🔍 Deep mTLS Health & Security Audit (`audit`)

Audits an mTLS CA bundle and calculates an actionable Health Score:

```bash
ca-bundle-worker audit /etc/nginx/ssl/client_cas.crt
```

```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                            🛡️  mTLS CA BUNDLE HEALTH AUDITOR & SECURITY REPORT                            │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│  Target Bundle: /etc/nginx/ssl/client_cas.crt                                                            │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│    HEALTH: 55/100 (CRITICAL ISSUES)    │   5 Total CAs (2 Roots, 2 SubCAs)   │   1 Expired               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯

🚨 Identified Health & Security Issues:
  • 🚨 1 EXPIRED CA(s) present in bundle. Clients using these CAs will fail mTLS!
  • 🚨 1 NON-CA LEAF CERTIFICATE(S) found in bundle! Leaf certs must NOT be in an mTLS CA bundle.
  • ⚠ 1 Duplicate CA(s) detected (identical SHA-256 fingerprints).

╭─ CERTIFICATE AUDIT TABLE (5) ────────────────────────────────────────────────────────────────────────────╮
│ #    │ COMMON NAME / SUBJECT              │ ISSUER CN                │ ROLE         │ EXPIRY / STATUS      │
├──────┼────────────────────────────────────┼──────────────────────────┼──────────────┼──────────────────────┤
│    1 │ Enterprise Root CA G1              │ Enterprise Root CA G1    │  ROOT CA     │ 364d left            │
│    2 │ Partner API Sub CA                 │ Enterprise Root CA G1    │ SUB-CA (INT) │ 179d left            │
│    3 │ accidental-leaf.corp               │ accidental-leaf.corp     │  LEAF (BUG)  │ 89d left             │
│    4 │ Legacy Deprecated Root CA          │ Legacy Deprecated...     │  ROOT CA     │ EXPIRED (10d ago)    │
│    5 │ Partner API Sub CA                 │ Enterprise Root CA G1    │ SUB-CA (INT) │ 179d left            │
╰──────┴────────────────────────────────────┴──────────────────────────┴──────────────┴──────────────────────╯
```

---

## ➕ Mutating CA Bundles (`append` & `remove`)

### Safely Append a New CA
Validates CA constraints and prevents adding duplicates:
```bash
# In-place update:
ca-bundle-worker append mtls-bundle.pem new-partner-subca.crt

# Output to a new file:
ca-bundle-worker append mtls-bundle.pem new-partner-subca.crt -o updated-bundle.pem
```

### Remove / Prune CAs
```bash
# 1. Remove by Common Name (or partial name):
ca-bundle-worker remove mtls-bundle.pem --cn "Legacy Deprecated Root"

# 2. Remove by SHA-256 fingerprint:
ca-bundle-worker remove mtls-bundle.pem --fingerprint "C7:1A:CC:F5:..."

# 3. Prune all expired CAs in bulk:
ca-bundle-worker remove mtls-bundle.pem --expired
```

---

## 🌐 Probing Online Acceptable Client CAs (`probe`)

Inspects what client CAs an online server accepts during TLS mTLS negotiation:

```bash
# Probe live endpoint
ca-bundle-worker probe api.internal.corp:443

# Probe and cross-reference against local mTLS bundle
ca-bundle-worker probe https://gateway.corp --bundle local-mtls-bundle.pem
```

---

## 📡 Continuous Flapping & Drop Monitor (`monitor`)

Checks an online endpoint **every 2 seconds over N duration** to catch intermittent network drops, load balancer routing anomalies, and drifting CA trust stores across backend pods:

```bash
# Monitor every 2 seconds for 60 seconds (30 polls)
ca-bundle-worker monitor api.internal.corp:443 --interval 2 --duration 60
```

```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                             📡  mTLS INTERMITTENT DROP & CA FLAPPING MONITOR                              │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│  Target Endpoint: api.internal.corp:443                                                                  │
│  Monitoring Config: Poll every 2.0s for 60.0s total (30 iterations)                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯

#    TIME (UTC)   LATENCY    STATUS         ADVERTISED mTLS CAs                  SERVER LEAF CN
────────────────────────────────────────────────────────────────────────────────────────────────────────────
1    02:04:31     69ms       ✔ OK           2 CAs: Partner Sub CA, Cloud CA G2   api.internal.corp
2    02:04:33     89ms       ✔ OK           2 CAs: Partner Sub CA, Cloud CA G2   api.internal.corp
3    02:04:35     90ms       ✔ OK           1 CAs: Legacy Root CA ONLY (DRIFT!)  api.internal.corp
────────────────────────────────────────────────────────────────────────────────────────────────────────────

╭─ 📊 MONITORING & FLAPPING SUMMARY AUDIT ────────────────────────────────────────────────────────────────────╮
│  Total Polls Executed: 30 iterations over 60s
│  Handshake Success:    30/30 successful (0 drops/errors)
│  Flapping / Drift:      FLAPPING / BACKEND DRIFT DETECTED! 
│  • mTLS CA Flapping: 2 distinct Acceptable CA sets were observed!
│    (Indicates load balancer is routing between drifting backend pods with different CA bundles).
│  Handshake Latency:    min: 65ms  │  avg: 81ms  │  max: 112ms
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

---

## 📄 License

MIT License. Maintained as part of [Daily-tools](https://github.com/khishoer/Daily-tools).
