# 🔐 Certificate & SAN Compare Utility (`cert-compare`)

> **Automated X.509 Leaf Certificate Comparison, Side-by-Side SAN Diff, and Renewal Safety Auditor.**

`cert-compare` is an ergonomic command-line tool built for Network Engineers, DevOps, SREs, and Security Teams to validate TLS/SSL certificate renewals, audit cryptographic parameters, prevent accidental outages from dropped Subject Alternative Names (SANs), verify Extended Key Usage (EKU) configurations, and ensure zero-downtime certificate rotation.

---

## 📑 Table of Contents

1. [Key Features](#-key-features)
2. [Prerequisites & Quick Setup](#-prerequisites--quick-setup)
3. [Command Syntax & Options](#-command-syntax--options)
4. [Real-World Use Cases & Recipes](#-real-world-use-cases--recipes)
5. [Understanding the Output](#-understanding-the-output)
6. [Automated CI/CD Pipeline Integration](#-automated-cicd-pipeline-integration)
7. [Troubleshooting & FAQ](#-troubleshooting--faq)

---

## ⚡ Key Features

* **Comprehensive 15+ Parameter Matrix**: Deeply compares Subject DN/CN, Issuer DN/CN, Serial, Signature Algorithm, Public Key (algorithm, size, curve), Validity Dates, Validity Remaining Days, Key Usage, EKU, Basic Constraints, OCSP, SKI, and Fingerprints (SHA-256, SHA-1).
* **Auto-Chronology Detection**: Intelligently identifies which certificate is the **Baseline/Hosted** and which is the **Renewal Candidate** based on validity timestamps, regardless of CLI argument order.
* **Side-by-Side Visual SAN Table**: Alphabetically aligned 2-column grid highlighting additions (`+`), removals (`-`), and common domains (`==`).
* **Noise-Free Domain Display**: Strips redundant `DNS:` prefixes while preserving clear badges for non-DNS identities (`[IP]`, `[URI]`, `[Email]`).
* **Critical EKU & Security Auditing**:
  * 🚨 **Fatal `serverAuth` Loss Alert**: Blocks deployment if `TLS Web Server Authentication` is missing.
  * ⚠️ **mTLS Breakage Alert**: Flags dropped `TLS Web Client Authentication`.
* **Cryptographic & CA Shift Tracking**: Detects RSA ➔ ECDSA modernization, key length changes, key pair rotation, and CA authority shifts.
* **Delta-Only Mode (`--only-diff`)**: Isolates differences for large certificates with dozens of SANs.
* **CI/CD Ready (`--quiet`)**: Returns exit code `0` on safe renewals/identical matches, `1` on breaking regressions.

---

## 🚀 Prerequisites & Quick Setup

### Prerequisites
* **Bash**: 4.0+ or macOS default `/bin/bash` / `zsh`
* **OpenSSL**: 1.1.1 or 3.x (`openssl`)
* **Python**: 3.6+ (`python3` standard on macOS/Linux)

### Installation Options

#### Option A: Direct Usage
```bash
git clone https://github.com/khishoer/Daily-tools.git
cd Daily-tools
chmod +x tools/cert-compare/cert-compare.sh
```

#### Option B: Global Symlink (Run from any directory)
```bash
# Add to user binary path
mkdir -p ~/.local/bin
ln -sf "$(pwd)/tools/cert-compare/cert-compare.sh" ~/.local/bin/cert-compare

# Ensure ~/.local/bin is in your PATH (e.g. in ~/.zshrc or ~/.bashrc)
export PATH="$HOME/.local/bin:$PATH"
```

---

## 🛠️ Command Syntax & Options

```bash
cert-compare [OPTIONS] <CERT1> <CERT2>
```

### Supported Target Formats
Target arguments `<CERT1>` and `<CERT2>` can be any combination of:
* **Local Files**: `.pem`, `.crt`, `.cer`, `.der`, `.p7b`
* **Live Remote Endpoints**: `example.com:443`, `https://subdomain.domain.com`, `10.0.1.50:8443`

### Command-Line Options

| Option | Long Flag | Description |
| :--- | :--- | :--- |
| **`-d`** | **`--only-diff`** | **Filter out matching rows**: Displays only differing parameters and SAN changes. |
| **`-s`** | **`--san-only`** | **SAN Focus**: Suppresses general parameters and renders only the side-by-side SAN table. |
| **`-q`** | **`--quiet`** | **Silent Mode**: Suppresses all stdout. Exits `0` if safe/identical, `1` if breaking differences. |
| **`-w <num>`**| **`--width <num>`** | Sets custom table column width (default: `108`). |
| **`-n`** | **`--no-color`** | Disables ANSI terminal color output (honors `$NO_COLOR`). |
| **`-h`** | **`--help`** | Displays quick command reference and usage examples. |

---

## 📖 Real-World Use Cases & Recipes

### 1. Pre-Deployment Renewal Verification (Hosted vs Candidate)
Verify a new renewal certificate before loading it onto an F5, Cloudflare, ALB, or NGINX Ingress:

```bash
# Compare live production website against new candidate certificate file
cert-compare https://app.example.com ./new_cert_2026.pem
```

---

### 2. High-Density SAN Delta Inspection (`--only-diff`)
When comparing massive certificates (e.g., 50+ SANs), hide the unchanged domains to instantly spot what changed:

```bash
cert-compare --only-diff prod_baseline.crt renewal_candidate.crt
# or shorthand:
cert-compare -d prod_baseline.crt renewal_candidate.crt
```

---

### 3. Comparing Two Live Websites
Quickly audit why two staging/production domains behave differently:

```bash
cert-compare google.com:443 youtube.com:443
cert-compare staging.example.com:443 prod.example.com:443
```

---

### 4. Reverse Order (Candidate passed first)
Order doesn't matter; the tool detects the renewal candidate automatically:

```bash
cert-compare ./new_candidate.crt ./currently_hosted.crt
```

---

### 5. SAN-Only Quick Audit
Compare purely the domain coverage across two environments:

```bash
cert-compare --san-only us-east-gateway.crt eu-west-gateway.crt
```

---

## 📊 Understanding the Output

The tool generates four structured, ergonomic sections:

### 1. Top Metric Dashboard
Displays high-level indicators at a glance:
```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                            🔐  X.509 CERTIFICATE COMPARISON & RENEWAL AUDITOR                             │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│   Cert [1] (Left):  app.example.com:443                      [ BASELINE / HOSTED ]                       │
│   Cert [2] (Right): ./new_candidate.pem                      [ RENEWAL CANDIDATE ]                       │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│   📊 AUDIT SUMMARY:  4 Param Diff(s)   │   12 Common SANs   │   +2 New in Candidate   │   0 Lost SANs     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### 2. General Parameters Comparison Matrix
Compares 15 core cryptographic & identity parameters:
* ` = ` (Soft gray): Identical parameter.
* ` ≠ ` (Highlighted cyan/yellow): Value changed between baseline and candidate.

### 3. Side-by-Side SAN Comparison Grid
Alphabetically sorted table comparing every domain entry:
* ` == ` (Green): Domain preserved in both certificates.
* ` + ` (Cyan): New domain added by the Renewal Candidate.
* ` - ` (Red): **Domain dropped from baseline** (DANGER: active traffic to this hostname will fail!).
* `· · · ·`: Subtle dot placeholder representing absence on that side.

### 4. Renewal Readiness & Risk Verdict
Actionable assessment categorizing the scenario:
* 🎯 **`EXACT IDENTICAL CERTIFICATE`**: Cryptographic twin.
* 🔄 **`SEAMLESS CERTIFICATE RENEWAL`**: 100% SAN continuity, valid lifetime extension, safe key rotation.
* 📈 **`SAFE SAN EXPANSION`**: All baseline domains kept + new domains added.
* 🚨 **`SAN CONTRACTION / REMOVAL`**: Hostnames lost (Breaking Change).
* 🚨 **`FATAL EKU LOSS`**: `serverAuth` missing from candidate (Immediate Outage Blocker).
* ⚠️ **`mTLS BREAKAGE`**: `clientAuth` dropped from candidate.
* ⚠️ **`EXPIRATION REGRESSION`**: Candidate expires sooner than the hosted baseline.
* ❌ **`COMPLETELY DISJOINT`**: 0% domain overlap.

---

## 🤖 Automated CI/CD Pipeline Integration

Integrate `cert-compare` into your GitHub Actions, GitLab CI, or Jenkins deployment pipelines to block invalid certificate deployments automatically.

### Example: GitHub Actions Workflow
```yaml
name: TLS Certificate Pre-Flight Validation

on:
  pull_request:
    paths:
      - 'certs/**'

jobs:
  validate-cert:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Validate Renewal Certificate
        run: |
          # Fails pipeline if candidate drops SANs, loses serverAuth, or has expired
          ./tools/cert-compare/cert-compare.sh --quiet https://prod.example.com certs/new_candidate.pem
```

---

## ❓ Troubleshooting & FAQ

#### Q: How does the script handle custom ports or IP addresses?
You can pass any port or IP address directly:
```bash
cert-compare 192.168.1.100:8443 https://internal.corp:9443
```

#### Q: Does it verify the certificate chain (intermediates / root)?
`cert-compare` inspects the **leaf certificate** presented by the server during TLS SNI negotiation, which is the entity governing SANs, hostnames, and expiration.

#### Q: What if an endpoint uses SNI virtual hosting?
The script automatically passes `-servername <host>` during OpenSSL TLS handshakes to ensure the correct virtual host leaf certificate is fetched.

---

## 📄 License & Repository

Maintained as part of [Daily-tools](https://github.com/khishoer/Daily-tools). Distributed under the MIT License.
