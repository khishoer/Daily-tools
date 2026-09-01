# 📦 CA Bundle Worker (`ca-bundle-worker`)

> **Production-grade CA Bundle Auditor, Certificate Chain Manager, and PKI Trust Store Utility.**

`ca-bundle-worker` is a tool for Network Engineers, DevOps, and SREs to inspect, split, merge, deduplicate, re-order, and diff multi-certificate bundles and TLS certificate chains.

---

## 📑 Table of Contents

1. [Key Features](#-key-features)
2. [Command Reference](#-command-reference)
3. [Recipes & Common Workflows](#-recipes--common-workflows)
4. [Fixing Broken/Unordered Chains](#-fixing-brokenunordered-chains)
5. [CI/CD Integration](#-cicd-integration)

---

## ⚡ Key Features

* **Deep CA Bundle Inspection**: Tabular audit of every certificate in a bundle (Subject, Issuer, Roots vs Intermediates vs Leaves, Expiry countdown, SHA-1/MD5 weak signature warnings, and duplicate detection).
* **Bundle Splitting**: Extracts every certificate from a bundle into individual `.pem` files named cleanly by CN and type (`01_root_DigiCert.pem`, `02_intermediate_SubCA.pem`).
* **Merge & Deduplicate**: Consolidates multiple certificate files or whole directories into a unified bundle, automatically filtering out duplicate certificates by SHA-256 fingerprint.
* **Hierarchical Chain Ordering (`order-chain`)**: Automatically sorts unordered certificate chains into the mandatory RFC hierarchy (`[Leaf] ➔ [Intermediate 1] ➔ [Intermediate 2] ➔ [Root CA]`) required by NGINX, Envoy, Apache, and Kubernetes TLS Ingress.
* **Trust Store Diffing**: Compares two CA bundles (e.g. OS truststore upgrade or Mozilla NSS vs Java cacerts) to highlight added, removed, and expired CAs.
* **Live Chain Fetching**: Connects to remote TLS endpoints (`host:port`) and dumps the served intermediate chain into a clean PEM bundle.
* **In-Bundle Search**: Finds certificates by CN, Organization, or Fingerprint inside massive enterprise bundles.

---

## 🛠️ Command Reference

```bash
ca-bundle-worker <COMMAND> [OPTIONS] [ARGUMENTS]
```

| Command | Description | Example |
| :--- | :--- | :--- |
| **`inspect`** | Audit and table-list all certificates in a bundle | `ca-bundle-worker inspect /etc/ssl/cert.pem` |
| **`split`** | Extract all certs into individual `.pem` files | `ca-bundle-worker split bundle.pem ./out-dir/` |
| **`merge`** | Merge & deduplicate multiple certs/dirs into one bundle | `ca-bundle-worker merge -o bundle.pem cert1.pem cert2.pem ./certs/` |
| **`order-chain`** | Reorder chain: Leaf ➔ Intermediates ➔ Root | `ca-bundle-worker order-chain unordered.pem -o fullchain.pem` |
| **`diff`** | Compare two CA bundles side-by-side | `ca-bundle-worker diff truststore-v1.pem truststore-v2.pem` |
| **`fetch`** | Download served chain from a live TLS endpoint | `ca-bundle-worker fetch google.com:443 -o google_chain.pem` |
| **`find`** | Search for certificates inside a bundle | `ca-bundle-worker find ca-bundle.crt "DigiCert"` |

---

## 📖 Recipes & Common Workflows

### 1. Audit an Enterprise Trust Store
Check for expired CAs or duplicate entries inside a corporate bundle:
```bash
ca-bundle-worker inspect enterprise-ca-bundle.pem
```

### 2. Fix an Unordered TLS Chain for Kubernetes / NGINX
Web servers fail TLS handshakes when the certificate chain is in the wrong order. Fix it in one step:
```bash
ca-bundle-worker order-chain unordered_chain.pem -o /etc/nginx/ssl/fullchain.pem
```

### 3. Build a Clean, Deduplicated CA Bundle
Combine certificates from multiple teams or directories into a clean single file:
```bash
ca-bundle-worker merge -o combined-ca.pem ./internal-cas/ ./partner-certs/ extra-root.pem
```

### 4. Extract Every Certificate From a Bundle
```bash
ca-bundle-worker split /etc/ssl/cert.pem ./extracted/
```

### 5. Diff Two CA Bundles
Check which CAs were added or removed between two trust store releases:
```bash
ca-bundle-worker diff old-ca-bundle.crt new-ca-bundle.crt
```

### 6. Fetch Live Chain From a Production Server
```bash
ca-bundle-worker fetch api.github.com:443 -o github_chain.pem
```

---

## 📄 License

MIT License. Maintained as part of [Daily-tools](https://github.com/khishoer/Daily-tools).
