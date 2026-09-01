# 🧰 Daily Tools

A curated collection of production-grade automation scripts, network diagnostics, DevOps helpers, and developer utilities for daily engineering workflows.

---

## 📂 Repository Structure

```text
Daily-tools/
├── tools/                      # Dedicated modular tool packages
│   ├── cert-compare/           # 🔐 Leaf certificate & SAN deep comparison utility
│   │   ├── cert-compare.sh     # Executable script
│   │   ├── README.md           # Comprehensive manual & recipes
│   │   └── tests/              # Test suite (scenarios, chronology, EKU)
│   │
│   └── ca-bundle-worker/       # 📦 CA bundle auditor, chain manager & trust store utility
│       ├── ca-bundle-worker.sh # Executable script
│       ├── README.md           # Comprehensive manual & recipes
│       └── tests/              # Test suite (inspect, split, merge, order, diff)
├── cli/                        # CLI symlinks for quick global PATH execution
│   ├── cert-compare -> ../tools/cert-compare/cert-compare.sh
│   └── ca-bundle-worker -> ../tools/ca-bundle-worker/ca-bundle-worker.sh
└── README.md
```

---

## 🛠️ Included Tools

### 🔐 1. Certificate & SAN Compare (`tools/cert-compare/`)

A terminal tool that deeply compares two X.509 leaf certificates across all standard parameters, automatically identifies **Baseline vs Renewal Candidate** regardless of argument order, and calculates a side-by-side **Subject Alternative Name (SAN)** delta with critical EKU safety checks.

* **Supports**: Local files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`) and live remote endpoints (`https://example.com` or `host:port`).
* **Auto-Chronology**: Intelligently detects whether you passed `<baseline> <candidate>` or `<candidate> <baseline>`.
* **Side-by-Side Aligned Table**: Clear 2-column view of common (`==`), added (`+`), and removed (`-`) SAN entries with stripped `DNS:` clutter.
* **Safety Guards**: Detects fatal `serverAuth` loss, mTLS `clientAuth` breakage, and cryptographic shifts (RSA ➔ ECDSA).
* **Delta-Only Mode (`-d`)**: Suppresses identical rows to isolate changes on massive certificates.

👉 **[Read the Full `cert-compare` Manual & Recipes](tools/cert-compare/README.md)**

---

### 📦 2. CA Bundle Worker (`tools/ca-bundle-worker/`)

A command-line tool for auditing, managing, and fixing multi-certificate CA bundles and TLS certificate chains.

* **`inspect`**: Audits every certificate in a bundle with expiry countdowns, duplicate detection, and weak hash alerts.
* **`split`**: Extracts multi-cert bundles into clean individual `.pem` files named by Common Name.
* **`merge`**: Merges files and directories into a single unified bundle with automatic SHA-256 deduplication.
* **`order-chain`**: Re-orders messy certificate chains into the proper RFC hierarchy (`[Leaf] ➔ [Intermediate] ➔ [Root]`) required by NGINX, Envoy, Cloudflare, and Kubernetes TLS.
* **`diff`**: Side-by-side comparison of two CA bundles to highlight added, removed, or expired CAs.
* **`fetch`**: Downloads the complete served TLS intermediate chain directly from any live server.

👉 **[Read the Full `ca-bundle-worker` Manual & Recipes](tools/ca-bundle-worker/README.md)**

---

## 🚀 Getting Started & Global CLI Setup

Clone the repository:
```bash
git clone https://github.com/khishoer/Daily-tools.git
cd Daily-tools
```

Add `cli/` to your PATH to run any tool directly by name:
```bash
export PATH="$HOME/tools/Daily-tools/cli:$PATH"

# Now run any tool directly from anywhere:
cert-compare google.com:443 youtube.com:443
ca-bundle-worker inspect /etc/ssl/cert.pem
```

---

## 📄 License

MIT License. Feel free to use, modify, and distribute.
