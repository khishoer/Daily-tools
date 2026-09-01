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
│   └── ca-bundle-worker/       # 🛡️ mTLS CA trust store worker & flapping monitor
│       ├── ca-bundle-worker.sh # Executable script
│       ├── README.md           # Comprehensive manual & recipes
│       └── tests/              # Test suite (audit, append, remove, probe, monitor)
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

### 🛡️ 2. mTLS CA Bundle Worker (`tools/ca-bundle-worker/`)

A command-line utility for auditing mTLS CA bundles, safely appending/removing CAs, probing server-advertised acceptable client CAs, and continuously monitoring live endpoints every 2 seconds for cloud drops and CA drifting.

* **`audit`**: Deep health check detecting expired CAs, duplicates, weak hashes, and non-CA leaf certificates accidentally bundled.
* **`append`**: Safely adds a new CA to the bundle with pre-validation and duplicate suppression.
* **`remove`**: Specifically prunes CAs by Common Name (`--cn`), SHA-256 fingerprint (`--fingerprint`), or prunes all expired CAs (`--expired`).
* **`probe`**: Probes an online FQDN to extract server-advertised **`Acceptable client certificate CA names`** and cross-references against your local bundle.
* **`monitor`**: Polls live endpoints **every 2 seconds over N duration** to catch intermittent network drops and backend pod CA drifting.

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

# Run tools directly from any directory:
cert-compare google.com:443 youtube.com:443
ca-bundle-worker audit /etc/ssl/client_cas.pem
ca-bundle-worker monitor api.internal.corp:443 --interval 2 --duration 60
```

---

## 📄 License

MIT License. Feel free to use, modify, and distribute.
