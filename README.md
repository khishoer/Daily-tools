# 🧰 Daily Tools

A curated collection of production-grade automation scripts, network diagnostics, DevOps helpers, and developer utilities for daily engineering workflows.

---

## 📂 Repository Structure

```text
Daily-tools/
├── tools/                      # Dedicated modular tool packages
│   └── san-compare/            # 🔐 Leaf certificate & SAN deep comparison utility
│       ├── san-compare.sh      # Executable script
│       ├── README.md           # Comprehensive manual & recipes
│       └── tests/              # Test suite (scenarios, chronology, EKU)
│           ├── test_scenarios.sh
│           ├── test_chronology.sh
│           └── test_eku_scenarios.sh
├── cli/                        # CLI symlinks for quick global PATH execution
│   └── san-compare -> ../tools/san-compare/san-compare.sh
└── README.md
```

---

## 🛠️ Included Tools

### 🔐 1. SAN & Certificate Compare (`tools/san-compare/`)

A terminal tool that deeply compares two X.509 leaf certificates across all standard parameters, automatically identifies **Baseline vs Renewal Candidate** regardless of argument order, and calculates a side-by-side **Subject Alternative Name (SAN)** delta with critical EKU safety checks.

* **Supports**: Local files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`) and live remote endpoints (`https://example.com` or `host:port`).
* **Auto-Chronology**: Intelligently detects whether you passed `<baseline> <candidate>` or `<candidate> <baseline>`.
* **Side-by-Side Aligned Table**: Clear 2-column view of common (`==`), added (`+`), and removed (`-`) SAN entries with stripped `DNS:` clutter.
* **Safety Guards**: Detects fatal `serverAuth` loss, mTLS `clientAuth` breakage, and cryptographic shifts (RSA ➔ ECDSA).
* **Delta-Only Mode (`-d`)**: Suppresses identical rows to isolate changes on massive certificates.

#### Quick Usage:
```bash
# Focus strictly on differences (suppresses all identical parameters and SANs)
./tools/san-compare/san-compare.sh -d current_prod.crt new_candidate.crt

# Compare live production website against a local renewal candidate
./tools/san-compare/san-compare.sh https://example.com ./new_candidate.pem

# Compare two live hostnames
./tools/san-compare/san-compare.sh google.com:443 youtube.com:443

# Compare SANs only
./tools/san-compare/san-compare.sh --san-only prod.crt staging.crt

# Silent CI/CD mode (exit 0 if safe/identical, 1 if breaking differences)
./tools/san-compare/san-compare.sh --quiet cert1.pem cert2.pem
```

👉 **[Read the Full `san-compare` Manual & CI/CD Recipes](tools/san-compare/README.md)**

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

# Now run directly from any directory:
san-compare google.com:443 youtube.com:443
```

---

## 📄 License

MIT License. Feel free to use, modify, and distribute.
