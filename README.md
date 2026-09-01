# 🛠️ Daily Tools

A curated collection of daily developer tools, automation scripts, CLI utilities, and productivity helpers.

---

## 📂 Repository Structure

```text
Daily-tools/
├── scripts/        # Automation scripts (Bash, Python, Zsh)
│   └── san-compare.sh  # Leaf certificate & SAN deep comparison utility
├── cli/            # CLI symlinks and wrapper utilities
│   └── san-compare -> ../scripts/san-compare.sh
├── configs/        # Dotfiles and tool configurations
└── docs/           # Usage cheat sheets and guides
```

---

## 🛠️ Included Tools

### 🔐 1. SAN Compare (`san-compare.sh`)

A terminal tool that deeply compares two X.509 leaf certificates across all standard parameters and calculates a complete Subject Alternative Name (SAN) delta (Added, Removed, Maintained).

* **Supports**: Local files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`) and live remote endpoints (`https://example.com` or `host:port`).
* **Parameters Checked**: Subject DN, Issuer DN, Serial Number, Signature Algorithm, Public Key & bit length, Not Before/After dates, Validity status, Key Usage, EKU, Basic Constraints, OCSP, SKI, AKI, SHA-256 / SHA-1 fingerprints.
* **SAN Delta**: Set difference calculation identifying exactly which DNS / IP entries were added, removed, or kept intact.

#### Usage:
```bash
# Focus strictly on differences (suppresses all identical parameters and SANs)
./scripts/san-compare.sh --only-diff cert_v1.pem cert_v2.pem
./scripts/san-compare.sh -d current_prod.crt new_candidate.crt

# Compare two local certificate files
./scripts/san-compare.sh cert_v1.pem cert_v2.pem

# Compare a local certificate against a live production endpoint
./scripts/san-compare.sh old_cert.crt https://example.com

# Compare two live hostnames
./scripts/san-compare.sh google.com:443 youtube.com:443

# Compare SANs only
./scripts/san-compare.sh --san-only prod.crt staging.crt

# Quiet mode (exit 0 if identical/safe, 1 if breaking differences)
./scripts/san-compare.sh --quiet cert1.pem cert2.pem
```

---

## 🚀 Getting Started

Clone the repository:
```bash
git clone https://github.com/khishoer/Daily-tools.git
cd Daily-tools
```
