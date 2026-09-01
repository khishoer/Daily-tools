#!/usr/bin/env bash
# ==============================================================================
# Script Name: ca-bundle-worker.sh
# Description: Production-grade CA Bundle Worker & Certificate Chain Manager.
#              Inspects, splits, merges, deduplicates, verifies, re-orders,
#              diffs, and fetches TLS CA bundles and certificate chains.
# Author: Daily Tools (https://github.com/khishoer/Daily-tools)
# Requirements: bash, openssl, python3
# ==============================================================================

# ------------------------------------------------------------------------------
# Help & Usage
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage:
  ca-bundle-worker.sh <COMMAND> [OPTIONS] [ARGUMENTS]

Description:
  High-ergonomics CA bundle auditor, certificate chain manager, and PKI utility.
  Perform deep inspection, splitting, merging, deduplication, chain re-ordering,
  and cross-bundle diffing.

Commands:
  inspect       Audit & list all certificates inside a bundle (expiry, weak crypto, duplicates)
  split         Extract every certificate in a bundle into individual clean files
  merge         Merge multiple certificates / directories into a deduplicated bundle
  order-chain   Re-order a certificate chain into valid hierarchy (Leaf ➔ Intermediates ➔ Root)
  diff          Compare two CA bundles side-by-side (added, removed, updated CAs)
  fetch         Download the full served certificate chain from a remote TLS endpoint
  find          Search for certificates by CN, Organization, or Fingerprint inside a bundle

Global Options:
  -n, --no-color       Disable color output
  -w, --width <cols>   Set custom terminal width (default: 108)
  -h, --help           Show this help message

Command Examples:
  # 1. Inspect and audit a CA bundle
  ca-bundle-worker.sh inspect /etc/ssl/cert.pem
  ca-bundle-worker.sh inspect enterprise-bundle.crt

  # 2. Split a multi-cert bundle into individual .pem files
  ca-bundle-worker.sh split bundle.pem ./extracted-certs/

  # 3. Merge & deduplicate multiple certificates into one clean bundle
  ca-bundle-worker.sh merge -o combined-bundle.pem cert1.pem cert2.pem ./ca-dir/

  # 4. Fix & reorder an unordered TLS chain for NGINX/Envoy/Kubernetes
  ca-bundle-worker.sh order-chain unordered_chain.pem -o fullchain.pem

  # 5. Compare two CA bundles (e.g. Old vs New enterprise truststore)
  ca-bundle-worker.sh diff ca-bundle-v1.crt ca-bundle-v2.crt

  # 6. Fetch live chain from remote server
  ca-bundle-worker.sh fetch google.com:443 -o google_chain.pem

  # 7. Search inside a bundle
  ca-bundle-worker.sh find ca-bundle.crt "DigiCert"

EOF
}

# ------------------------------------------------------------------------------
# Command Routing
# ------------------------------------------------------------------------------
if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

COMMAND="$1"
shift

# Handle Global flags if passed before command
NO_COLOR_FLAG=0
CUSTOM_WIDTH=108

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -n|--no-color)
            NO_COLOR_FLAG=1
            shift
            ;;
        -w|--width)
            CUSTOM_WIDTH="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Python Execution Engine for CA Bundle Operations
# ------------------------------------------------------------------------------
python3 - << 'EOF' "$COMMAND" "$NO_COLOR_FLAG" "$CUSTOM_WIDTH" "${ARGS[@]}"
import sys
import os
import re
import subprocess
from datetime import datetime, timezone

command = sys.argv[1]
no_color = (sys.argv[2] == '1') or ('NO_COLOR' in os.environ)
total_width = int(sys.argv[3]) if sys.argv[3].isdigit() else 108
args = sys.argv[4:]

# ------------------------------------------------------------------------------
# Color formatting
# ------------------------------------------------------------------------------
class C:
    if not no_color and sys.stdout.isatty():
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        ITALIC = "\033[3m"
        
        RED = "\033[38;5;203m"
        GREEN = "\033[38;5;120m"
        YELLOW = "\033[38;5;221m"
        BLUE = "\033[38;5;75m"
        MAGENTA = "\033[38;5;176m"
        CYAN = "\033[38;5;80m"
        WHITE = "\033[38;5;255m"
        GRAY = "\033[38;5;244m"
        DARK_GRAY = "\033[38;5;238m"
        
        BG_RED = "\033[48;5;196;38;5;255;1m"
        BG_GREEN = "\033[48;5;28;38;5;255;1m"
        BG_YELLOW = "\033[48;5;214;38;5;16;1m"
        BG_BLUE = "\033[48;5;31;38;5;255;1m"
        BG_DARK = "\033[48;5;236;38;5;255m"
    else:
        RESET = BOLD = DIM = ITALIC = ""
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = GRAY = DARK_GRAY = ""
        BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = BG_DARK = ""

def visible_len(s):
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))

def pad_to(s, width, align='left'):
    v_len = visible_len(s)
    pad = max(0, width - v_len)
    if align == 'center':
        left_pad = pad // 2
        right_pad = pad - left_pad
        return " " * left_pad + s + " " * right_pad
    elif align == 'right':
        return " " * pad + s
    else:
        return s + " " * pad

def run_cmd(cmd, stdin_text=None):
    try:
        res = subprocess.run(cmd, shell=True, input=stdin_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.stdout.strip()
    except Exception:
        return ""

def extract_certs_from_bundle(content):
    """Parses a multi-cert PEM text block into a list of individual cert PEM strings."""
    certs = []
    current = []
    inside = False
    
    for line in content.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line or "-----BEGIN X509 CERTIFICATE-----" in line or "-----BEGIN TRUSTED CERTIFICATE-----" in line:
            inside = True
            current = ["-----BEGIN CERTIFICATE-----"]
        elif inside:
            if "-----END CERTIFICATE-----" in line or "-----END X509 CERTIFICATE-----" in line or "-----END TRUSTED CERTIFICATE-----" in line:
                current.append("-----END CERTIFICATE-----")
                certs.append("\n".join(current))
                current = []
                inside = False
            else:
                current.append(line.strip())
    return certs

def parse_single_cert(pem_str):
    """Extracts parsed metadata for a single certificate PEM block."""
    d = {'pem': pem_str}
    
    # Subject & Issuer
    d['subject_dn'] = run_cmd("openssl x509 -noout -subject -nameopt RFC2253", pem_str).replace("subject=", "").strip()
    d['issuer_dn'] = run_cmd("openssl x509 -noout -issuer -nameopt RFC2253", pem_str).replace("issuer=", "").strip()
    
    # Subject CN & Org
    subj_raw = run_cmd("openssl x509 -noout -subject", pem_str)
    d['subject_cn'] = subj_raw.split("CN=")[-1].split(",")[0].strip() if "CN=" in subj_raw else (d['subject_dn'] or "Unknown")
    d['subject_org'] = subj_raw.split("O=")[-1].split(",")[0].strip() if "O=" in subj_raw else ""
    
    issuer_raw = run_cmd("openssl x509 -noout -issuer", pem_str)
    d['issuer_cn'] = issuer_raw.split("CN=")[-1].split(",")[0].strip() if "CN=" in issuer_raw else (d['issuer_dn'] or "Unknown")
    
    d['serial'] = run_cmd("openssl x509 -noout -serial", pem_str).replace("serial=", "").strip()
    
    # Dates
    nb_raw = run_cmd("openssl x509 -noout -startdate", pem_str).replace("notBefore=", "").strip()
    na_raw = run_cmd("openssl x509 -noout -enddate", pem_str).replace("notAfter=", "").strip()
    d['not_before'] = nb_raw
    d['not_after'] = na_raw
    
    d['dt_not_after'] = None
    try:
        cleaned = " ".join(na_raw.split())
        d['dt_not_after'] = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        pass
        
    now = datetime.now(timezone.utc)
    if d['dt_not_after']:
        d['days_remaining'] = (d['dt_not_after'] - now).days
        d['is_expired'] = d['days_remaining'] < 0
        d['expires_soon'] = (0 <= d['days_remaining'] <= 30)
    else:
        d['days_remaining'] = 0
        d['is_expired'] = False
        d['expires_soon'] = False

    # Public Key & Sig Algo
    txt = run_cmd("openssl x509 -noout -text", pem_str)
    pk_algo = ""
    pk_size = ""
    for line in txt.splitlines():
        if "Public Key Algorithm:" in line:
            pk_algo = line.split(":")[-1].strip()
        elif "RSA Public-Key:" in line or "Public-Key:" in line:
            pk_size = line.split("(")[-1].replace(")", "").strip()
        elif "NIST CURVE:" in line or "ASN1 OID:" in line:
            pk_size = line.split(":")[-1].strip()
    d['pubkey_info'] = f"{pk_algo} ({pk_size})" if pk_size else (pk_algo or "Unknown")
    
    sig_raw = run_cmd("openssl x509 -noout -text | grep 'Signature Algorithm:' | head -n 1", pem_str)
    d['sig_algo'] = sig_raw.split(":")[-1].strip() if ":" in sig_raw else "Unknown"
    d['is_weak_sig'] = any(w in d['sig_algo'].lower() for w in ['md5', 'sha1'])
    
    # Is Root / CA
    bc = run_cmd("openssl x509 -noout -ext basicConstraints | grep -v 'Basic Constraints'", pem_str).strip()
    d['is_ca'] = "CA:TRUE" in bc or "CA: TRUE" in bc
    d['is_self_signed'] = (d['subject_dn'] == d['issuer_dn'] and bool(d['subject_dn']))
    d['is_root'] = d['is_ca'] and d['is_self_signed']
    
    d['sha256'] = run_cmd("openssl x509 -noout -fingerprint -sha256", pem_str).split("=")[-1].strip()
    d['ski'] = run_cmd("openssl x509 -noout -ext subjectKeyIdentifier | grep -v 'SubjectKeyIdentifier'", pem_str).strip()
    d['aki'] = run_cmd("openssl x509 -noout -ext authorityKeyIdentifier | grep -A 1 'keyid:' | grep 'keyid:' | sed 's/.*keyid://'", pem_str).strip()
    
    # SANs
    san_raw = run_cmd("openssl x509 -noout -ext subjectAltName | grep -v 'Subject Alternative Name'", pem_str)
    d['san_count'] = len([s for s in san_raw.split(",") if s.strip()]) if san_raw else 0
    return d

def load_bundle_file(filepath):
    if not os.path.exists(filepath):
        print(f"{C.RED}[ERROR] File not found: '{filepath}'{C.RESET}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"{C.RED}[ERROR] Failed to read '{filepath}': {e}{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    raw_certs = extract_certs_from_bundle(content)
    if not raw_certs:
        # Check if DER / PKCS7
        converted = run_cmd(f"openssl pkcs7 -in '{filepath}' -print_certs 2>/dev/null")
        if converted:
            raw_certs = extract_certs_from_bundle(converted)
            
    if not raw_certs:
        # Try single cert
        single_pem = run_cmd(f"openssl x509 -in '{filepath}' -outform PEM 2>/dev/null")
        if single_pem:
            raw_certs = [single_pem]

    if not raw_certs:
        print(f"{C.RED}[ERROR] No valid X.509 certificates found in '{filepath}'{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    return [parse_single_cert(c) for c in raw_certs]

# ------------------------------------------------------------------------------
# 1. COMMAND: INSPECT
# ------------------------------------------------------------------------------
def cmd_inspect():
    if not args:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker inspect <bundle_path>{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    bundle_path = args[0]
    certs = load_bundle_file(bundle_path)
    
    # Metrics
    total = len(certs)
    roots = sum(1 for c in certs if c['is_root'])
    intermediates = sum(1 for c in certs if c['is_ca'] and not c['is_root'])
    leaves = sum(1 for c in certs if not c['is_ca'])
    expired = sum(1 for c in certs if c['is_expired'])
    expiring_soon = sum(1 for c in certs if c['expires_soon'])
    weak = sum(1 for c in certs if c['is_weak_sig'])
    
    # Duplicates check
    fps = [c['sha256'] for c in certs]
    duplicates = len(fps) - len(set(fps))

    inner_w = total_width - 4
    
    print()
    print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}📦 CA BUNDLE INSPECTION & AUDIT REPORT{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Target Bundle:{C.RESET} {C.YELLOW}{bundle_path:<{inner_w - 18}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    
    # Dashboard line
    stat_tot = f"{C.WHITE}{C.BOLD}{total} Total Cert(s){C.RESET}"
    stat_roots = f"{C.CYAN}{roots} Roots{C.RESET}"
    stat_inter = f"{C.BLUE}{intermediates} Intermediates{C.RESET}"
    stat_leaf = f"{C.MAGENTA}{leaves} Leaves{C.RESET}"
    stat_exp = f"{C.RED}{C.BOLD}{expired} Expired{C.RESET}" if expired > 0 else f"{C.GREEN}0 Expired{C.RESET}"
    stat_soon = f"{C.YELLOW}{expiring_soon} Expiring <30d{C.RESET}" if expiring_soon > 0 else ""
    stat_dup = f"{C.RED}{C.BOLD}{duplicates} Dupes!{C.RESET}" if duplicates > 0 else ""
    stat_weak = f"{C.RED}{C.BOLD}{weak} Weak (SHA-1/MD5)!{C.RESET}" if weak > 0 else ""

    dash_parts = [stat_tot, stat_roots, stat_inter]
    if leaves > 0: dash_parts.append(stat_leaf)
    dash_parts.append(stat_exp)
    if stat_soon: dash_parts.append(stat_soon)
    if stat_dup: dash_parts.append(stat_dup)
    if stat_weak: dash_parts.append(stat_weak)

    dash_line = "  📊 " + "  │  ".join(dash_parts)
    print(f"{C.CYAN}│{C.RESET} {pad_to(dash_line, inner_w)} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")

    # Table of Certs
    print()
    sec_title = f"CERTIFICATES IN BUNDLE ({total})"
    c_idx_w = 4
    c_cn_w = 34
    c_issuer_w = 26
    c_type_w = 11
    c_exp_w = 18
    
    t_top = f"╭─ {C.BOLD}{C.WHITE}{sec_title}{C.RESET} " + "─" * max(0, total_width - len(sec_title) - 5) + "╮"
    t_head = f"│ {pad_to(f'{C.BOLD}#{C.RESET}', c_idx_w)} │ {pad_to(f'{C.BOLD}{C.CYAN}SUBJECT (COMMON NAME){C.RESET}', c_cn_w)} │ {pad_to(f'{C.BOLD}{C.WHITE}ISSUER CN{C.RESET}', c_issuer_w)} │ {pad_to(f'{C.BOLD}TYPE{C.RESET}', c_type_w)} │ {pad_to(f'{C.BOLD}EXPIRY / STATUS{C.RESET}', c_exp_w)} │"
    t_sep = f"├" + "─" * (c_idx_w + 2) + "┼" + "─" * (c_cn_w + 2) + "┼" + "─" * (c_issuer_w + 2) + "┼" + "─" * (c_type_w + 2) + "┼" + "─" * (c_exp_w + 2) + "┤"
    t_bot = f"╰" + "─" * (c_idx_w + 2) + "┴" + "─" * (c_cn_w + 2) + "┴" + "─" * (c_issuer_w + 2) + "┴" + "─" * (c_type_w + 2) + "┴" + "─" * (c_exp_w + 2) + "╯"

    print(f"{C.CYAN}{t_top}{C.RESET}")
    print(f"{C.CYAN}{t_head}{C.RESET}")
    print(f"{C.CYAN}{t_sep}{C.RESET}")

    for idx, c in enumerate(certs, 1):
        cn_disp = c['subject_cn'][:c_cn_w] if len(c['subject_cn']) <= c_cn_w else (c['subject_cn'][:c_cn_w-3] + "...")
        iss_disp = c['issuer_cn'][:c_issuer_w] if len(c['issuer_cn']) <= c_issuer_w else (c['issuer_cn'][:c_issuer_w-3] + "...")
        
        # Type
        if c['is_root']:
            type_badge = f"{C.BG_BLUE} ROOT CA {C.RESET}"
        elif c['is_ca']:
            type_badge = f"{C.CYAN}INTERMEDIATE{C.RESET}"
        else:
            type_badge = f"{C.MAGENTA}LEAF CERT{C.RESET}"

        # Status / Expiry
        if c['is_expired']:
            exp_disp = f"{C.RED}{C.BOLD}EXPIRED ({abs(c['days_remaining'])}d ago){C.RESET}"
        elif c['expires_soon']:
            exp_disp = f"{C.YELLOW}{C.BOLD}{c['days_remaining']}d left (<30d){C.RESET}"
        else:
            exp_disp = f"{C.GREEN}{c['days_remaining']}d left{C.RESET}"

        idx_str = pad_to(str(idx), c_idx_w, 'right')
        cn_col = pad_to(f"{C.WHITE}{cn_disp}{C.RESET}", c_cn_w)
        iss_col = pad_to(f"{C.GRAY}{iss_disp}{C.RESET}", c_issuer_w)
        type_col = pad_to(type_badge, c_type_w)
        exp_col = pad_to(exp_disp, c_exp_w)

        print(f"{C.CYAN}│{C.RESET} {idx_str} {C.CYAN}│{C.RESET} {cn_col} {C.CYAN}│{C.RESET} {iss_col} {C.CYAN}│{C.RESET} {type_col} {C.CYAN}│{C.RESET} {exp_col} {C.CYAN}│{C.RESET}")

    print(f"{C.CYAN}{t_bot}{C.RESET}\n")

# ------------------------------------------------------------------------------
# 2. COMMAND: SPLIT
# ------------------------------------------------------------------------------
def cmd_split():
    if not args:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker split <bundle_path> [output_dir]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    bundle_path = args[0]
    out_dir = args[1] if len(args) > 1 else "./extracted-certs"
    certs = load_bundle_file(bundle_path)
    
    os.makedirs(out_dir, exist_ok=True)
    
    print(f"\n{C.CYAN}[*] Extracting {len(certs)} certificate(s) from '{bundle_path}' into '{out_dir}'...{C.RESET}\n")
    
    for idx, c in enumerate(certs, 1):
        # Sanitize filename
        clean_name = re.sub(r'[^a-zA-Z0-9._-]', '_', c['subject_cn'])
        c_type = "root" if c['is_root'] else ("intermediate" if c['is_ca'] else "leaf")
        filename = f"{idx:02d}_{c_type}_{clean_name[:40]}.pem"
        filepath = os.path.join(out_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(f"# Subject: {c['subject_dn']}\n")
            f.write(f"# Issuer:  {c['issuer_dn']}\n")
            f.write(f"# SHA256:  {c['sha256']}\n")
            f.write(f"# Valid:   {c['not_before']} to {c['not_after']}\n")
            f.write(c['pem'] + "\n")
            
        print(f"  {C.GREEN}✔{C.RESET} [{idx:02d}/{len(certs):02d}] Extracted: {C.BOLD}{filename}{C.RESET} ({c['subject_cn']})")
        
    print(f"\n{C.GREEN}{C.BOLD}✔ Successfully extracted {len(certs)} certificates into '{out_dir}'.{C.RESET}\n")

# ------------------------------------------------------------------------------
# 3. COMMAND: MERGE & DEDUPLICATE
# ------------------------------------------------------------------------------
def cmd_merge():
    out_file = "merged-bundle.pem"
    inputs = []
    
    i = 0
    while i < len(args):
        if args[i] in ['-o', '--out', '--output']:
            if i + 1 < len(args):
                out_file = args[i+1]
                i += 2
                continue
        else:
            inputs.append(args[i])
            i += 1
            
    if not inputs:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker merge -o <output.pem> <file1> <file2> ... [dir/]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    all_files = []
    for inp in inputs:
        if os.path.isdir(inp):
            for root, _, files in os.walk(inp):
                for f in files:
                    if f.endswith(('.pem', '.crt', '.cer', '.bundle')):
                        all_files.append(os.path.join(root, f))
        elif os.path.isfile(inp):
            all_files.append(inp)
            
    if not all_files:
        print(f"{C.RED}[ERROR] No certificate files found in provided inputs.{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    print(f"\n{C.CYAN}[*] Merging and deduplicating certificates from {len(all_files)} file(s)...{C.RESET}")
    
    seen_fps = set()
    unique_certs = []
    duplicate_count = 0
    
    for fpath in all_files:
        try:
            certs = load_bundle_file(fpath)
            for c in certs:
                if c['sha256'] in seen_fps:
                    duplicate_count += 1
                else:
                    seen_fps.add(c['sha256'])
                    unique_certs.append(c)
        except Exception as e:
            print(f"  {C.YELLOW}⚠ Warning: Skipped {fpath}: {e}{C.RESET}", file=sys.stderr)

    with open(out_file, 'w') as f:
        f.write(f"# CA Bundle generated by ca-bundle-worker on {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total Unique Certificates: {len(unique_certs)}\n\n")
        for c in unique_certs:
            f.write(f"# Subject: {c['subject_dn']}\n")
            f.write(f"# Issuer:  {c['issuer_dn']}\n")
            f.write(f"# SHA256:  {c['sha256']}\n")
            f.write(c['pem'] + "\n\n")
            
    print(f"\n{C.GREEN}{C.BOLD}✔ Successfully wrote {len(unique_certs)} unique certificates to '{out_file}'.{C.RESET}")
    if duplicate_count > 0:
        print(f"  {C.YELLOW}ℹ Filtered out {duplicate_count} duplicate certificate(s).{C.RESET}\n")

# ------------------------------------------------------------------------------
# 4. COMMAND: ORDER-CHAIN (Hierarchical Ordering: Leaf ➔ Intermediates ➔ Root)
# ------------------------------------------------------------------------------
def cmd_order_chain():
    out_file = None
    input_file = None
    
    i = 0
    while i < len(args):
        if args[i] in ['-o', '--out', '--output']:
            if i + 1 < len(args):
                out_file = args[i+1]
                i += 2
                continue
        elif not input_file:
            input_file = args[i]
            i += 1
        else:
            i += 1
            
    if not input_file:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker order-chain <chain.pem> [-o ordered.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    certs = load_bundle_file(input_file)
    if len(certs) <= 1:
        print(f"{C.YELLOW}ℹ Only 1 certificate in file. No chain re-ordering needed.{C.RESET}")
        return

    print(f"\n{C.CYAN}[*] Analyzing and ordering certificate chain for '{input_file}'...{C.RESET}")
    
    # Identify Leaf (not a CA or whose subject is not an issuer for any cert in the set)
    # Build issuer map: Subject DN -> Cert
    subj_map = {c['subject_dn']: c for c in certs}
    iss_map = {c['issuer_dn']: c for c in certs}
    
    leaf_candidates = [c for c in certs if not c['is_ca']]
    if not leaf_candidates:
        leaf_candidates = [c for c in certs if not c['is_root']]
    
    if not leaf_candidates:
        leaf = certs[0]
    else:
        leaf = leaf_candidates[0]

    # Reconstruct chain from leaf upwards
    ordered = [leaf]
    curr = leaf
    visited = {leaf['sha256']}
    
    while True:
        if curr['is_root']:
            break
        # Find who issued curr
        issuer_cert = subj_map.get(curr['issuer_dn'])
        if not issuer_cert:
            # Fallback check by AKI/SKI
            for c in certs:
                if c['ski'] and curr['aki'] and c['ski'] == curr['aki']:
                    issuer_cert = c
                    break
                    
        if issuer_cert and issuer_cert['sha256'] not in visited:
            ordered.append(issuer_cert)
            visited.add(issuer_cert['sha256'])
            curr = issuer_cert
        else:
            break
            
    # Add any remaining unlinked certs at the end
    for c in certs:
        if c['sha256'] not in visited:
            ordered.append(c)
            visited.add(c['sha256'])

    print(f"\n{C.BOLD}{C.WHITE}Hierarchical Certificate Chain Flow:{C.RESET}")
    for idx, c in enumerate(ordered):
        indent = "  " * idx
        arrow = "└── " if idx > 0 else "    "
        c_type = "[ ROOT CA ]" if c['is_root'] else ("[ INTERMEDIATE CA ]" if c['is_ca'] else "[ LEAF CERT ]")
        print(f"  {indent}{C.CYAN}{arrow}{C.RESET}{C.BOLD}{c['subject_cn']}{C.RESET} {C.DIM}{c_type}{C.RESET}")

    if out_file:
        with open(out_file, 'w') as f:
            for c in ordered:
                f.write(c['pem'] + "\n")
        print(f"\n{C.GREEN}{C.BOLD}✔ Successfully wrote properly ordered fullchain to '{out_file}'.{C.RESET}\n")

# ------------------------------------------------------------------------------
# 5. COMMAND: DIFF (Compare two CA bundles)
# ------------------------------------------------------------------------------
def cmd_diff():
    if len(args) < 2:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker diff <bundle1.pem> <bundle2.pem>{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    b1_path = args[0]
    b2_path = args[1]
    
    c1_list = load_bundle_file(b1_path)
    c2_list = load_bundle_file(b2_path)
    
    c1_map = {c['sha256']: c for c in c1_list}
    c2_map = {c['sha256']: c for c in c2_list}
    
    fps1 = set(c1_map.keys())
    fps2 = set(c2_map.keys())
    
    common_fps = fps1 & fps2
    removed_fps = fps1 - fps2  # in 1, not in 2
    added_fps = fps2 - fps1    # in 2, not in 1

    inner_w = total_width - 4

    print()
    print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}📊 CA BUNDLE COMPARISON & TRUST STORE DIFF{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Bundle [1]:{C.RESET} {C.YELLOW}{b1_path:<{inner_w - 14}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Bundle [2]:{C.RESET} {C.YELLOW}{b2_path:<{inner_w - 14}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

    diff_summary = f"  • Common CAs: {C.GREEN}{len(common_fps)}{C.RESET}  │  • Added in [2]: {C.CYAN}+{len(added_fps)}{C.RESET}  │  • Removed from [1]: {C.RED}-{len(removed_fps)}{C.RESET}"
    print(f"{C.CYAN}│{C.RESET} {pad_to(diff_summary, inner_w)} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")

    if added_fps:
        print(f"\n{C.CYAN}{C.BOLD}➕ Certificates Added in Bundle [2] ({len(added_fps)}):{C.RESET}")
        for fp in sorted(added_fps):
            c = c2_map[fp]
            print(f"  {C.CYAN}+{C.RESET} {C.BOLD}{c['subject_cn']}{C.RESET} (Issuer: {c['issuer_cn']}) [Expires: {c['not_after']}]")

    if removed_fps:
        print(f"\n{C.RED}{C.BOLD}➖ Certificates Removed from Bundle [1] ({len(removed_fps)}):{C.RESET}")
        for fp in sorted(removed_fps):
            c = c1_map[fp]
            print(f"  {C.RED}-{C.RESET} {C.BOLD}{c['subject_cn']}{C.RESET} (Issuer: {c['issuer_cn']}) [Expires: {c['not_after']}]")

    if not added_fps and not removed_fps:
        print(f"\n{C.GREEN}{C.BOLD}✔ Both CA bundles contain the exact same {len(common_fps)} certificates (0 differences).{C.RESET}\n")
    else:
        print()

# ------------------------------------------------------------------------------
# 6. COMMAND: FETCH LIVE CHAIN
# ------------------------------------------------------------------------------
def cmd_fetch():
    out_file = None
    target = None
    
    i = 0
    while i < len(args):
        if args[i] in ['-o', '--out', '--output']:
            if i + 1 < len(args):
                out_file = args[i+1]
                i += 2
                continue
        elif not target:
            target = args[i]
            i += 1
        else:
            i += 1
            
    if not target:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker fetch <host:port> [-o chain.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = "443"
    if ":" in host:
        host, port = host.split(":", 1)
        
    print(f"\n{C.CYAN}[*] Connecting to {host}:{port} and retrieving served certificate chain...{C.RESET}")
    
    raw_chain = run_cmd(f"echo | openssl s_client -servername '{host}' -connect '{host}:{port}' -showcerts 2>/dev/null")
    certs = [parse_single_cert(c) for c in extract_certs_from_bundle(raw_chain)]
    
    if not certs:
        print(f"{C.RED}[ERROR] Failed to fetch certificate chain from {host}:{port}{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    print(f"\n{C.GREEN}{C.BOLD}✔ Retrieved {len(certs)} certificate(s) in served chain:{C.RESET}")
    for idx, c in enumerate(certs, 1):
        c_type = "Leaf" if idx == 1 else "Intermediate CA"
        print(f"  [{idx}] {C.BOLD}{c['subject_cn']}{C.RESET} ({c_type}) ➔ Issuer: {c['issuer_cn']}")
        
    if out_file:
        with open(out_file, 'w') as f:
            for c in certs:
                f.write(c['pem'] + "\n")
        print(f"\n{C.GREEN}{C.BOLD}✔ Saved chain to '{out_file}'.{C.RESET}\n")

# ------------------------------------------------------------------------------
# 7. COMMAND: FIND
# ------------------------------------------------------------------------------
def cmd_find():
    if len(args) < 2:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker find <bundle.pem> <query>{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    bundle_path = args[0]
    query = args[1].lower()
    certs = load_bundle_file(bundle_path)
    
    matches = []
    for c in certs:
        if query in c['subject_dn'].lower() or query in c['issuer_dn'].lower() or query in c['sha256'].lower() or query in c['serial'].lower():
            matches.append(c)
            
    print(f"\n{C.CYAN}[*] Searching for '{query}' in '{bundle_path}' ({len(certs)} total certs)...{C.RESET}")
    print(f"{C.BOLD}Found {len(matches)} matching certificate(s):{C.RESET}\n")
    
    for idx, c in enumerate(matches, 1):
        print(f"  {C.CYAN}[{idx}]{C.RESET} {C.BOLD}{c['subject_cn']}{C.RESET}")
        print(f"      • Subject: {c['subject_dn']}")
        print(f"      • Issuer:  {c['issuer_dn']}")
        print(f"      • SHA-256: {c['sha256']}")
        print(f"      • Status:  {c['days_remaining']} days remaining (Expires: {c['not_after']})\n")

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------
if command == 'inspect':
    cmd_inspect()
elif command == 'split':
    cmd_split()
elif command == 'merge':
    cmd_merge()
elif command in ['order-chain', 'order']:
    cmd_order_chain()
elif command == 'diff':
    cmd_diff()
elif command == 'fetch':
    cmd_fetch()
elif command in ['find', 'search']:
    cmd_find()
else:
    print(f"{C.RED}[ERROR] Unknown command: '{command}'{C.RESET}\n", file=sys.stderr)
    sys.exit(1)
EOF
