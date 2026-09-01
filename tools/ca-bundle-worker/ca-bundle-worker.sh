#!/usr/bin/env bash
# ==============================================================================
# Script Name: ca-bundle-worker.sh
# Description: Production-grade mTLS CA Bundle Worker & Flapping Monitor.
#              Audits mTLS bundles (duplicates, expired, non-CA leaves, weak crypto),
#              safely appends/removes CAs, probes online FQDN acceptable client CAs,
#              and continuously monitors for intermittent cloud drops & CA flapping.
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
  mTLS CA Bundle Worker, Trust Store Maintenance, and Flapping Monitor.
  Audits client-auth CA bundles for issues, mutates CAs (append/remove), probes
  server-advertised acceptable mTLS CAs, and monitors online endpoints every 2s
  over a specified duration for intermittent cloud drops and CA drifting.

Commands:
  audit         Deep health audit of mTLS bundle (duplicates, expired, non-CA leaves, weak crypto)
  append        Safely add a new CA to the bundle (with validation & duplicate checks)
  remove        Remove specific CAs by Common Name, SHA-256 fingerprint, or prune all expired CAs
  probe         Probe an online FQDN for server-advertised Acceptable Client CAs (mTLS CertificateRequest)
  monitor       Poll an online FQDN every 2s over N period to detect intermittent CA drops & backend flapping
  split         Extract every certificate in a bundle into individual clean .pem files
  merge         Consolidate multiple files/directories into one deduplicated CA bundle

Global Options:
  -n, --no-color       Disable color output
  -w, --width <cols>   Set custom terminal width (default: 108)
  -h, --help           Show this help message

Command Examples:
  # 1. Audit an mTLS CA bundle for health issues & security bugs
  ca-bundle-worker.sh audit mtls-ca-bundle.pem

  # 2. Safely append a new CA to the bundle
  ca-bundle-worker.sh append mtls-ca-bundle.pem new-subca.crt
  ca-bundle-worker.sh append mtls-ca-bundle.pem new-subca.crt -o updated-bundle.pem

  # 3. Remove a CA by Common Name or fingerprint
  ca-bundle-worker.sh remove mtls-ca-bundle.pem --cn "Old Enterprise Root CA"
  ca-bundle-worker.sh remove mtls-ca-bundle.pem --fingerprint "A1:B2:C3:..."
  ca-bundle-worker.sh remove mtls-ca-bundle.pem --expired

  # 4. Probe an online FQDN for acceptable client certificate CAs
  ca-bundle-worker.sh probe api.internal.corp:443
  ca-bundle-worker.sh probe https://gateway.corp --bundle local-mtls-bundle.pem

  # 5. Monitor an online FQDN every 2 seconds for 60s to detect intermittent CA drops & pod flapping
  ca-bundle-worker.sh monitor api.internal.corp:443 --interval 2 --duration 60
  ca-bundle-worker.sh monitor https://mtls.corp --duration 30 --bundle mtls-ca-bundle.pem

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
# Python Execution Engine for mTLS CA Bundle Operations
# ------------------------------------------------------------------------------
python3 - << 'EOF' "$COMMAND" "$NO_COLOR_FLAG" "$CUSTOM_WIDTH" "${ARGS[@]}"
import sys
import os
import re
import time
import socket
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
        BG_CYAN = "\033[48;5;30;38;5;255;1m"
        BG_DARK = "\033[48;5;236;38;5;255m"
    else:
        RESET = BOLD = DIM = ITALIC = ""
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = GRAY = DARK_GRAY = ""
        BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = BG_CYAN = BG_DARK = ""

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

def run_cmd(cmd, stdin_text=None, timeout=10):
    try:
        res = subprocess.run(cmd, shell=True, input=stdin_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
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
    """Extracts deep parsed metadata for an X.509 certificate."""
    d = {'pem': pem_str}
    
    d['subject_dn'] = run_cmd("openssl x509 -noout -subject -nameopt RFC2253", pem_str).replace("subject=", "").strip()
    d['issuer_dn'] = run_cmd("openssl x509 -noout -issuer -nameopt RFC2253", pem_str).replace("issuer=", "").strip()
    
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

    # Key size & algo
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
    
    # Is Root / CA / Leaf
    bc = run_cmd("openssl x509 -noout -ext basicConstraints | grep -v 'Basic Constraints'", pem_str).strip()
    d['is_ca'] = "CA:TRUE" in bc or "CA: TRUE" in bc
    d['is_self_signed'] = (d['subject_dn'] == d['issuer_dn'] and bool(d['subject_dn']))
    d['is_root'] = d['is_ca'] and d['is_self_signed']
    d['is_leaf'] = not d['is_ca']  # Non-CA certificate!
    
    # Key Usage check
    ku_raw = run_cmd("openssl x509 -noout -ext keyUsage | grep -v 'Key Usage'", pem_str).strip()
    d['key_usage'] = ku_raw
    d['has_cert_sign'] = "Certificate Sign" in ku_raw or "keyCertSign" in ku_raw
    
    d['sha256'] = run_cmd("openssl x509 -noout -fingerprint -sha256", pem_str).split("=")[-1].strip()
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
        # Check if PKCS7
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
# 1. COMMAND: AUDIT (Deep health check for mTLS bundle)
# ------------------------------------------------------------------------------
def cmd_audit():
    if not args:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker audit <bundle_path>{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    bundle_path = args[0]
    certs = load_bundle_file(bundle_path)
    
    total = len(certs)
    roots = sum(1 for c in certs if c['is_root'])
    intermediates = sum(1 for c in certs if c['is_ca'] and not c['is_root'])
    leaves = sum(1 for c in certs if c['is_leaf'])
    expired = sum(1 for c in certs if c['is_expired'])
    expiring_soon = sum(1 for c in certs if c['expires_soon'])
    weak = sum(1 for c in certs if c['is_weak_sig'])
    
    # Duplicate Analysis
    fps = [c['sha256'] for c in certs]
    dupe_fps = [fp for fp in set(fps) if fps.count(fp) > 1]
    duplicate_count = len(fps) - len(set(fps))
    
    # Subject CN collisions (different certs with identical Subject CN)
    cns = [c['subject_cn'] for c in certs]
    cn_collisions = [cn for cn in set(cns) if cns.count(cn) > 1 and len(set(c['sha256'] for c in certs if c['subject_cn'] == cn)) > 1]

    # Non-CA warning (Leaf certs in mTLS CA bundle is a severe bug)
    missing_sign = [c for c in certs if c['is_ca'] and not c['has_cert_sign'] and c['key_usage']]

    # Health Score (0-100)
    penalties = (expired * 25) + (leaves * 30) + (duplicate_count * 15) + (weak * 20) + (len(missing_sign) * 10)
    health_score = max(0, 100 - penalties)
    
    inner_w = total_width - 4
    
    print()
    print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}🛡️  mTLS CA BUNDLE HEALTH AUDITOR & SECURITY REPORT{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Target Bundle:{C.RESET} {C.YELLOW}{bundle_path:<{inner_w - 18}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

    if health_score >= 90:
        score_badge = f"{C.BG_GREEN} HEALTH: {health_score}/100 (EXCELLENT) {C.RESET}"
    elif health_score >= 70:
        score_badge = f"{C.BG_YELLOW} HEALTH: {health_score}/100 (WARNINGS FOUND) {C.RESET}"
    else:
        score_badge = f"{C.BG_RED} HEALTH: {health_score}/100 (CRITICAL ISSUES) {C.RESET}"

    stat_line = f"  {score_badge}   │   {total} Total CAs ({roots} Roots, {intermediates} SubCAs)   │   {expired} Expired"
    print(f"{C.CYAN}│{C.RESET} {pad_to(stat_line, inner_w)} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")

    # Issues Card
    issues = []
    if expired > 0:
        issues.append((C.RED, f"🚨 {expired} EXPIRED CA(s) present in bundle. Clients using these CAs will fail mTLS!"))
    if leaves > 0:
        issues.append((C.RED, f"🚨 {leaves} NON-CA LEAF CERTIFICATE(S) found in bundle! Leaf certs must NOT be in an mTLS CA bundle."))
    if duplicate_count > 0:
        issues.append((C.YELLOW, f"⚠ {duplicate_count} Duplicate CA(s) detected (identical SHA-256 fingerprints). Use 'merge' to deduplicate."))
    if cn_collisions:
        issues.append((C.YELLOW, f"⚠ Subject CN collision: Multiple different certs share CN: {', '.join(cn_collisions[:3])}"))
    if weak > 0:
        issues.append((C.RED, f"🚨 {weak} CA(s) signed with deprecated weak hash algorithms (SHA-1 / MD5)!"))
    if missing_sign:
        issues.append((C.YELLOW, f"⚠ {len(missing_sign)} CA(s) have keyUsage but are missing 'Certificate Sign' permission."))

    if issues:
        print(f"\n{C.BOLD}{C.WHITE}🚨 Identified Health & Security Issues:{C.RESET}")
        for col, msg in issues:
            print(f"  {col}• {msg}{C.RESET}")

    # Table of Certs
    print()
    sec_title = f"CERTIFICATE AUDIT TABLE ({total})"
    c_idx_w = 4
    c_cn_w = 34
    c_issuer_w = 24
    c_type_w = 12
    c_exp_w = 20
    
    t_top = f"╭─ {C.BOLD}{C.WHITE}{sec_title}{C.RESET} " + "─" * max(0, total_width - len(sec_title) - 5) + "╮"
    t_head = f"│ {pad_to(f'{C.BOLD}#{C.RESET}', c_idx_w)} │ {pad_to(f'{C.BOLD}{C.CYAN}COMMON NAME / SUBJECT{C.RESET}', c_cn_w)} │ {pad_to(f'{C.BOLD}{C.WHITE}ISSUER CN{C.RESET}', c_issuer_w)} │ {pad_to(f'{C.BOLD}ROLE{C.RESET}', c_type_w)} │ {pad_to(f'{C.BOLD}EXPIRY / STATUS{C.RESET}', c_exp_w)} │"
    t_sep = f"├" + "─" * (c_idx_w + 2) + "┼" + "─" * (c_cn_w + 2) + "┼" + "─" * (c_issuer_w + 2) + "┼" + "─" * (c_type_w + 2) + "┼" + "─" * (c_exp_w + 2) + "┤"
    t_bot = f"╰" + "─" * (c_idx_w + 2) + "┴" + "─" * (c_cn_w + 2) + "┴" + "─" * (c_issuer_w + 2) + "┴" + "─" * (c_type_w + 2) + "┴" + "─" * (c_exp_w + 2) + "╯"

    print(f"{C.CYAN}{t_top}{C.RESET}")
    print(f"{C.CYAN}{t_head}{C.RESET}")
    print(f"{C.CYAN}{t_sep}{C.RESET}")

    for idx, c in enumerate(certs, 1):
        cn_disp = c['subject_cn'][:c_cn_w] if len(c['subject_cn']) <= c_cn_w else (c['subject_cn'][:c_cn_w-3] + "...")
        iss_disp = c['issuer_cn'][:c_issuer_w] if len(c['issuer_cn']) <= c_issuer_w else (c['issuer_cn'][:c_issuer_w-3] + "...")
        
        if c['is_root']:
            type_badge = f"{C.BG_BLUE} ROOT CA {C.RESET}"
        elif c['is_ca']:
            type_badge = f"{C.CYAN}SUB-CA (INT){C.RESET}"
        else:
            type_badge = f"{C.BG_RED} LEAF (BUG) {C.RESET}"

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
# 2. COMMAND: APPEND (Safely add CA to bundle with verification)
# ------------------------------------------------------------------------------
def cmd_append():
    out_file = None
    target_bundle = None
    new_ca_path = None
    force = False
    
    i = 0
    while i < len(args):
        if args[i] in ['-o', '--out', '--output']:
            if i + 1 < len(args):
                out_file = args[i+1]
                i += 2
                continue
        elif args[i] in ['-f', '--force']:
            force = True
            i += 1
        elif not target_bundle:
            target_bundle = args[i]
            i += 1
        elif not new_ca_path:
            new_ca_path = args[i]
            i += 1
        else:
            i += 1
            
    if not target_bundle or not new_ca_path:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker append <bundle.pem> <new_ca.pem> [-o output.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    out_file = out_file if out_file else target_bundle
    existing_certs = load_bundle_file(target_bundle)
    new_certs = load_bundle_file(new_ca_path)
    
    existing_fps = set(c['sha256'] for c in existing_certs)
    
    print(f"\n{C.CYAN}[*] Validating candidate CA(s) from '{new_ca_path}' to append to '{target_bundle}'...{C.RESET}\n")
    
    to_add = []
    for c in new_certs:
        if c['sha256'] in existing_fps:
            print(f"  {C.YELLOW}⚠ Skipped duplicate:{C.RESET} '{c['subject_cn']}' is ALREADY present in bundle.")
            continue
            
        if not force:
            if c['is_leaf']:
                print(f"  {C.RED}✖ Rejected:{C.RESET} '{c['subject_cn']}' is a LEAF certificate (not a CA!). Use --force to bypass.")
                continue
            if c['is_expired']:
                print(f"  {C.RED}✖ Rejected:{C.RESET} '{c['subject_cn']}' is EXPIRED ({c['not_after']}). Use --force to bypass.")
                continue
                
        to_add.append(c)
        print(f"  {C.GREEN}✔ Validated CA:{C.RESET} {C.BOLD}{c['subject_cn']}{C.RESET} (Issuer: {c['issuer_cn']}, {c['days_remaining']}d remaining)")

    if not to_add:
        print(f"\n{C.YELLOW}ℹ No new certificates were added to the bundle.{C.RESET}\n")
        return

    # Write updated bundle
    with open(out_file, 'w') as f:
        f.write(f"# mTLS CA Bundle updated by ca-bundle-worker on {datetime.now(timezone.utc).isoformat()}\n\n")
        for c in existing_certs:
            f.write(f"# Subject: {c['subject_dn']}\n")
            f.write(f"# SHA256:  {c['sha256']}\n")
            f.write(c['pem'] + "\n\n")
            
        for c in to_add:
            f.write(f"# [NEWLY APPENDED] Subject: {c['subject_dn']}\n")
            f.write(f"# SHA256:  {c['sha256']}\n")
            f.write(c['pem'] + "\n\n")
            
    print(f"\n{C.GREEN}{C.BOLD}✔ Successfully appended {len(to_add)} CA(s). Bundle now contains {len(existing_certs) + len(to_add)} certificates ({out_file}).{C.RESET}\n")

# ------------------------------------------------------------------------------
# 3. COMMAND: REMOVE (Specifically prune a CA by CN, Fingerprint, or Expired)
# ------------------------------------------------------------------------------
def cmd_remove():
    target_bundle = None
    out_file = None
    target_cn = None
    target_fp = None
    remove_expired = False
    
    i = 0
    while i < len(args):
        if args[i] in ['-o', '--out', '--output']:
            if i + 1 < len(args):
                out_file = args[i+1]
                i += 2
                continue
        elif args[i] in ['--cn', '-cn']:
            if i + 1 < len(args):
                target_cn = args[i+1]
                i += 2
                continue
        elif args[i] in ['--fingerprint', '--fp', '-fp']:
            if i + 1 < len(args):
                target_fp = args[i+1].replace(":", "").replace(" ", "").lower()
                i += 2
                continue
        elif args[i] in ['--expired']:
            remove_expired = True
            i += 1
        elif not target_bundle:
            target_bundle = args[i]
            i += 1
        else:
            i += 1
            
    if not target_bundle or (not target_cn and not target_fp and not remove_expired):
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker remove <bundle.pem> [--cn <name> | --fingerprint <sha256> | --expired] [-o output.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    out_file = out_file if out_file else target_bundle
    certs = load_bundle_file(target_bundle)
    
    kept = []
    removed = []
    
    for c in certs:
        c_fp_clean = c['sha256'].replace(":", "").replace(" ", "").lower()
        should_remove = False
        
        if remove_expired and c['is_expired']:
            should_remove = True
        elif target_fp and c_fp_clean.startswith(target_fp):
            should_remove = True
        elif target_cn and target_cn.lower() in c['subject_cn'].lower():
            should_remove = True
            
        if should_remove:
            removed.append(c)
        else:
            kept.append(c)
            
    if not removed:
        print(f"\n{C.YELLOW}ℹ No matching certificates found to remove from '{target_bundle}'.{C.RESET}\n")
        return
        
    print(f"\n{C.CYAN}[*] Removing {len(removed)} certificate(s) from '{target_bundle}'...{C.RESET}")
    for c in removed:
        print(f"  {C.RED}-{C.RESET} Removed: {C.BOLD}{c['subject_cn']}{C.RESET} (Issuer: {c['issuer_cn']}, SHA256: {c['sha256'][:20]}...)")
        
    with open(out_file, 'w') as f:
        f.write(f"# mTLS CA Bundle pruned by ca-bundle-worker on {datetime.now(timezone.utc).isoformat()}\n\n")
        for c in kept:
            f.write(f"# Subject: {c['subject_dn']}\n")
            f.write(f"# SHA256:  {c['sha256']}\n")
            f.write(c['pem'] + "\n\n")
            
    print(f"\n{C.GREEN}{C.BOLD}✔ Successfully removed {len(removed)} CA(s). Bundle now contains {len(kept)} certificates ({out_file}).{C.RESET}\n")

# ------------------------------------------------------------------------------
# 4. COMMAND: PROBE (Test online FQDN for acceptable client mTLS CAs)
# ------------------------------------------------------------------------------
def cmd_probe():
    target = None
    bundle_path = None
    
    i = 0
    while i < len(args):
        if args[i] in ['-b', '--bundle']:
            if i + 1 < len(args):
                bundle_path = args[i+1]
                i += 2
                continue
        elif not target:
            target = args[i]
            i += 1
        else:
            i += 1
            
    if not target:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker probe <fqdn:port> [--bundle local_bundle.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = "443"
    if ":" in host:
        host, port = host.split(":", 1)
        
    inner_w = total_width - 4
    
    print()
    print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}🔍 ONLINE mTLS ACCEPTABLE CA PROBE{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Target Endpoint:{C.RESET} {C.YELLOW}{host}:{port:<{inner_w - 20}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}\n")

    print(f"{C.DIM}[*] Initiating TLS handshake with SNI '{host}'...{C.RESET}")
    
    # Run OpenSSL handshake extraction
    raw_out = run_cmd(f"echo | openssl s_client -servername '{host}' -connect '{host}:{port}' -prexit 2>&1")
    
    # Check if Acceptable client CA names is present
    ca_names = []
    if "Acceptable client certificate CA names" in raw_out:
        section = raw_out.split("Acceptable client certificate CA names")[-1]
        for line in section.splitlines():
            line_str = line.strip()
            if line_str.startswith("/") or line_str.startswith("CN=") or line_str.startswith("subject="):
                ca_names.append(line_str)
            elif "---" in line_str or "SSL handshake has read" in line_str or "New, TLSv" in line_str:
                break
                
    # Also extract server certificate chain
    chain_raw = run_cmd(f"echo | openssl s_client -servername '{host}' -connect '{host}:{port}' -showcerts 2>/dev/null")
    server_certs = [parse_single_cert(c) for c in extract_certs_from_bundle(chain_raw)]

    if ca_names:
        print(f"\n{C.GREEN}{C.BOLD}✔ Server actively requests mTLS (Client Certificate Required/Requested).{C.RESET}")
        print(f"{C.BOLD}{C.WHITE}Acceptable Client CAs advertised by {host}:{port} ({len(ca_names)}):{C.RESET}")
        for idx, name in enumerate(ca_names, 1):
            print(f"  {C.CYAN}[{idx}]{C.RESET} {C.BOLD}{name}{C.RESET}")
    else:
        print(f"\n{C.YELLOW}ℹ Server did NOT advertise 'Acceptable client certificate CA names'.{C.RESET}")
        print(f"  {C.DIM}(mTLS may be disabled, optional without client CA advertising, or handled at L7 proxy).{C.RESET}")

    if server_certs:
        print(f"\n{C.BOLD}{C.WHITE}Server's Served Certificate Chain ({len(server_certs)}):{C.RESET}")
        for idx, c in enumerate(server_certs, 1):
            c_type = "Leaf" if idx == 1 else "Intermediate CA"
            print(f"  [{idx}] {C.BOLD}{c['subject_cn']}{C.RESET} ({c_type}) ➔ Issuer: {c['issuer_cn']} [Expires: {c['not_after']}]")

    # If local bundle passed, cross reference
    if bundle_path:
        print(f"\n{C.BOLD}{C.WHITE}Cross-referencing with Local Bundle ('{bundle_path}')...{C.RESET}")
        local_certs = load_bundle_file(bundle_path)
        local_cns = set(c['subject_cn'] for c in local_certs)
        
        matched_cns = []
        for adv_name in ca_names:
            for l_cn in local_cns:
                if l_cn in adv_name:
                    matched_cns.append(l_cn)
                    
        if matched_cns:
            print(f"  {C.GREEN}✔ {len(matched_cns)} matching CA(s) found in local bundle!{C.RESET} (Client certs signed by these will be accepted).")
        else:
            print(f"  {C.RED}✖ None of the server's advertised client CAs exist in your local bundle!{C.RESET}")
    print()

# ------------------------------------------------------------------------------
# 5. COMMAND: MONITOR (Check every 2s over N period for cloud drops & CA flapping)
# ------------------------------------------------------------------------------
def cmd_monitor():
    target = None
    interval = 2.0
    duration = 30.0  # seconds
    bundle_path = None
    
    i = 0
    while i < len(args):
        if args[i] in ['-i', '--interval']:
            if i + 1 < len(args):
                interval = float(args[i+1])
                i += 2
                continue
        elif args[i] in ['-d', '--duration']:
            if i + 1 < len(args):
                duration = float(args[i+1])
                i += 2
                continue
        elif args[i] in ['-b', '--bundle']:
            if i + 1 < len(args):
                bundle_path = args[i+1]
                i += 2
                continue
        elif not target:
            target = args[i]
            i += 1
        else:
            i += 1
            
    if not target:
        print(f"{C.RED}[ERROR] Usage: ca-bundle-worker monitor <fqdn:port> [--interval 2] [--duration 60] [--bundle local.pem]{C.RESET}", file=sys.stderr)
        sys.exit(1)
        
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = "443"
    if ":" in host:
        host, port = host.split(":", 1)
        
    total_polls = int(duration // interval)
    inner_w = total_width - 4
    
    print()
    print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}📡  mTLS INTERMITTENT DROP & CA FLAPPING MONITOR{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Target Endpoint:{C.RESET} {C.YELLOW}{host}:{port:<{inner_w - 20}}{C.RESET} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Monitoring Config:{C.RESET} Poll every {interval}s for {duration}s total ({total_polls} iterations) {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}\n")

    print(f"{C.BOLD}{C.CYAN}{'#':<4} {'TIME (UTC)':<12} {'LATENCY':<10} {'STATUS':<14} {'ADVERTISED mTLS CAs':<36} {'SERVER LEAF CN'}{C.RESET}")
    print(f"{C.DIM}{'─'*total_width}{C.RESET}")

    history = []
    unique_ca_fingerprints = set()
    unique_server_leaves = set()
    failed_handshakes = 0

    start_time = time.time()
    poll_idx = 1
    
    while (time.time() - start_time) < duration:
        t_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        t0 = time.time()
        
        # Connect & extract
        cmd = f"echo | openssl s_client -servername '{host}' -connect '{host}:{port}' -showcerts -prexit 2>&1"
        out = run_cmd(cmd, timeout=int(interval + 3))
        latency_ms = int((time.time() - t0) * 1000)
        
        # Extract Acceptable CAs
        adv_cas = []
        if "Acceptable client certificate CA names" in out:
            sec = out.split("Acceptable client certificate CA names")[-1]
            for line in sec.splitlines():
                l = line.strip()
                if l.startswith("/") or l.startswith("CN="):
                    adv_cas.append(l)
                elif "---" in l or "SSL handshake has read" in l or "New, TLSv" in l:
                    break
                    
        # Extract Server Leaf CN
        leaf_cn = "N/A"
        if "subject=" in out:
            leaf_m = re.search(r'subject=.*CN\s*=\s*([^,\n/]+)', out)
            if leaf_m:
                leaf_cn = leaf_m.group(1).strip()

        # Status determination
        if "Connection refused" in out or "connect:errno" in out or not out:
            status_badge = f"{C.BG_RED} FAILED {C.RESET}"
            adv_str = f"{C.RED}Connection Refused / Drop{C.RESET}"
            failed_handshakes += 1
        elif "SSL_ERROR" in out or "handshake failure" in out:
            status_badge = f"{C.BG_RED} TLS ERR {C.RESET}"
            adv_str = f"{C.RED}TLS Handshake Failure{C.RESET}"
            failed_handshakes += 1
        else:
            status_badge = f"{C.GREEN}✔ OK{C.RESET}"
            if adv_cas:
                adv_str = f"{C.CYAN}{len(adv_cas)} CAs: {', '.join(c.split('CN=')[-1].split('/')[0] for c in adv_cas[:2])}{C.RESET}"
                if len(adv_cas) > 2: adv_str += f" (+{len(adv_cas)-2})"
            else:
                adv_str = f"{C.GRAY}No client CAs advertised{C.RESET}"

        ca_hash = "|".join(sorted(adv_cas))
        unique_ca_fingerprints.add(ca_hash)
        unique_server_leaves.add(leaf_cn)

        history.append({
            'idx': poll_idx,
            'time': t_str,
            'latency': latency_ms,
            'ok': (status_badge.startswith(f"{C.GREEN}")),
            'ca_hash': ca_hash,
            'adv_cas': adv_cas,
            'leaf_cn': leaf_cn
        })

        lat_str = f"{latency_ms}ms"
        print(f"{poll_idx:<4} {t_str:<12} {lat_str:<10} {status_badge:<22} {pad_to(adv_str, 36)} {C.WHITE}{leaf_cn}{C.RESET}")
        
        poll_idx += 1
        elapsed = time.time() - t0
        sleep_dur = max(0.1, interval - elapsed)
        time.sleep(sleep_dur)

    # --------------------------------------------------------------------------
    # Flapping / Stability Summary Card
    # --------------------------------------------------------------------------
    print(f"{C.DIM}{'─'*total_width}{C.RESET}\n")
    
    flapping_detected = (len(unique_ca_fingerprints) > 1) or (len(unique_server_leaves) > 1)
    
    print(f"{C.CYAN}╭─ {C.BOLD}{C.WHITE}📊 MONITORING & FLAPPING SUMMARY AUDIT{C.RESET} " + "─" * (total_width - 40) + f"╮{C.RESET}")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Total Polls Executed:{C.RESET} {len(history)} iterations over {int(time.time() - start_time)}s")
    print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Handshake Success:{C.RESET}    {C.GREEN if failed_handshakes == 0 else C.RED}{len(history) - failed_handshakes}/{len(history)} successful ({failed_handshakes} drops/errors){C.RESET}")

    if not flapping_detected and failed_handshakes == 0:
        print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Flapping / Drift:{C.RESET}     {C.BG_GREEN} STABLE (0% DRIFT DETECTED) {C.RESET}")
        print(f"{C.CYAN}│{C.RESET}  • Advertised mTLS CAs and server certificates remained 100% consistent across all polls.")
    else:
        print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Flapping / Drift:{C.RESET}     {C.BG_RED} FLAPPING / BACKEND DRIFT DETECTED! {C.RESET}")
        if len(unique_ca_fingerprints) > 1:
            print(f"{C.CYAN}│{C.RESET}  • {C.RED}mTLS CA Flapping:{C.RESET} {len(unique_ca_fingerprints)} distinct Acceptable CA sets were observed!")
            print(f"{C.CYAN}│{C.RESET}    (Indicates load balancer is routing between drifting backend pods/gateways with different CA bundles).")
        if len(unique_server_leaves) > 1:
            print(f"{C.CYAN}│{C.RESET}  • {C.YELLOW}Server Leaf Flapping:{C.RESET} {len(unique_server_leaves)} different server certificates observed: {', '.join(unique_server_leaves)}")

    # Latencies
    lats = [h['latency'] for h in history if h['ok']]
    if lats:
        avg_lat = sum(lats) // len(lats)
        print(f"{C.CYAN}│{C.RESET}  {C.BOLD}Handshake Latency:{C.RESET}    min: {min(lats)}ms  │  avg: {avg_lat}ms  │  max: {max(lats)}ms")

    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}\n")

# ------------------------------------------------------------------------------
# 6. COMMAND: SPLIT / MERGE ROUTING
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
        clean_name = re.sub(r'[^a-zA-Z0-9._-]', '_', c['subject_cn'])
        c_type = "root" if c['is_root'] else ("intermediate" if c['is_ca'] else "leaf")
        filename = f"{idx:02d}_{c_type}_{clean_name[:40]}.pem"
        with open(os.path.join(out_dir, filename), 'w') as f:
            f.write(f"# Subject: {c['subject_dn']}\n# Issuer:  {c['issuer_dn']}\n# SHA256:  {c['sha256']}\n" + c['pem'] + "\n")
        print(f"  {C.GREEN}✔{C.RESET} [{idx:02d}/{len(certs):02d}] Extracted: {C.BOLD}{filename}{C.RESET}")
    print(f"\n{C.GREEN}{C.BOLD}✔ Extracted {len(certs)} certificates into '{out_dir}'.{C.RESET}\n")

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
            
    seen_fps = set()
    unique_certs = []
    duplicate_count = 0
    for fpath in all_files:
        try:
            for c in load_bundle_file(fpath):
                if c['sha256'] in seen_fps:
                    duplicate_count += 1
                else:
                    seen_fps.add(c['sha256'])
                    unique_certs.append(c)
        except Exception:
            pass

    with open(out_file, 'w') as f:
        f.write(f"# CA Bundle generated by ca-bundle-worker on {datetime.now(timezone.utc).isoformat()}\n\n")
        for c in unique_certs:
            f.write(f"# Subject: {c['subject_dn']}\n# SHA256:  {c['sha256']}\n" + c['pem'] + "\n\n")
    print(f"\n{C.GREEN}{C.BOLD}✔ Merged {len(unique_certs)} unique certificates into '{out_file}' (Filtered out {duplicate_count} duplicates).{C.RESET}\n")

# ------------------------------------------------------------------------------
# Router
# ------------------------------------------------------------------------------
if command in ['audit', 'inspect']:
    cmd_audit()
elif command in ['append', 'add']:
    cmd_append()
elif command in ['remove', 'delete', 'prune']:
    cmd_remove()
elif command in ['probe', 'test-fqdn']:
    cmd_probe()
elif command in ['monitor', 'watch']:
    cmd_monitor()
elif command == 'split':
    cmd_split()
elif command == 'merge':
    cmd_merge()
else:
    print(f"{C.RED}[ERROR] Unknown command: '{command}'{C.RESET}\n", file=sys.stderr)
    show_help()
    sys.exit(1)
EOF
