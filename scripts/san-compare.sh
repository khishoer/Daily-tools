#!/usr/bin/env bash
# ==============================================================================
# Script Name: san-compare.sh
# Description: High-ergonomics X.509 certificate comparison & side-by-side SAN diff.
# Author: Daily Tools (https://github.com/khishoer/Daily-tools)
# Requirements: bash, openssl, python3
# ==============================================================================

# ------------------------------------------------------------------------------
# Help & Usage
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage:
  san-compare.sh [OPTIONS] <CERT1> <CERT2>

Description:
  High-ergonomics, visually intuitive X.509 certificate and SAN comparison tool.
  Renders clean, side-by-side tables for both General Parameters and Subject
  Alternative Names (SANs) with intelligent risk verdicts.

Arguments:
  <CERT1>, <CERT2>     Can be:
                       - Local file path (.pem, .crt, .cer, .der, .p7b)
                       - Remote hostname with port (e.g. "google.com:443" or "https://github.com")

Options:
  -s, --san-only       Only compare Subject Alternative Names (SANs)
  -q, --quiet          Quiet mode (exit 0 if identical, 1 if differences)
  -n, --no-color       Disable color output
  -w, --width <cols>   Set custom table width (default: auto or 108)
  -h, --help           Show this help message

Examples:
  san-compare.sh cert_v1.pem cert_v2.pem
  san-compare.sh google.com:443 github.com:443
  san-compare.sh --san-only prod.crt staging.crt

EOF
}

# ------------------------------------------------------------------------------
# Temporary Workspace Cleanup
# ------------------------------------------------------------------------------
TMP_DIR=$(mktemp -d -t cert_compare_XXXXXX)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# Certificate Fetcher / Normalizer (Converts File or Remote to PEM)
# ------------------------------------------------------------------------------
load_certificate() {
    local target="$1"
    local out_pem="$2"

    # Remote URL or Host:Port
    if [[ "$target" =~ ^https?:// ]] || [[ "$target" =~ :[0-9]+$ ]] || [[ ! -f "$target" && "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} ]]; then
        local host="$target"
        host="${host#https://}"
        host="${host#http://}"
        host="${host%%/*}"
        local port="443"
        if [[ "$host" =~ :([0-9]+)$ ]]; then
            port="${BASH_REMATCH[1]}"
            host="${host%:*}"
        fi

        echo "[*] Fetching leaf certificate from remote host: ${host}:${port}..." >&2
        if ! echo | openssl s_client -servername "$host" -connect "${host}:${port}" -showcerts 2>/dev/null | \
             openssl x509 -outform PEM > "$out_pem" 2>/dev/null; then
            echo "[ERROR] Failed to fetch certificate from ${host}:${port}" >&2
            exit 1
        fi
        return 0
    fi

    # Local file
    if [[ ! -f "$target" ]]; then
        echo "[ERROR] File not found: '$target'" >&2
        exit 1
    fi

    if openssl x509 -in "$target" -inform PEM -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    elif openssl x509 -in "$target" -inform DER -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    elif openssl pkcs7 -in "$target" -print_certs 2>/dev/null | openssl x509 -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    else
        echo "[ERROR] Unsupported or corrupted certificate format: '$target'" >&2
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# CLI Flag Parsing
# ------------------------------------------------------------------------------
SAN_ONLY=false
QUIET=false
NO_COLOR_FLAG=0
CUSTOM_WIDTH=108

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--san-only)
            SAN_ONLY=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -n|--no-color)
            NO_COLOR_FLAG=1
            shift
            ;;
        -w|--width)
            CUSTOM_WIDTH="$2"
            shift 2
            ;;
        -*)
            echo "[ERROR] Unknown option: $1" >&2
            show_help
            exit 1
            ;;
        *)
            if [[ -z "${TARGET1:-}" ]]; then
                TARGET1="$1"
            elif [[ -z "${TARGET2:-}" ]]; then
                TARGET2="$1"
            else
                echo "[ERROR] Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "${TARGET1:-}" || -z "${TARGET2:-}" ]]; then
    echo "[ERROR] You must provide two certificate targets to compare." >&2
    echo "" >&2
    show_help
    exit 1
fi

CERT1_PEM="${TMP_DIR}/cert1.pem"
CERT2_PEM="${TMP_DIR}/cert2.pem"

load_certificate "$TARGET1" "$CERT1_PEM"
load_certificate "$TARGET2" "$CERT2_PEM"

# ------------------------------------------------------------------------------
# Execute Modern Ergonomic Comparison Engine (Python)
# ------------------------------------------------------------------------------
python3 - << 'EOF' "$CERT1_PEM" "$CERT2_PEM" "$TARGET1" "$TARGET2" "$SAN_ONLY" "$QUIET" "$NO_COLOR_FLAG" "$CUSTOM_WIDTH"
import sys
import os
import re
import subprocess
from datetime import datetime, timezone

cert1_pem, cert2_pem, target1, target2, san_only_str, quiet_str, no_color_str, width_str = sys.argv[1:9]
san_only = san_only_str.lower() == 'true'
quiet = quiet_str.lower() == 'true'
no_color = (no_color_str == '1') or ('NO_COLOR' in os.environ)
total_width = int(width_str) if width_str.isdigit() else 108

# Color definitions
class C:
    if not no_color and sys.stdout.isatty():
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        ITALIC = "\033[3m"
        
        # Modern refined 256/16 colors
        RED = "\033[38;5;203m"
        GREEN = "\033[38;5;120m"
        YELLOW = "\033[38;5;221m"
        BLUE = "\033[38;5;75m"
        MAGENTA = "\033[38;5;176m"
        CYAN = "\033[38;5;80m"
        WHITE = "\033[38;5;255m"
        GRAY = "\033[38;5;244m"
        DARK_GRAY = "\033[38;5;238m"
        
        # Badges
        BG_RED = "\033[48;5;196;38;5;255;1m"
        BG_GREEN = "\033[48;5;28;38;5;255;1m"
        BG_YELLOW = "\033[48;5;214;38;5;16;1m"
        BG_BLUE = "\033[48;5;31;38;5;255;1m"
    else:
        RESET = BOLD = DIM = ITALIC = ""
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = GRAY = DARK_GRAY = ""
        BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = ""

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

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.stdout.strip()
    except Exception:
        return ""

def parse_cert(pem_path):
    d = {}
    d['subject_dn'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -subject -nameopt RFC2253").replace("subject=", "").strip()
    d['issuer_dn'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -issuer -nameopt RFC2253").replace("issuer=", "").strip()
    
    subj_cn = run_cmd(f"openssl x509 -in '{pem_path}' -noout -subject")
    d['subject_cn'] = subj_cn.split("CN=")[-1].split(",")[0].strip() if "CN=" in subj_cn else (d['subject_dn'] or "N/A")
    
    issuer_cn = run_cmd(f"openssl x509 -in '{pem_path}' -noout -issuer")
    d['issuer_cn'] = issuer_cn.split("CN=")[-1].split(",")[0].strip() if "CN=" in issuer_cn else (d['issuer_dn'] or "N/A")
    
    d['serial'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -serial").replace("serial=", "").strip()
    
    sig_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -text | grep 'Signature Algorithm:' | head -n 1")
    d['sig_algo'] = sig_raw.split(":")[-1].strip() if ":" in sig_raw else "N/A"
    
    nb_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -startdate").replace("notBefore=", "").strip()
    na_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -enddate").replace("notAfter=", "").strip()
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
    else:
        d['days_remaining'] = 0
        d['is_expired'] = False

    txt = run_cmd(f"openssl x509 -in '{pem_path}' -noout -text")
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
    d['pubkey_algo'] = pk_algo
    d['pubkey_size'] = pk_size
    
    d['pubkey_hash'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -pubkey | openssl sha256 | awk '{{print $NF}}'")
    d['sha256'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -fingerprint -sha256").split("=")[-1].strip()
    d['sha1'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -fingerprint -sha1").split("=")[-1].strip()
    
    d['key_usage'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext keyUsage | grep -v 'Key Usage'").strip()
    d['ext_key_usage'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext extendedKeyUsage | grep -v 'Extended Key Usage'").strip()
    d['basic_constraints'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext basicConstraints | grep -v 'Basic Constraints'").strip()
    d['ocsp'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ocsp_uri")
    
    san_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext subjectAltName | grep -v 'Subject Alternative Name'")
    sans = []
    if san_raw:
        for item in san_raw.split(","):
            val = item.strip()
            if val:
                sans.append(val)
    d['sans'] = sorted(list(set(sans)))
    return d

c1 = parse_cert(cert1_pem)
c2 = parse_cert(cert2_pem)

# SAN Sets
s1 = set(c1['sans'])
s2 = set(c2['sans'])
common_sans = sorted(list(s1 & s2))
removed_sans = sorted(list(s1 - s2))
added_sans = sorted(list(s2 - s1))
all_unique_sans = sorted(list(s1 | s2))

c1_san_count = len(c1['sans'])
c2_san_count = len(c2['sans'])
common_count = len(common_sans)
removed_count = len(removed_sans)
added_count = len(added_sans)
san_diff_count = removed_count + added_count

params_to_compare = [
    ("Subject CN", c1['subject_cn'], c2['subject_cn']),
    ("Subject DN", c1['subject_dn'], c2['subject_dn']),
    ("Issuer CN", c1['issuer_cn'], c2['issuer_cn']),
    ("Issuer DN", c1['issuer_dn'], c2['issuer_dn']),
    ("Serial Number", c1['serial'], c2['serial']),
    ("Signature Algorithm", c1['sig_algo'], c2['sig_algo']),
    ("Public Key", c1['pubkey_info'], c2['pubkey_info']),
    ("Valid From", c1['not_before'], c2['not_before']),
    ("Valid Until (Expiry)", c1['not_after'], c2['not_after']),
    ("Validity Status", 
     f"{'EXPIRED' if c1['is_expired'] else 'VALID'} ({c1['days_remaining']}d left)", 
     f"{'EXPIRED' if c2['is_expired'] else 'VALID'} ({c2['days_remaining']}d left)"),
    ("Key Usage", c1['key_usage'] or "<None>", c2['key_usage'] or "<None>"),
    ("Ext Key Usage (EKU)", c1['ext_key_usage'] or "<None>", c2['ext_key_usage'] or "<None>"),
    ("Basic Constraints", c1['basic_constraints'] or "<None>", c2['basic_constraints'] or "<None>"),
    ("OCSP Responder", c1['ocsp'] or "<None>", c2['ocsp'] or "<None>"),
    ("SHA-256 Fingerprint", c1['sha256'], c2['sha256']),
]

param_diffs = sum(1 for _, v1, v2 in params_to_compare if v1 != v2)
param_total = len(params_to_compare)

if quiet:
    sys.exit(0 if (param_diffs == 0 and san_diff_count == 0) else 1)

# ------------------------------------------------------------------------------
# 1. TOP HEADER & METRIC DASHBOARD
# ------------------------------------------------------------------------------
print()
banner_title = "🔐  X.509 CERTIFICATE & SAN COMPARISON REPORT"
inner_w = total_width - 4

print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}{banner_title}{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

line_t1 = f"  {C.BOLD}Cert [1] (Left):{C.RESET}  {C.YELLOW}{target1}{C.RESET}"
line_t2 = f"  {C.BOLD}Cert [2] (Right):{C.RESET} {C.YELLOW}{target2}{C.RESET}"
print(f"{C.CYAN}│{C.RESET} {pad_to(line_t1, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(line_t2, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

diff_badge = f"{C.RED}{C.BOLD}{param_diffs} Parameter Diff(s){C.RESET}" if param_diffs > 0 else f"{C.GREEN}{C.BOLD}All Params Match{C.RESET}"
san_match_badge = f"{C.GREEN}{common_count} Common SANs{C.RESET}"
san_add_badge = f"{C.CYAN}+{added_count} Added{C.RESET}" if added_count > 0 else f"{C.GRAY}0 Added{C.RESET}"
san_rem_badge = f"{C.RED}-{removed_count} Removed{C.RESET}" if removed_count > 0 else f"{C.GRAY}0 Removed{C.RESET}"

dash_line = f"  📊 {C.BOLD}STATUS DASHBOARD:{C.RESET}  {diff_badge}   │   {san_match_badge}   │   {san_add_badge}   │   {san_rem_badge}"
print(f"{C.CYAN}│{C.RESET} {pad_to(dash_line, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")

# ------------------------------------------------------------------------------
# 2. GENERAL PARAMETERS SIDE-BY-SIDE TABLE
# ------------------------------------------------------------------------------
if not san_only:
    print()
    sec1_title = "1. GENERAL PARAMETERS COMPARISON"
    p_name_w = 22
    p_val_w = (total_width - p_name_w - 12) // 2
    
    t_top = f"╭─ {C.BOLD}{C.WHITE}{sec1_title}{C.RESET} " + "─" * max(0, total_width - len(sec1_title) - 5) + "╮"
    t_head = f"│ {pad_to(f'{C.BOLD}{C.CYAN}PARAMETER{C.RESET}', p_name_w)} │ {pad_to(f'{C.BOLD}{C.WHITE}CERT [1] (Left){C.RESET}', p_val_w)} │ {'DIFF':^4} │ {pad_to(f'{C.BOLD}{C.WHITE}CERT [2] (Right){C.RESET}', p_val_w)} │"
    t_sep = f"├" + "─" * (p_name_w + 2) + "┼" + "─" * (p_val_w + 2) + "┼" + "─" * 6 + "┼" + "─" * (p_val_w + 2) + "┤"
    t_bot = f"╰" + "─" * (p_name_w + 2) + "┴" + "─" * (p_val_w + 2) + "┴" + "─" * 6 + "┴" + "─" * (p_val_w + 2) + "╯"

    print(f"{C.CYAN}{t_top}{C.RESET}")
    print(f"{C.CYAN}{t_head}{C.RESET}")
    print(f"{C.CYAN}{t_sep}{C.RESET}")

    for name, v1, v2 in params_to_compare:
        v1_clean = v1 if v1 else "<None>"
        v2_clean = v2 if v2 else "<None>"
        
        v1_disp = v1_clean if len(v1_clean) <= p_val_w else (v1_clean[:p_val_w-3] + "...")
        v2_disp = v2_clean if len(v2_clean) <= p_val_w else (v2_clean[:p_val_w-3] + "...")
        
        if v1_clean == v2_clean:
            tag = f"{C.GREEN} =  {C.RESET}"
            v1_col = pad_to(f"{C.GRAY}{v1_disp}{C.RESET}", p_val_w)
            v2_col = pad_to(f"{C.GRAY}{v2_disp}{C.RESET}", p_val_w)
            p_col = pad_to(f"{C.WHITE}{name}{C.RESET}", p_name_w)
        else:
            tag = f"{C.RED}{C.BOLD} ≠  {C.RESET}"
            v1_col = pad_to(f"{C.RED}{v1_disp}{C.RESET}", p_val_w)
            v2_col = pad_to(f"{C.GREEN}{v2_disp}{C.RESET}", p_val_w)
            p_col = pad_to(f"{C.YELLOW}{C.BOLD}{name}{C.RESET}", p_name_w)
            
        print(f"{C.CYAN}│{C.RESET} {p_col} {C.CYAN}│{C.RESET} {v1_col} {C.CYAN}│{C.RESET} {tag} {C.CYAN}│{C.RESET} {v2_col} {C.CYAN}│{C.RESET}")

    print(f"{C.CYAN}{t_bot}{C.RESET}")

# ------------------------------------------------------------------------------
# 3. SIDE-BY-SIDE SUBJECT ALTERNATIVE NAMES (SAN) TABLE
# ------------------------------------------------------------------------------
print()
sec2_title = "2. SUBJECT ALTERNATIVE NAMES (SAN) SIDE-BY-SIDE"
san_col_w = (total_width - 10) // 2

s_top = f"╭─ {C.BOLD}{C.WHITE}{sec2_title}{C.RESET} " + "─" * max(0, total_width - len(sec2_title) - 5) + "╮"
s_h1 = f"Cert [1] SANs ({c1_san_count})"
s_h2 = f"Cert [2] SANs ({c2_san_count})"
s_head = f"│ {pad_to(f'{C.BOLD}{C.WHITE}{s_h1}{C.RESET}', san_col_w)} │ {'STAT':^4} │ {pad_to(f'{C.BOLD}{C.WHITE}{s_h2}{C.RESET}', san_col_w)} │"
s_sep = f"├" + "─" * (san_col_w + 2) + "┼" + "─" * 6 + "┼" + "─" * (san_col_w + 2) + "┤"
s_bot = f"╰" + "─" * (san_col_w + 2) + "┴" + "─" * 6 + "┴" + "─" * (san_col_w + 2) + "╯"

print(f"{C.CYAN}{s_top}{C.RESET}")
print(f"{C.CYAN}{s_head}{C.RESET}")
print(f"{C.CYAN}{s_sep}{C.RESET}")

if not all_unique_sans:
    no_san_msg = pad_to(f"{C.GRAY}<No Subject Alternative Names Found>{C.RESET}", san_col_w)
    print(f"{C.CYAN}│{C.RESET} {no_san_msg} {C.CYAN}│{C.RESET} {C.GRAY} == {C.RESET} {C.CYAN}│{C.RESET} {no_san_msg} {C.CYAN}│{C.RESET}")
else:
    for san in all_unique_sans:
        in_c1 = san in s1
        in_c2 = san in s2
        
        san_disp = san if len(san) <= san_col_w else (san[:san_col_w-3] + "...")
        placeholder = "· " * ((san_col_w // 2) - 1)
        
        if in_c1 and in_c2:
            tag = f"{C.GREEN}{C.BOLD} == {C.RESET}"
            left_side = pad_to(f"{C.GREEN}{san_disp}{C.RESET}", san_col_w)
            right_side = pad_to(f"{C.GREEN}{san_disp}{C.RESET}", san_col_w)
        elif in_c1 and not in_c2:
            tag = f"{C.RED}{C.BOLD} -  {C.RESET}"
            left_side = pad_to(f"{C.RED}{C.BOLD}{san_disp}{C.RESET}", san_col_w)
            right_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
        elif not in_c1 and in_c2:
            tag = f"{C.CYAN}{C.BOLD} +  {C.RESET}"
            left_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
            right_side = pad_to(f"{C.CYAN}{C.BOLD}{san_disp}{C.RESET}", san_col_w)

        print(f"{C.CYAN}│{C.RESET} {left_side} {C.CYAN}│{C.RESET} {tag} {C.CYAN}│{C.RESET} {right_side} {C.CYAN}│{C.RESET}")

print(f"{C.CYAN}{s_bot}{C.RESET}")

# ------------------------------------------------------------------------------
# 4. EXECUTIVE VERDICT & RISK ASSESSMENT CARD
# ------------------------------------------------------------------------------
print()
sec3_title = "3. EXECUTIVE VERDICT & RISK ASSESSMENT"
v_top = f"╭─ {C.BOLD}{C.WHITE}{sec3_title}{C.RESET} " + "─" * max(0, total_width - len(sec3_title) - 5) + "╮"
v_bot = f"╰" + "─" * (total_width - 2) + "╯"

if c1['sha256'] == c2['sha256']:
    scenario_title = "🎯 EXACT IDENTICAL CERTIFICATE"
    risk_pill = f"{C.BG_GREEN} RISK: NONE (IDENTICAL ISSUE) {C.RESET}"
    action_item = f"{C.GREEN}✔ No action required.{C.RESET} Both targets serve the exact same cryptographic certificate."
elif common_count == 0 and c1_san_count > 0 and c2_san_count > 0:
    scenario_title = "❌ COMPLETELY DISJOINT / UNRELATED CERTIFICATES"
    risk_pill = f"{C.BG_RED} RISK: HIGH (INCOMPATIBLE TARGETS) {C.RESET}"
    action_item = f"{C.RED}✖ Incompatible targets.{C.RESET} Do not swap these certificates; they serve completely separate services."
elif san_diff_count == 0:
    if c2['days_remaining'] < c1['days_remaining']:
        scenario_title = "⚠️ EXPIRATION REGRESSION DETECTED"
        risk_pill = f"{C.BG_RED} RISK: HIGH (LIFETIME REGRESSION) {C.RESET}"
        action_item = f"{C.RED}✖ Caution!{C.RESET} Cert [2] expires earlier than Cert [1]. Verify you are not deploying an older archive cert."
    elif c1['is_expired'] and not c2['is_expired']:
        scenario_title = "🔄 EXPIRED CERTIFICATE REPLACEMENT"
        risk_pill = f"{C.BG_GREEN} RISK: LOW (CRITICAL RESTORATION) {C.RESET}"
        action_item = f"{C.GREEN}✔ Deploy immediately.{C.RESET} Restore valid HTTPS trust on your ingress / load balancer."
    else:
        scenario_title = "🔄 SEAMLESS CERTIFICATE RENEWAL / RE-ISSUANCE"
        risk_pill = f"{C.BG_GREEN} RISK: LOW (SAFE TO DEPLOY) {C.RESET}"
        action_item = f"{C.GREEN}✔ Safe for deployment.{C.RESET} Seamless drop-in replacement on Load Balancers, Ingress, and CDNs."
elif removed_count == 0 and added_count > 0:
    scenario_title = f"📈 BACKWARDS-COMPATIBLE SAN EXPANSION (+{added_count} New Domains)"
    risk_pill = f"{C.BG_BLUE} RISK: LOW-MEDIUM (SAFE FOR EXISTING TRAFFIC) {C.RESET}"
    action_item = f"{C.GREEN}✔ Safe for current traffic.{C.RESET} Ensure DNS records for new SANs point to this endpoint before routing new traffic."
elif removed_count > 0 and added_count == 0:
    scenario_title = f"🚨 SAN CONTRACTION / REMOVAL ({removed_count} Domains Lost!)"
    risk_pill = f"{C.BG_RED} RISK: CRITICAL (BREAKING OUTAGE RISK) {C.RESET}"
    action_item = f"{C.RED}✖ DO NOT DEPLOY!{C.RESET} Active traffic hitting removed hostnames will experience immediate TLS handshake failures."
else:
    scenario_title = f"🔀 SAN OVERHAUL / PARTIAL DRIFT (+{added_count} Added, -{removed_count} Removed)"
    risk_pill = f"{C.BG_YELLOW} RISK: HIGH (PARTIAL OUTAGE RISK) {C.RESET}"
    action_item = f"{C.YELLOW}⚠ Audit required.{C.RESET} Verify decommissioned status of removed domains before rotating."

print(f"{C.CYAN}{v_top}{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}VERDICT:{C.RESET}     {C.BOLD}{C.WHITE}{scenario_title}{C.RESET}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}RISK LEVEL:{C.RESET}  {risk_pill}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET}" + " " * (inner_w + 2) + f"{C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}{C.WHITE}🔍 Key Lifecycle Insights:{C.RESET}', inner_w)} {C.CYAN}│{C.RESET}")

# Insights
if san_diff_count == 0:
    san_msg = f"   • {C.GREEN}SAN Continuity:{C.RESET}  100% Match ({c1_san_count}/{c1_san_count} domains preserved)."
elif removed_count == 0:
    san_msg = f"   • {C.GREEN}SAN Continuity:{C.RESET}  Backwards-Compatible ({common_count} preserved, +{added_count} new)."
elif common_count == 0:
    san_msg = f"   • {C.RED}SAN Continuity:{C.RESET}  0% Overlap (No shared domains)."
else:
    san_msg = f"   • {C.YELLOW}SAN Continuity:{C.RESET}  Partial ({common_count} kept, +{added_count} added, {C.RED}-{removed_count} lost{C.RESET})."
print(f"{C.CYAN}│{C.RESET} {pad_to(san_msg, inner_w)} {C.CYAN}│{C.RESET}")

if c1['dt_not_after'] and c2['dt_not_after']:
    delta_days = (c2['dt_not_after'] - c1['dt_not_after']).days
    if delta_days > 0:
        val_msg = f"   • {C.GREEN}Validity Delta:{C.RESET}  Cert [2] extends lifespan by {C.BOLD}+{delta_days} days{C.RESET} ({c2['days_remaining']}d remaining)."
    elif delta_days < 0:
        val_msg = f"   • {C.RED}Validity Delta:{C.RESET}  Cert [2] expires {C.BOLD}{abs(delta_days)} days SOONER{C.RESET} than Cert [1]."
    else:
        val_msg = f"   • {C.GRAY}Validity Delta:{C.RESET}  Both certificates share the exact same expiry date."
    print(f"{C.CYAN}│{C.RESET} {pad_to(val_msg, inner_w)} {C.CYAN}│{C.RESET}")

if c1['pubkey_hash'] == c2['pubkey_hash'] and c1['pubkey_hash']:
    key_msg = f"   • {C.GRAY}Private Key:{C.RESET}     Re-used identical underlying key pair."
else:
    key_msg = f"   • {C.CYAN}Private Key:{C.RESET}     Rotated to a fresh cryptographic key pair."
print(f"{C.CYAN}│{C.RESET} {pad_to(key_msg, inner_w)} {C.CYAN}│{C.RESET}")

if c1['pubkey_info'] != c2['pubkey_info']:
    crypto_msg = f"   • {C.MAGENTA}Crypto Shift:{C.RESET}    {c1['pubkey_info']} ➔ {c2['pubkey_info']}"
    print(f"{C.CYAN}│{C.RESET} {pad_to(crypto_msg, inner_w)} {C.CYAN}│{C.RESET}")

if c1['issuer_dn'] != c2['issuer_dn']:
    ca_msg = f"   • {C.CYAN}CA Authority:{C.RESET}    Migrated from '{c1['issuer_cn']}' ➔ '{c2['issuer_cn']}'"
    print(f"{C.CYAN}│{C.RESET} {pad_to(ca_msg, inner_w)} {C.CYAN}│{C.RESET}")

print(f"{C.CYAN}│{C.RESET}" + " " * (inner_w + 2) + f"{C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}{C.WHITE}📋 Actionable Recommendation:{C.RESET}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f'   {action_item}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}{v_bot}{C.RESET}\n")

if scenario_title.startswith("❌") or "CRITICAL" in risk_pill or "LIFETIME REGRESSION" in scenario_title:
    sys.exit(1)
else:
    sys.exit(0)
EOF
