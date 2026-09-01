#!/usr/bin/env bash
# ==============================================================================
# Script Name: cert-compare.sh
# Description: High-ergonomics X.509 certificate comparison & SAN diff tool.
#              Automatically identifies Current/Hosted Baseline vs Renewal Candidate
#              regardless of argument order, cleans SAN prefixes, supports --only-diff,
#              and audits deployment risk.
# Author: Daily Tools (https://github.com/khishoer/Daily-tools)
# Requirements: bash, openssl, python3
# ==============================================================================

# ------------------------------------------------------------------------------
# Help & Usage
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage:
  cert-compare.sh [OPTIONS] <CERT1> <CERT2>

Description:
  High-ergonomics X.509 leaf certificate comparison and renewal auditor.
  Compares all parameters (Subject, Issuer, Validity, Keys, EKU, Extensions)
  with a side-by-side SAN delta table and intelligent risk verdicts.

Arguments:
  <CERT1>, <CERT2>     Can be:
                       - Local file path (.pem, .crt, .cer, .der, .p7b)
                       - Remote hostname with port (e.g. "google.com:443" or "https://github.com")

Options:
  -d, --only-diff      Only show differing parameters and differing SAN entries (suppress identical rows)
  -s, --san-only       Only compare Subject Alternative Names (SANs)
  -q, --quiet          Quiet mode (exit 0 if safe/identical, 1 if breaking differences)
  -n, --no-color       Disable color output
  -w, --width <cols>   Set custom table width (default: auto or 108)
  -h, --help           Show this help message

Examples:
  # Focus strictly on differences
  cert-compare.sh --only-diff current.crt candidate.crt

  # Compare existing hosted cert against a new renewal candidate
  cert-compare.sh current_prod.crt new_candidate.crt
  cert-compare.sh new_candidate.crt https://example.com
  cert-compare.sh --only-diff google.com:443 youtube.com:443

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
ONLY_DIFF=false
QUIET=false
NO_COLOR_FLAG=0
CUSTOM_WIDTH=108

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--only-diff|--diff-only)
            ONLY_DIFF=true
            shift
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
python3 - << 'EOF' "$CERT1_PEM" "$CERT2_PEM" "$TARGET1" "$TARGET2" "$SAN_ONLY" "$ONLY_DIFF" "$QUIET" "$NO_COLOR_FLAG" "$CUSTOM_WIDTH"
import sys
import os
import re
import subprocess
from datetime import datetime, timezone

cert1_pem, cert2_pem, target1, target2, san_only_str, only_diff_str, quiet_str, no_color_str, width_str = sys.argv[1:10]
san_only = san_only_str.lower() == 'true'
only_diff = only_diff_str.lower() == 'true'
quiet = quiet_str.lower() == 'true'
no_color = (no_color_str == '1') or ('NO_COLOR' in os.environ)
total_width = int(width_str) if width_str.isdigit() else 108

# Color formatting class
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

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.stdout.strip()
    except Exception:
        return ""

def clean_san(raw_san):
    s = raw_san.strip()
    if s.startswith("DNS:"):
        return s[4:].strip()
    elif s.startswith("IP Address:"):
        return f"[IP] {s[11:].strip()}"
    elif s.startswith("IP:"):
        return f"[IP] {s[3:].strip()}"
    elif s.startswith("URI:"):
        return f"[URI] {s[4:].strip()}"
    elif s.startswith("email:") or s.startswith("emailAddress:"):
        return f"[Email] {s.split(':', 1)[-1].strip()}"
    return s

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
    
    d['dt_not_before'] = None
    d['dt_not_after'] = None
    try:
        cleaned_nb = " ".join(nb_raw.split())
        d['dt_not_before'] = datetime.strptime(cleaned_nb, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        cleaned_na = " ".join(na_raw.split())
        d['dt_not_after'] = datetime.strptime(cleaned_na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
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
    
    # Extensions (Normalized Key Usage & EKU)
    ku_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext keyUsage | grep -v 'Key Usage'").strip()
    d['key_usage_list'] = sorted([x.strip() for x in ku_raw.split(",") if x.strip()])
    d['key_usage'] = ", ".join(d['key_usage_list'])
    
    eku_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext extendedKeyUsage | grep -v 'Extended Key Usage'").strip()
    d['eku_list'] = sorted([x.strip() for x in eku_raw.split(",") if x.strip()])
    d['ext_key_usage'] = ", ".join(d['eku_list'])
    
    d['basic_constraints'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext basicConstraints | grep -v 'Basic Constraints'").strip()
    d['ocsp'] = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ocsp_uri")
    
    san_raw = run_cmd(f"openssl x509 -in '{pem_path}' -noout -ext subjectAltName | grep -v 'Subject Alternative Name'")
    sans = []
    if san_raw:
        for item in san_raw.split(","):
            val = clean_san(item)
            if val:
                sans.append(val)
    d['sans'] = sorted(list(set(sans)))
    return d

c1 = parse_cert(cert1_pem)
c2 = parse_cert(cert2_pem)

# ------------------------------------------------------------------------------
# Chronology & Role Auto-Detection (Baseline vs Renewal Candidate)
# ------------------------------------------------------------------------------
is_identical = (c1['sha256'] == c2['sha256'])

c1_is_candidate = False
c2_is_candidate = False

if is_identical:
    c1_role_label = "[ PEER TWIN ]"
    c2_role_label = "[ PEER TWIN ]"
    candidate_num = 2
    base_cert, cand_cert = c1, c2
    base_target, cand_target = target1, target2
else:
    if c1['dt_not_after'] and c2['dt_not_after']:
        if c2['dt_not_after'] > c1['dt_not_after']:
            c2_is_candidate = True
        elif c1['dt_not_after'] > c2['dt_not_after']:
            c1_is_candidate = True
        else:
            if c1['dt_not_before'] and c2['dt_not_before']:
                if c2['dt_not_before'] > c1['dt_not_before']:
                    c2_is_candidate = True
                elif c1['dt_not_before'] > c2['dt_not_before']:
                    c1_is_candidate = True
    
    if not c1_is_candidate and not c2_is_candidate:
        c2_is_candidate = True

    if c2_is_candidate:
        c1_role_label = "[ BASELINE / HOSTED ]"
        c2_role_label = "[ RENEWAL CANDIDATE ]"
        base_cert, cand_cert = c1, c2
        base_target, cand_target = target1, target2
        candidate_num = 2
    else:
        c1_role_label = "[ RENEWAL CANDIDATE ]"
        c2_role_label = "[ BASELINE / HOSTED ]"
        base_cert, cand_cert = c2, c1
        base_target, cand_target = target2, target1
        candidate_num = 1

base_sans = set(base_cert['sans']) if not is_identical else set(c1['sans'])
cand_sans = set(cand_cert['sans']) if not is_identical else set(c2['sans'])

common_sans = sorted(list(base_sans & cand_sans))
removed_sans = sorted(list(base_sans - cand_sans))
added_sans = sorted(list(cand_sans - base_sans))
all_unique_sans = sorted(list(set(c1['sans']) | set(c2['sans'])))

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
    ("Valid From (Issue)", c1['not_before'], c2['not_before']),
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

if quiet:
    sys.exit(0 if (removed_count == 0 and not is_identical and cand_cert['days_remaining'] > base_cert['days_remaining']) else 1)

# ------------------------------------------------------------------------------
# 1. TOP HEADER & CHRONOLOGY DASHBOARD
# ------------------------------------------------------------------------------
print()
banner_title = "🔐  X.509 CERTIFICATE COMPARISON & RENEWAL AUDITOR"
if only_diff:
    banner_title += " [ONLY DIFFERENCES]"
inner_w = total_width - 4

print(f"{C.CYAN}╭" + "─" * (total_width - 2) + f"╮{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f'{C.BOLD}{C.WHITE}{banner_title}{C.RESET}', inner_w, 'center')} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

if is_identical:
    t1_tag = f"{C.BG_GREEN} {c1_role_label} {C.RESET}"
    t2_tag = f"{C.BG_GREEN} {c2_role_label} {C.RESET}"
elif c2_is_candidate:
    t1_tag = f"{C.BG_DARK} {c1_role_label} {C.RESET}"
    t2_tag = f"{C.BG_CYAN} {c2_role_label} {C.RESET}"
else:
    t1_tag = f"{C.BG_CYAN} {c1_role_label} {C.RESET}"
    t2_tag = f"{C.BG_DARK} {c2_role_label} {C.RESET}"

line_t1 = f"  {C.BOLD}Cert [1] (Left):{C.RESET}  {C.YELLOW}{target1:<38}{C.RESET}  {t1_tag}"
line_t2 = f"  {C.BOLD}Cert [2] (Right):{C.RESET} {C.YELLOW}{target2:<38}{C.RESET}  {t2_tag}"

print(f"{C.CYAN}│{C.RESET} {pad_to(line_t1, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(line_t2, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}├" + "─" * (total_width - 2) + f"┤{C.RESET}")

diff_badge = f"{C.RED}{C.BOLD}{param_diffs} Param Diff(s){C.RESET}" if param_diffs > 0 else f"{C.GREEN}{C.BOLD}All Params Match{C.RESET}"
san_match_badge = f"{C.GREEN}{common_count} Common SANs{C.RESET}"
san_add_badge = f"{C.CYAN}+{added_count} New in Candidate{C.RESET}" if added_count > 0 else f"{C.GRAY}0 New SANs{C.RESET}"
san_rem_badge = f"{C.RED}{C.BOLD}-{removed_count} Lost from Baseline!{C.RESET}" if removed_count > 0 else f"{C.GRAY}0 Lost SANs{C.RESET}"

dash_line = f"  📊 {C.BOLD}AUDIT SUMMARY:{C.RESET}  {diff_badge}   │   {san_match_badge}   │   {san_add_badge}   │   {san_rem_badge}"
print(f"{C.CYAN}│{C.RESET} {pad_to(dash_line, inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")

# ------------------------------------------------------------------------------
# 2. GENERAL PARAMETERS SIDE-BY-SIDE TABLE
# ------------------------------------------------------------------------------
if not san_only:
    print()
    sec1_title = "1. GENERAL PARAMETERS (ONLY DIFFERENCES)" if only_diff else "1. GENERAL PARAMETERS COMPARISON"
    p_name_w = 22
    p_val_w = (total_width - p_name_w - 12) // 2
    
    t_top = f"╭─ {C.BOLD}{C.WHITE}{sec1_title}{C.RESET} " + "─" * max(0, total_width - len(sec1_title) - 5) + "╮"
    t_h1 = f"CERT [1] {c1_role_label}"
    t_h2 = f"CERT [2] {c2_role_label}"
    t_head = f"│ {pad_to(f'{C.BOLD}{C.CYAN}PARAMETER{C.RESET}', p_name_w)} │ {pad_to(f'{C.BOLD}{C.WHITE}{t_h1}{C.RESET}', p_val_w)} │ {'DIFF':^4} │ {pad_to(f'{C.BOLD}{C.WHITE}{t_h2}{C.RESET}', p_val_w)} │"
    t_sep = f"├" + "─" * (p_name_w + 2) + "┼" + "─" * (p_val_w + 2) + "┼" + "─" * 6 + "┼" + "─" * (p_val_w + 2) + "┤"
    t_bot = f"╰" + "─" * (p_name_w + 2) + "┴" + "─" * (p_val_w + 2) + "┴" + "─" * 6 + "┴" + "─" * (p_val_w + 2) + "╯"

    print(f"{C.CYAN}{t_top}{C.RESET}")
    
    filtered_params = [p for p in params_to_compare if (not only_diff or p[1] != p[2])]

    if only_diff and not filtered_params:
        match_msg = f"{C.GREEN}✔ All {len(params_to_compare)} General Parameters are identical. No parameter differences detected.{C.RESET}"
        print(f"{C.CYAN}│{C.RESET} {pad_to(match_msg, inner_w)} {C.CYAN}│{C.RESET}")
        print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")
    else:
        print(f"{C.CYAN}{t_head}{C.RESET}")
        print(f"{C.CYAN}{t_sep}{C.RESET}")

        for name, v1, v2 in filtered_params:
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
                v1_col = pad_to(f"{C.YELLOW if c1_is_candidate else C.WHITE}{v1_disp}{C.RESET}", p_val_w)
                v2_col = pad_to(f"{C.YELLOW if c2_is_candidate else C.WHITE}{v2_disp}{C.RESET}", p_val_w)
                p_col = pad_to(f"{C.CYAN}{C.BOLD}{name}{C.RESET}", p_name_w)
                
            print(f"{C.CYAN}│{C.RESET} {p_col} {C.CYAN}│{C.RESET} {v1_col} {C.CYAN}│{C.RESET} {tag} {C.CYAN}│{C.RESET} {v2_col} {C.CYAN}│{C.RESET}")

        print(f"{C.CYAN}{t_bot}{C.RESET}")

# ------------------------------------------------------------------------------
# 3. SIDE-BY-SIDE SUBJECT ALTERNATIVE NAMES (SAN) TABLE
# ------------------------------------------------------------------------------
print()
sec2_title = "2. SUBJECT ALTERNATIVE NAMES (ONLY DIFFERENCES)" if only_diff else "2. SUBJECT ALTERNATIVE NAMES (SAN) SIDE-BY-SIDE"
san_col_w = (total_width - 10) // 2

s_top = f"╭─ {C.BOLD}{C.WHITE}{sec2_title}{C.RESET} " + "─" * max(0, total_width - len(sec2_title) - 5) + "╮"
s_h1 = f"Cert [1] SANs ({len(c1['sans'])}) {c1_role_label}"
s_h2 = f"Cert [2] SANs ({len(c2['sans'])}) {c2_role_label}"
s_head = f"│ {pad_to(f'{C.BOLD}{C.WHITE}{s_h1}{C.RESET}', san_col_w)} │ {'STAT':^4} │ {pad_to(f'{C.BOLD}{C.WHITE}{s_h2}{C.RESET}', san_col_w)} │"
s_sep = f"├" + "─" * (san_col_w + 2) + "┼" + "─" * 6 + "┼" + "─" * (san_col_w + 2) + "┤"
s_bot = f"╰" + "─" * (san_col_w + 2) + "┴" + "─" * 6 + "┴" + "─" * (san_col_w + 2) + "╯"

print(f"{C.CYAN}{s_top}{C.RESET}")

s1_set = set(c1['sans'])
s2_set = set(c2['sans'])

if only_diff:
    san_list_to_show = [s for s in all_unique_sans if not (s in s1_set and s in s2_set)]
else:
    san_list_to_show = all_unique_sans

if only_diff and san_diff_count == 0:
    no_diff_san = f"{C.GREEN}✔ All {common_count} SAN domains are identical between both certificates (0 delta entries).{C.RESET}"
    print(f"{C.CYAN}│{C.RESET} {pad_to(no_diff_san, inner_w)} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}╰" + "─" * (total_width - 2) + f"╯{C.RESET}")
elif not san_list_to_show:
    no_san_msg = pad_to(f"{C.GRAY}<No Subject Alternative Names Found>{C.RESET}", san_col_w)
    print(f"{C.CYAN}{s_head}{C.RESET}")
    print(f"{C.CYAN}{s_sep}{C.RESET}")
    print(f"{C.CYAN}│{C.RESET} {no_san_msg} {C.CYAN}│{C.RESET} {C.GRAY} == {C.RESET} {C.CYAN}│{C.RESET} {no_san_msg} {C.CYAN}│{C.RESET}")
    print(f"{C.CYAN}{s_bot}{C.RESET}")
else:
    print(f"{C.CYAN}{s_head}{C.RESET}")
    print(f"{C.CYAN}{s_sep}{C.RESET}")
    for san in san_list_to_show:
        in_c1 = san in s1_set
        in_c2 = san in s2_set
        
        san_disp = san if len(san) <= san_col_w else (san[:san_col_w-3] + "...")
        placeholder = "· " * ((san_col_w // 2) - 1)
        
        if in_c1 and in_c2:
            tag = f"{C.GREEN}{C.BOLD} == {C.RESET}"
            left_side = pad_to(f"{C.GREEN}{san_disp}{C.RESET}", san_col_w)
            right_side = pad_to(f"{C.GREEN}{san_disp}{C.RESET}", san_col_w)
        elif in_c1 and not in_c2:
            if c1_is_candidate:
                tag = f"{C.CYAN}{C.BOLD} +  {C.RESET}"
                left_side = pad_to(f"{C.CYAN}{C.BOLD}{san_disp}{C.RESET}", san_col_w)
                right_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
            else:
                tag = f"{C.RED}{C.BOLD} -  {C.RESET}"
                left_side = pad_to(f"{C.RED}{C.BOLD}{san_disp}{C.RESET}", san_col_w)
                right_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
        elif not in_c1 and in_c2:
            if c2_is_candidate:
                tag = f"{C.CYAN}{C.BOLD} +  {C.RESET}"
                left_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
                right_side = pad_to(f"{C.CYAN}{C.BOLD}{san_disp}{C.RESET}", san_col_w)
            else:
                tag = f"{C.RED}{C.BOLD} -  {C.RESET}"
                left_side = pad_to(f"{C.DARK_GRAY}{placeholder}{C.RESET}", san_col_w)
                right_side = pad_to(f"{C.RED}{C.BOLD}{san_disp}{C.RESET}", san_col_w)

        print(f"{C.CYAN}│{C.RESET} {left_side} {C.CYAN}│{C.RESET} {tag} {C.CYAN}│{C.RESET} {right_side} {C.CYAN}│{C.RESET}")

    print(f"{C.CYAN}{s_bot}{C.RESET}")

# ------------------------------------------------------------------------------
# 4. CANDIDATE READINESS & RISK VERDICT CARD
# ------------------------------------------------------------------------------
print()
sec3_title = "3. RENEWAL READINESS & RISK VERDICT"
v_top = f"╭─ {C.BOLD}{C.WHITE}{sec3_title}{C.RESET} " + "─" * max(0, total_width - len(sec3_title) - 5) + "╮"
v_bot = f"╰" + "─" * (total_width - 2) + "╯"

base_ekus = set(base_cert['eku_list']) if not is_identical else set(c1['eku_list'])
cand_ekus = set(cand_cert['eku_list']) if not is_identical else set(c2['eku_list'])
eku_removed = sorted(list(base_ekus - cand_ekus))
eku_added = sorted(list(cand_ekus - base_ekus))

server_auth_lost = any("Server Authentication" in x for x in eku_removed)
client_auth_lost = any("Client Authentication" in x for x in eku_removed)

if is_identical:
    scenario_title = "🎯 EXACT IDENTICAL CERTIFICATE"
    risk_pill = f"{C.BG_GREEN} RISK: NONE (IDENTICAL ISSUE) {C.RESET}"
    action_item = f"{C.GREEN}✔ No action needed.{C.RESET} Both targets serve the exact same cryptographic certificate."
elif server_auth_lost:
    scenario_title = "🚨 FATAL EKU LOSS: Server Authentication Dropped!"
    risk_pill = f"{C.BG_RED} RISK: CRITICAL (TLS HANDSHAKE OUTAGE) {C.RESET}"
    action_item = f"{C.RED}✖ DO NOT DEPLOY!{C.RESET} The candidate is missing 'TLS Web Server Authentication'. Browsers & clients will reject connections!"
elif common_count == 0 and len(base_sans) > 0 and len(cand_sans) > 0:
    scenario_title = "❌ COMPLETELY DISJOINT / UNRELATED CERTIFICATES"
    risk_pill = f"{C.BG_RED} RISK: HIGH (INCOMPATIBLE TARGETS) {C.RESET}"
    action_item = f"{C.RED}✖ Incompatible targets.{C.RESET} 0% domain overlap. Do not deploy as a replacement!"
elif removed_count > 0:
    scenario_title = f"🚨 SAN CONTRACTION / HOSTNAME REMOVAL ({removed_count} Domains Lost!)"
    risk_pill = f"{C.BG_RED} RISK: CRITICAL (BREAKING OUTAGE RISK) {C.RESET}"
    action_item = f"{C.RED}✖ DO NOT DEPLOY CANDIDATE!{C.RESET} The candidate is missing {removed_count} active domain(s) present in the hosted baseline!"
elif client_auth_lost:
    scenario_title = "⚠️ EKU CONTRACTION: Client Authentication (mTLS) Dropped"
    risk_pill = f"{C.BG_YELLOW} RISK: HIGH (mTLS BREAKAGE RISK) {C.RESET}"
    action_item = f"{C.YELLOW}⚠ Verify mTLS requirements.{C.RESET} 'TLS Web Client Authentication' was dropped; mutual TLS clients may fail."
elif removed_count == 0 and added_count > 0:
    scenario_title = f"📈 SAFE SAN EXPANSION (+{added_count} New Domains Added)"
    risk_pill = f"{C.BG_BLUE} RISK: LOW-MEDIUM (SAFE FOR EXISTING TRAFFIC) {C.RESET}"
    action_item = f"{C.GREEN}✔ Safe for current traffic.{C.RESET} All hosted domains preserved. Ensure DNS for newly added SANs is configured."
elif cand_cert['days_remaining'] < base_cert['days_remaining']:
    scenario_title = "⚠️ EXPIRATION REGRESSION DETECTED"
    risk_pill = f"{C.BG_RED} RISK: HIGH (LIFETIME REGRESSION) {C.RESET}"
    action_item = f"{C.RED}✖ Hold deployment!{C.RESET} Candidate certificate expires SOONER than the currently hosted baseline."
elif base_cert['is_expired'] and not cand_cert['is_expired']:
    scenario_title = "🔄 EXPIRED CERTIFICATE RESTORATION"
    risk_pill = f"{C.BG_GREEN} RISK: LOW (CRITICAL FIX) {C.RESET}"
    action_item = f"{C.GREEN}✔ Deploy immediately.{C.RESET} The hosted baseline is expired; candidate restores HTTPS trust."
else:
    scenario_title = "🔄 SEAMLESS CERTIFICATE RENEWAL"
    risk_pill = f"{C.BG_GREEN} RISK: LOW (READY TO DEPLOY) {C.RESET}"
    action_item = f"{C.GREEN}✔ Candidate is fully validated.{C.RESET} Safe for zero-downtime rotation on Load Balancers & Gateways."

print(f"{C.CYAN}{v_top}{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}VERDICT:{C.RESET}     {C.BOLD}{C.WHITE}{scenario_title}{C.RESET}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}RISK LEVEL:{C.RESET}  {risk_pill}', inner_w)} {C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET}" + " " * (inner_w + 2) + f"{C.CYAN}│{C.RESET}")
print(f"{C.CYAN}│{C.RESET} {pad_to(f' {C.BOLD}{C.WHITE}🔍 Role-Aware Lifecycle Analysis (Baseline ➔ Candidate):{C.RESET}', inner_w)} {C.CYAN}│{C.RESET}")

if not is_identical:
    role_info = f"   • {C.WHITE}Identified Roles:{C.RESET} Cert [{candidate_num}] ({cand_target}) is the {C.CYAN}{C.BOLD}Renewal Candidate{C.RESET}."
    print(f"{C.CYAN}│{C.RESET} {pad_to(role_info, inner_w)} {C.CYAN}│{C.RESET}")

if san_diff_count == 0:
    san_msg = f"   • {C.GREEN}SAN Coverage:{C.RESET}    100% Match ({common_count}/{common_count} hosted domains preserved)."
elif removed_count == 0:
    san_msg = f"   • {C.GREEN}SAN Coverage:{C.RESET}    Backwards-Compatible ({common_count} hosted preserved, +{added_count} new)."
elif common_count == 0:
    san_msg = f"   • {C.RED}SAN Coverage:{C.RESET}    0% Overlap between Baseline and Candidate."
else:
    san_msg = f"   • {C.YELLOW}SAN Coverage:{C.RESET}    Partial ({common_count} kept, +{added_count} added, {C.RED}-{removed_count} lost from baseline{C.RESET})."
print(f"{C.CYAN}│{C.RESET} {pad_to(san_msg, inner_w)} {C.CYAN}│{C.RESET}")

if base_cert['dt_not_after'] and cand_cert['dt_not_after']:
    delta_days = (cand_cert['dt_not_after'] - base_cert['dt_not_after']).days
    if delta_days > 0:
        val_msg = f"   • {C.GREEN}Validity Gain:{C.RESET}   Candidate extends lifespan by {C.BOLD}+{delta_days} days{C.RESET} ({cand_cert['days_remaining']}d remaining)."
    elif delta_days < 0:
        val_msg = f"   • {C.RED}Validity Delta:{C.RESET}  Candidate expires {C.BOLD}{abs(delta_days)} days SOONER{C.RESET} than baseline!"
    else:
        val_msg = f"   • {C.GRAY}Validity Delta:{C.RESET}  Both certificates share the exact same expiry date."
    print(f"{C.CYAN}│{C.RESET} {pad_to(val_msg, inner_w)} {C.CYAN}│{C.RESET}")

if base_cert['pubkey_hash'] == cand_cert['pubkey_hash'] and base_cert['pubkey_hash']:
    key_msg = f"   • {C.GRAY}Key Pair:{C.RESET}        Candidate re-uses existing private key (CSR re-signed)."
else:
    key_msg = f"   • {C.CYAN}Key Pair:{C.RESET}        Candidate uses a fresh private/public key pair (Rotated)."
print(f"{C.CYAN}│{C.RESET} {pad_to(key_msg, inner_w)} {C.CYAN}│{C.RESET}")

if eku_removed or eku_added:
    if eku_removed:
        print(f"{C.CYAN}│{C.RESET} " + pad_to(f"   • {C.RED}EKU Dropped:{C.RESET}     Candidate lost: {', '.join(eku_removed)}", inner_w) + f" {C.CYAN}│{C.RESET}")
    if eku_added:
        print(f"{C.CYAN}│{C.RESET} " + pad_to(f"   • {C.GREEN}EKU Added:{C.RESET}       Candidate gained: {', '.join(eku_added)}", inner_w) + f" {C.CYAN}│{C.RESET}")

if base_cert['pubkey_info'] != cand_cert['pubkey_info']:
    crypto_msg = f"   • {C.MAGENTA}Crypto Shift:{C.RESET}    {base_cert['pubkey_info']} ➔ {cand_cert['pubkey_info']}"
    print(f"{C.CYAN}│{C.RESET} {pad_to(crypto_msg, inner_w)} {C.CYAN}│{C.RESET}")

if base_cert['issuer_dn'] != cand_cert['issuer_dn']:
    ca_msg = f"   • {C.CYAN}CA Authority:{C.RESET}    {base_cert['issuer_cn']} ➔ {cand_cert['issuer_cn']}"
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
