#!/usr/bin/env bash
# ==============================================================================
# Script Name: san-compare.sh
# Description: Compares two X.509 leaf certificates parameter-by-parameter and
#              displays a true SIDE-BY-SIDE SAN table with rich lifecycle verdicts.
# Author: Daily Tools (https://github.com/khishoer/Daily-tools)
# Requirements: bash, openssl, awk, sed, grep, python3
# ==============================================================================

# ------------------------------------------------------------------------------
# Color formatting
# ------------------------------------------------------------------------------
setup_colors() {
    if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
        BOLD="\033[1m"
        DIM="\033[2m"
        RED="\033[31m"
        GREEN="\033[32m"
        YELLOW="\033[33m"
        BLUE="\033[34m"
        MAGENTA="\033[35m"
        CYAN="\033[36m"
        WHITE="\033[37m"
        BG_RED="\033[41;37m"
        BG_GREEN="\033[42;30m"
        BG_YELLOW="\033[43;30m"
        BG_BLUE="\033[44;37m"
        RESET="\033[0m"
    else
        BOLD=""
        DIM=""
        RED=""
        GREEN=""
        YELLOW=""
        BLUE=""
        MAGENTA=""
        CYAN=""
        WHITE=""
        BG_RED=""
        BG_GREEN=""
        BG_YELLOW=""
        BG_BLUE=""
        RESET=""
    fi
}

# ------------------------------------------------------------------------------
# Help & Usage
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
${BOLD}Usage:${RESET}
  san-compare.sh [OPTIONS] <CERT1> <CERT2>

${BOLD}Description:${RESET}
  Deeply compares two X.509 leaf certificates across all standard parameters
  with a dedicated ${BOLD}SIDE-BY-SIDE SAN COMPARISON TABLE${RESET} and rich lifecycle verdicts:
  - 🔄 Seamless Renewal / Re-issuance
  - 📈 Backwards-Compatible SAN Expansion
  - 🚨 Dangerous SAN Contraction (Breaking Changes)
  - 🔀 Mixed SAN Overhaul & Domain Drift
  - ❌ Completely Disjoint / Unrelated Certificates

${BOLD}Arguments:${RESET}
  <CERT1>, <CERT2>     Can be:
                       - Local file path (.pem, .crt, .cer, .der, .p7b)
                       - Remote hostname with port (e.g. "google.com:443" or "https://github.com")

${BOLD}Options:${RESET}
  -s, --san-only       Only compare Subject Alternative Names (SANs) in side-by-side view
  -w, --width <num>    Set terminal table width (default: auto or 100)
  -q, --quiet          Quiet mode: suppress output, exit 0 if identical, 1 if differences
  -n, --no-color       Disable color output
  -h, --help           Show this help message

${BOLD}Examples:${RESET}
  san-compare.sh cert_v1.pem cert_v2.pem
  san-compare.sh google.com:443 youtube.com:443
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
    local label="$3"

    # 1. Check if target is a remote URL or Host:Port
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

        echo -e "${DIM}[*] Fetching leaf certificate from remote host: ${BOLD}${host}:${port}${RESET}..." >&2
        if ! echo | openssl s_client -servername "$host" -connect "${host}:${port}" -showcerts 2>/dev/null | \
             openssl x509 -outform PEM > "$out_pem" 2>/dev/null; then
            echo -e "${RED}[ERROR] Failed to fetch certificate from ${host}:${port}${RESET}" >&2
            exit 1
        fi
        return 0
    fi

    # 2. Local file
    if [[ ! -f "$target" ]]; then
        echo -e "${RED}[ERROR] File not found: '$target'${RESET}" >&2
        exit 1
    fi

    # Check if PEM
    if openssl x509 -in "$target" -inform PEM -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    # Check if DER
    elif openssl x509 -in "$target" -inform DER -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    # Check if PKCS#7 (.p7b)
    elif openssl pkcs7 -in "$target" -print_certs 2>/dev/null | openssl x509 -outform PEM > "$out_pem" 2>/dev/null; then
        return 0
    else
        echo -e "${RED}[ERROR] Unsupported or corrupted certificate format: '$target'${RESET}" >&2
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Extract Parameters from PEM Certificate safely
# ------------------------------------------------------------------------------
safe_x509_cmd() {
    openssl x509 -in "$1" "${@:2}" 2>/dev/null || true
}

extract_params() {
    local pem="$1"
    local prefix="$2" # "c1" or "c2"

    # Subject & Issuer
    eval "${prefix}_subject=\"\$(safe_x509_cmd \"\$pem\" -noout -subject -nameopt RFC2253 | sed -e 's/^subject= //' -e 's/^[ \t]*//')\""
    eval "${prefix}_issuer=\"\$(safe_x509_cmd \"\$pem\" -noout -issuer -nameopt RFC2253 | sed -e 's/^issuer= //' -e 's/^[ \t]*//')\""

    # Subject CN & Issuer CN
    eval "${prefix}_subject_cn=\"\$(safe_x509_cmd \"\$pem\" -noout -subject | sed -n 's/.*CN[ =]*//p' | sed 's/,.*//')\""
    eval "${prefix}_issuer_cn=\"\$(safe_x509_cmd \"\$pem\" -noout -issuer | sed -n 's/.*CN[ =]*//p' | sed 's/,.*//')\""

    # Serial Number & Signature Algorithm
    eval "${prefix}_serial=\"\$(safe_x509_cmd \"\$pem\" -noout -serial | sed 's/^serial=//')\""
    eval "${prefix}_sig_algo=\"\$(safe_x509_cmd \"\$pem\" -noout -text | grep 'Signature Algorithm:' | head -n 1 | awk -F: '{print \$2}' | sed 's/^[ \t]*//' || true)\""

    # Validity Dates
    local nb na
    nb=$(safe_x509_cmd "$pem" -noout -startdate | sed 's/^notBefore=//')
    na=$(safe_x509_cmd "$pem" -noout -enddate | sed 's/^notAfter=//')
    eval "${prefix}_not_before=\"\$nb\""
    eval "${prefix}_not_after=\"\$na\""

    # Validity Status
    if openssl x509 -in "$pem" -checkend 0 -noout >/dev/null 2>&1; then
        eval "${prefix}_status=\"VALID\""
    else
        eval "${prefix}_status=\"EXPIRED\""
    fi

    # Public Key Info (Algorithm & Size)
    local pubkey_algo pubkey_bits
    pubkey_algo=$(safe_x509_cmd "$pem" -noout -text | grep -A 1 "Public Key Algorithm:" | head -n 1 | awk -F: '{print $2}' | sed 's/^[ \t]*//' || true)
    pubkey_bits=$(safe_x509_cmd "$pem" -noout -text | grep -E "(Public-Key|RSA Public-Key|NIST CURVE|ASN1 OID):" | head -n 1 | sed -E 's/.*: (.*)/\1/' | sed 's/^[ \t]*//' || true)
    eval "${prefix}_pubkey_algo=\"\$pubkey_algo\""
    eval "${prefix}_pubkey_bits=\"\$pubkey_bits\""
    eval "${prefix}_pubkey_info=\"\${pubkey_algo:-Unknown} (\${pubkey_bits:-N/A})\""

    # Public Key Hash (to check if private/public key was rotated)
    eval "${prefix}_pubkey_modulus=\"\$(openssl x509 -in \"\$pem\" -noout -pubkey 2>/dev/null | openssl sha256 | awk '{print \$NF}' || true)\""

    # Fingerprints
    eval "${prefix}_sha256=\"\$(safe_x509_cmd \"\$pem\" -noout -fingerprint -sha256 | sed -e 's/^SHA256 Fingerprint=//' -e 's/^sha256 Fingerprint=//')\""
    eval "${prefix}_sha1=\"\$(safe_x509_cmd \"\$pem\" -noout -fingerprint -sha1 | sed -e 's/^SHA1 Fingerprint=//' -e 's/^sha1 Fingerprint=//')\""

    # Key Identifiers (SKI & AKI)
    eval "${prefix}_ski=\"\$(safe_x509_cmd \"\$pem\" -noout -ext subjectKeyIdentifier | grep -v 'SubjectKeyIdentifier' | sed 's/^[ \t]*//' | tr -d '\n' || true)\""
    eval "${prefix}_aki=\"\$(safe_x509_cmd \"\$pem\" -noout -ext authorityKeyIdentifier | grep -A 1 'keyid:' | grep 'keyid:' | sed 's/.*keyid://' | tr -d ' \n' || true)\""

    # Key Usage & Extended Key Usage
    eval "${prefix}_key_usage=\"\$(safe_x509_cmd \"\$pem\" -noout -ext keyUsage | grep -v 'Key Usage' | sed 's/^[ \t]*//' | tr -d '\n' || true)\""
    eval "${prefix}_ext_key_usage=\"\$(safe_x509_cmd \"\$pem\" -noout -ext extendedKeyUsage | grep -v 'Extended Key Usage' | sed 's/^[ \t]*//' | tr -d '\n' || true)\""

    # Basic Constraints (CA / Pathlen)
    eval "${prefix}_basic_constraints=\"\$(safe_x509_cmd \"\$pem\" -noout -ext basicConstraints | grep -v 'Basic Constraints' | sed 's/^[ \t]*//' | tr -d '\n' || true)\""

    # OCSP
    eval "${prefix}_ocsp=\"\$(safe_x509_cmd \"\$pem\" -noout -ocsp_uri || true)\""

    # SAN extraction -> file
    local san_file="${TMP_DIR}/${prefix}_sans.txt"
    safe_x509_cmd "$pem" -noout -ext subjectAltName | \
        grep -v "Subject Alternative Name" | \
        tr ',' '\n' | \
        sed 's/^[ \t]*//;s/[ \t]*$//' | \
        grep -v '^$' | \
        sort -u > "$san_file" || touch "$san_file"
}

# ------------------------------------------------------------------------------
# Comparison Runner
# ------------------------------------------------------------------------------
TOTAL_DIFFS=0
TOTAL_CHECKS=0

compare_field() {
    local label="$1"
    local val1="$2"
    local val2="$3"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Normalize empty or null values
    val1="${val1:-<Not Present>}"
    val2="${val2:-<Not Present>}"

    if [[ "$val1" == "$val2" ]]; then
        printf "  ${GREEN}✔${RESET} ${BOLD}%-26s${RESET} : %s\n" "$label" "$val1"
    else
        TOTAL_DIFFS=$((TOTAL_DIFFS + 1))
        printf "  ${RED}✖${RESET} ${BOLD}%-26s${RESET} :\n" "$label"
        printf "      ${RED}[1] %s${RESET}\n" "$val1"
        printf "      ${GREEN}[2] %s${RESET}\n" "$val2"
    fi
}

# ------------------------------------------------------------------------------
# Main Script Execution
# ------------------------------------------------------------------------------
SAN_ONLY=false
QUIET=false
CUSTOM_WIDTH=""

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
        -w|--width)
            CUSTOM_WIDTH="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -n|--no-color)
            NO_COLOR=1
            shift
            ;;
        -*)
            echo -e "${RED}[ERROR] Unknown option: $1${RESET}" >&2
            show_help
            exit 1
            ;;
        *)
            if [[ -z "${TARGET1:-}" ]]; then
                TARGET1="$1"
            elif [[ -z "${TARGET2:-}" ]]; then
                TARGET2="$1"
            else
                echo -e "${RED}[ERROR] Unexpected additional argument: $1${RESET}" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

setup_colors

if [[ -z "${TARGET1:-}" || -z "${TARGET2:-}" ]]; then
    echo -e "${RED}[ERROR] You must provide two certificate targets to compare.${RESET}\n" >&2
    show_help
    exit 1
fi

CERT1_PEM="${TMP_DIR}/cert1.pem"
CERT2_PEM="${TMP_DIR}/cert2.pem"

load_certificate "$TARGET1" "$CERT1_PEM" "1"
load_certificate "$TARGET2" "$CERT2_PEM" "2"

extract_params "$CERT1_PEM" "c1"
extract_params "$CERT2_PEM" "c2"

# ------------------------------------------------------------------------------
# SAN Analysis
# ------------------------------------------------------------------------------
C1_SAN_FILE="${TMP_DIR}/c1_sans.txt"
C2_SAN_FILE="${TMP_DIR}/c2_sans.txt"

C1_SAN_COUNT=$(wc -l < "$C1_SAN_FILE" | tr -d ' ')
C2_SAN_COUNT=$(wc -l < "$C2_SAN_FILE" | tr -d ' ')

# Calculate Sets
COMMON_SANS="${TMP_DIR}/common_sans.txt"
REMOVED_SANS="${TMP_DIR}/removed_sans.txt" # in 1, not in 2
ADDED_SANS="${TMP_DIR}/added_sans.txt"     # in 2, not in 1

comm -12 "$C1_SAN_FILE" "$C2_SAN_FILE" > "$COMMON_SANS"
comm -23 "$C1_SAN_FILE" "$C2_SAN_FILE" > "$REMOVED_SANS"
comm -13 "$C1_SAN_FILE" "$C2_SAN_FILE" > "$ADDED_SANS"

COMMON_COUNT=$(wc -l < "$COMMON_SANS" | tr -d ' ')
REMOVED_COUNT=$(wc -l < "$REMOVED_SANS" | tr -d ' ')
ADDED_COUNT=$(wc -l < "$ADDED_SANS" | tr -d ' ')

SAN_DIFF_COUNT=$((REMOVED_COUNT + ADDED_COUNT))

# ------------------------------------------------------------------------------
# Date / Lifetime Analytics via Python Helper
# ------------------------------------------------------------------------------
DATE_EVAL=$(python3 -c "
from datetime import datetime, timezone

def parse_date(d_str):
    try:
        cleaned = ' '.join(d_str.split())
        return datetime.strptime(cleaned, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    except Exception:
        return None

d1 = parse_date('''$c1_not_after''')
d2 = parse_date('''$c2_not_after''')
now = datetime.now(timezone.utc)

rem1 = (d1 - now).days if d1 else 0
rem2 = (d2 - now).days if d2 else 0

delta_days = (d2 - d1).days if (d1 and d2) else 0

newer = 'true' if (d2 and d1 and d2 > d1) else 'false'
older = 'true' if (d2 and d1 and d2 < d1) else 'false'
same = 'true' if (d2 and d1 and d2 == d1) else 'false'

print(f'REM1={rem1};REM2={rem2};DELTA_DAYS={delta_days};NEWER={newer};OLDER={older};SAME_DATE={same}')
")

eval "$DATE_EVAL"

if [[ "$QUIET" == true ]]; then
    if [[ $SAN_DIFF_COUNT -eq 0 && "$c1_sha256" == "$c2_sha256" ]]; then
        exit 0
    else
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# Banner & Targets
# ------------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}========================================================================================================${RESET}"
echo -e "${BOLD}${CYAN}                            🔐 X.509 CERTIFICATE & SAN COMPARISON REPORT                               ${RESET}"
echo -e "${BOLD}${CYAN}========================================================================================================${RESET}"
echo -e "  ${BOLD}Cert [1]:${RESET} ${YELLOW}${TARGET1}${RESET}"
echo -e "  ${BOLD}Cert [2]:${RESET} ${YELLOW}${TARGET2}${RESET}"
echo -e "${CYAN}--------------------------------------------------------------------------------------------------------${RESET}"

# ------------------------------------------------------------------------------
# Parameter Diff Section (if not SAN-only)
# ------------------------------------------------------------------------------
if [[ "$SAN_ONLY" == false ]]; then
    echo -e "\n${BOLD}${MAGENTA}--- [ 1. General Certificate Parameters ] ---${RESET}"
    compare_field "Subject CN" "$c1_subject_cn" "$c2_subject_cn"
    compare_field "Subject (Full DN)" "$c1_subject" "$c2_subject"
    compare_field "Issuer CN" "$c1_issuer_cn" "$c2_issuer_cn"
    compare_field "Issuer (Full DN)" "$c1_issuer" "$c2_issuer"
    compare_field "Serial Number" "$c1_serial" "$c2_serial"
    compare_field "Signature Algorithm" "$c1_sig_algo" "$c2_sig_algo"
    compare_field "Public Key" "$c1_pubkey_info" "$c2_pubkey_info"
    compare_field "Not Before (Start)" "$c1_not_before" "$c2_not_before"
    compare_field "Not After (Expiry)" "$c1_not_after" "$c2_not_after"
    compare_field "Validity Status" "$c1_status ($REM1 days rem.)" "$c2_status ($REM2 days rem.)"
    compare_field "Key Usage" "$c1_key_usage" "$c2_key_usage"
    compare_field "Ext Key Usage (EKU)" "$c1_ext_key_usage" "$c2_ext_key_usage"
    compare_field "Basic Constraints" "$c1_basic_constraints" "$c2_basic_constraints"
    compare_field "OCSP Responder" "$c1_ocsp" "$c2_ocsp"
    compare_field "Subject Key ID (SKI)" "$c1_ski" "$c2_ski"
    compare_field "Authority Key ID (AKI)" "$c1_aki" "$c2_aki"
    compare_field "SHA-256 Fingerprint" "$c1_sha256" "$c2_sha256"
fi

# ------------------------------------------------------------------------------
# SIDE-BY-SIDE SAN COMPARISON TABLE
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${MAGENTA}--- [ 2. Subject Alternative Name (SAN) Side-by-Side Comparison ] ---${RESET}"
echo -e "  • Total in Cert [1]: ${BOLD}${C1_SAN_COUNT}${RESET}  |  • Total in Cert [2]: ${BOLD}${C2_SAN_COUNT}${RESET}  |  • Common: ${GREEN}${BOLD}${COMMON_COUNT}${RESET}  |  • Added: ${CYAN}${BOLD}+${ADDED_COUNT}${RESET}  |  • Removed: ${RED}${BOLD}-${REMOVED_COUNT}${RESET}\n"

# Run Python side-by-side table renderer
python3 -c "
import os
import sys

c1_file = '''$C1_SAN_FILE'''
c2_file = '''$C2_SAN_FILE'''
target1 = '''$TARGET1'''
target2 = '''$TARGET2'''
use_color = os.environ.get('NO_COLOR') is None

with open(c1_file, 'r') as f:
    c1_sans = [line.strip() for line in f if line.strip()]

with open(c2_file, 'r') as f:
    c2_sans = [line.strip() for line in f if line.strip()]

c1_set = set(c1_sans)
c2_set = set(c2_sans)
all_sans = sorted(list(c1_set | c2_set))

# Color helpers
def colorize(text, color_code):
    if not use_color:
        return text
    return f'\033[{color_code}m{text}\033[0m'

# Column widths
term_cols = 104
col_w = 46

header_c1 = f'Cert [1]: {target1}'[:col_w]
header_c2 = f'Cert [2]: {target2}'[:col_w]

border = '+' + '-' * (col_w + 2) + '+' + '-' * 8 + '+' + '-' * (col_w + 2) + '+'
header = f'| {header_c1:<{col_w}} |  Diff  | {header_c2:<{col_w}} |'

print(colorize(border, '36'))
print(colorize(header, '1;37'))
print(colorize(border, '36'))

if not all_sans:
    empty_row = f'| {\"<No SANs Found>\":<{col_w}} |  ==    | {\"<No SANs Found>\":<{col_w}} |'
    print(empty_row)
else:
    for san in all_sans:
        in_c1 = san in c1_set
        in_c2 = san in c2_set
        san_display = san[:col_w]

        if in_c1 and in_c2:
            diff_tag = colorize('  ==  ', '32;1')
            left_txt = colorize(f'{san_display:<{col_w}}', '32')
            right_txt = colorize(f'{san_display:<{col_w}}', '32')
            print(f'| {left_txt} | {diff_tag} | {right_txt} |')
        elif in_c1 and not in_c2:
            diff_tag = colorize('  --  ', '31;1')
            left_txt = colorize(f'{san_display:<{col_w}}', '31;1')
            not_in_2 = '<Removed in Cert 2>'[:col_w]
            right_txt = colorize(f'{not_in_2:<{col_w}}', '2;31')
            print(f'| {left_txt} | {diff_tag} | {right_txt} |')
        elif not in_c1 and in_c2:
            diff_tag = colorize('  ++  ', '36;1')
            not_in_1 = '<Not in Cert 1>'[:col_w]
            left_txt = colorize(f'{not_in_1:<{col_w}}', '2;36')
            right_txt = colorize(f'{san_display:<{col_w}}', '36;1')
            print(f'| {left_txt} | {diff_tag} | {right_txt} |')

print(colorize(border, '36'))
"

# ------------------------------------------------------------------------------
# Multi-Dimensional Intelligence Verdict Analysis
# ------------------------------------------------------------------------------
echo ""
echo -e "${CYAN}========================================================================================================${RESET}"
echo -e "${BOLD}${CYAN}                                📊 COMPREHENSIVE VERDICT & RISK ANALYSIS                                ${RESET}"
echo -e "${CYAN}========================================================================================================${RESET}"

# Determine Scenario Category
SCENARIO=""
RISK_LEVEL=""
RISK_COLOR=""
SUMMARY_TITLE=""

# 1. Exact Duplicate
if [[ "$c1_sha256" == "$c2_sha256" ]]; then
    SCENARIO="IDENTICAL"
    RISK_LEVEL="NONE"
    RISK_COLOR="$GREEN"
    SUMMARY_TITLE="🎯 EXACT IDENTICAL CERTIFICATE (Same Fingerprint & Serial)"

# 2. Complete Disjoint (No shared domains)
elif [[ "$COMMON_COUNT" -eq 0 && "$C1_SAN_COUNT" -gt 0 && "$C2_SAN_COUNT" -gt 0 ]]; then
    SCENARIO="DISJOINT"
    RISK_LEVEL="HIGH (INCOMPATIBLE TARGETS)"
    RISK_COLOR="$RED"
    SUMMARY_TITLE="❌ COMPLETELY DISJOINT / UNRELATED CERTIFICATES"

# 3. Seamless Renewal (Same SANs, valid newer dates or rotated key/serial)
elif [[ "$SAN_DIFF_COUNT" -eq 0 ]]; then
    if [[ "$OLDER" == "true" ]]; then
        SCENARIO="RENEWAL_REGRESSION"
        RISK_LEVEL="HIGH (EXPIRATION REGRESSION)"
        RISK_COLOR="$RED"
        SUMMARY_TITLE="⚠️ LIFETIME REGRESSION (Cert [2] expires earlier than Cert [1])"
    elif [[ "$c1_status" == "EXPIRED" && "$c2_status" == "VALID" ]]; then
        SCENARIO="EXPIRED_REPLACEMENT"
        RISK_LEVEL="LOW (MANDATORY UPDATE)"
        RISK_COLOR="$GREEN"
        SUMMARY_TITLE="🔄 EXPIRED CERTIFICATE REPLACEMENT (Cert [1] is Expired)"
    else
        SCENARIO="RENEWAL_SEAMLESS"
        RISK_LEVEL="LOW (SAFE TO DEPLOY)"
        RISK_COLOR="$GREEN"
        SUMMARY_TITLE="🔄 SEAMLESS CERTIFICATE RENEWAL / RE-ISSUANCE"
    fi

# 4. Safe SAN Expansion (0 removed, N added)
elif [[ "$REMOVED_COUNT" -eq 0 && "$ADDED_COUNT" -gt 0 ]]; then
    SCENARIO="SAN_EXPANSION"
    RISK_LEVEL="LOW-MEDIUM (BACKWARDS COMPATIBLE)"
    RISK_COLOR="$GREEN"
    SUMMARY_TITLE="📈 SAN EXPANSION (All original domains preserved + $ADDED_COUNT new)"

# 5. Breaking SAN Contraction (N removed, 0 added)
elif [[ "$REMOVED_COUNT" -gt 0 && "$ADDED_COUNT" -eq 0 ]]; then
    SCENARIO="SAN_CONTRACTION"
    RISK_LEVEL="CRITICAL (BREAKING CHANGE - DOMAINS LOST)"
    RISK_COLOR="$RED"
    SUMMARY_TITLE="🚨 SAN CONTRACTION / REMOVAL ($REMOVED_COUNT domains removed)"

# 6. Mixed SAN Overhaul
else
    SCENARIO="SAN_OVERHAUL"
    RISK_LEVEL="HIGH (COMPLEX DRIFT)"
    RISK_COLOR="$YELLOW"
    SUMMARY_TITLE="🔀 SAN OVERHAUL / PARTIAL DRIFT (+$ADDED_COUNT added, -$REMOVED_COUNT removed)"
fi

# Print Primary Verdict Header
echo -e "  ${BOLD}Verdict Category:${RESET}  ${BOLD}${SUMMARY_TITLE}${RESET}"
echo -e "  ${BOLD}Deployment Risk:${RESET}   ${RISK_COLOR}${BOLD}[ ${RISK_LEVEL} ]${RESET}\n"

# Print Key Analytical Insights
echo -e "  ${BOLD}${WHITE}🔍 Key Lifecycle Insights:${RESET}"

# 1. SAN Insight
if [[ "$SAN_DIFF_COUNT" -eq 0 ]]; then
    echo -e "    • ${GREEN}SAN Continuity:${RESET}  100% match. All ${C1_SAN_COUNT} domain(s) fully preserved in side-by-side alignment."
elif [[ "$REMOVED_COUNT" -eq 0 ]]; then
    echo -e "    • ${GREEN}SAN Continuity:${RESET}  Backwards-compatible. All ${COMMON_COUNT} existing domains preserved + ${ADDED_COUNT} added."
elif [[ "$COMMON_COUNT" -eq 0 ]]; then
    echo -e "    • ${RED}SAN Continuity:${RESET}  0% overlap. No shared Subject Alternative Names."
else
    echo -e "    • ${YELLOW}SAN Continuity:${RESET}  Partial overlap (${COMMON_COUNT} preserved, ${ADDED_COUNT} new, ${RED}${REMOVED_COUNT} dropped${RESET})."
fi

# 2. Validity / Expiry Insight
if [[ "$SAME_DATE" == "true" ]]; then
    echo -e "    • ${DIM}Validity Period:${RESET} Both certificates share the exact same expiry (${c2_not_after})."
elif [[ "$NEWER" == "true" ]]; then
    echo -e "    • ${GREEN}Validity Delta:${RESET}  Cert [2] extends coverage by ${BOLD}+${DELTA_DAYS} days${RESET} (Expires: ${c2_not_after}, ${REM2} days remaining)."
elif [[ "$OLDER" == "true" ]]; then
    echo -e "    • ${RED}Validity Delta:${RESET}  Cert [2] expires ${BOLD}${DELTA_DAYS#-} days SOONER${RESET} than Cert [1] (Expires: ${c2_not_after})."
fi

# 3. Cryptographic Key Insight
if [[ "$c1_pubkey_modulus" == "$c2_pubkey_modulus" && -n "$c1_pubkey_modulus" ]]; then
    echo -e "    • ${DIM}Private Key Pair:${RESET} Shared (Re-issued with the SAME underlying private key)."
else
    echo -e "    • ${CYAN}Private Key Pair:${RESET} Rotated (Issued with a fresh, distinct cryptographic key pair)."
fi

# 4. Crypto Algorithm Evolution
if [[ "$c1_pubkey_info" != "$c2_pubkey_info" ]]; then
    if [[ "$c1_pubkey_algo" =~ rsa && "$c2_pubkey_algo" =~ (ec|ECDSA) ]]; then
        echo -e "    • ${GREEN}Crypto Modernization:${RESET} Upgraded from RSA ➔ ECDSA (Higher security, faster TLS handshakes)."
    elif [[ "$c1_pubkey_algo" =~ (ec|ECDSA) && "$c2_pubkey_algo" =~ rsa ]]; then
        echo -e "    • ${YELLOW}Crypto Migration:${RESET} Changed from ECDSA ➔ RSA (Legacy compatibility mode)."
    else
        echo -e "    • ${CYAN}Crypto Migration:${RESET} Key parameters changed (${c1_pubkey_info} ➔ ${c2_pubkey_info})."
    fi
fi

# 5. CA / Issuer Evolution
if [[ "$c1_issuer" != "$c2_issuer" ]]; then
    echo -e "    • ${CYAN}CA Migration:${RESET}     Issued by different Certificate Authority:"
    echo -e "                       From: ${c1_issuer_cn:-$c1_issuer}"
    echo -e "                       To:   ${c2_issuer_cn:-$c2_issuer}"
fi

# Print Specific Risk & Action Recommendations
echo -e "\n  ${BOLD}${WHITE}📋 Actionable Recommendation:${RESET}"
case "$SCENARIO" in
    "IDENTICAL")
        echo -e "    ${GREEN}✔ No action needed.${RESET} Both files/endpoints present the exact same certificate."
        ;;
    "RENEWAL_SEAMLESS")
        echo -e "    ${GREEN}✔ Safe for immediate deployment.${RESET} Rotate on Load Balancers, Ingress Gateways, and CDNs without traffic risk."
        ;;
    "EXPIRED_REPLACEMENT")
        echo -e "    ${GREEN}✔ Critical renewal.${RESET} Deploy immediately to replace the expired certificate and restore valid HTTPS trust."
        ;;
    "RENEWAL_REGRESSION")
        echo -e "    ${RED}✖ Review required.${RESET} Cert [2] has an earlier expiration date. Verify you are not accidentally deploying an older archive cert."
        ;;
    "SAN_EXPANSION")
        echo -e "    ${GREEN}✔ Safe for existing traffic.${RESET} Verify DNS A/CNAME records point to your load balancer for newly added SANs before routing new traffic."
        ;;
    "SAN_CONTRACTION")
        echo -e "    ${RED}✖ DANGER OF OUTAGE!${RESET} Domain(s) were removed in Cert [2] (see '--' entries in the table above)."
        echo -e "      ${RED}Do NOT deploy if production traffic is still actively hitting these removed hostnames!${RESET}"
        ;;
    "SAN_OVERHAUL")
        echo -e "    ${YELLOW}⚠ Audit traffic routing.${RESET} Ensure removed domains are decommissioned and new domains have active DNS bindings."
        ;;
    "DISJOINT")
        echo -e "    ${RED}✖ Incompatible certificates.${RESET} These certificates belong to completely separate services or domains."
        ;;
esac

echo -e "${CYAN}========================================================================================================${RESET}\n"

if [[ "$SCENARIO" == "IDENTICAL" || "$SCENARIO" == "RENEWAL_SEAMLESS" || "$SCENARIO" == "EXPIRED_REPLACEMENT" || "$SCENARIO" == "SAN_EXPANSION" ]]; then
    exit 0
else
    exit 1
fi
