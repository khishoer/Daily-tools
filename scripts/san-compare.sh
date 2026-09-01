#!/usr/bin/env bash
# ==============================================================================
# Script Name: san-compare.sh
# Description: Compares two X.509 leaf certificates parameter-by-parameter and
#              highlights differences with special emphasis on SAN (Subject Alternative Names).
# Author: Daily Tools (https://github.com/khishoer/Daily-tools)
# Requirements: bash, openssl, awk, sed, grep
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
  (Subject, Issuer, Validity, Public Key, Key Usage, Fingerprints) and performs
  a detailed Subject Alternative Name (SAN) delta analysis (Added / Removed / Common).

${BOLD}Arguments:${RESET}
  <CERT1>, <CERT2>     Can be:
                       - Local file path (.pem, .crt, .cer, .der, .p7b)
                       - Remote hostname with port (e.g. "google.com:443" or "https://github.com")

${BOLD}Options:${RESET}
  -s, --san-only       Only compare Subject Alternative Names (SANs)
  -q, --quiet          Quiet mode: suppress diff output, exit 0 if identical, 1 if differences
  -n, --no-color       Disable color output
  -h, --help           Show this help message

${BOLD}Examples:${RESET}
  san-compare.sh cert_v1.pem cert_v2.pem
  san-compare.sh old_cert.crt https://example.com
  san-compare.sh google.com:443 bing.com:443
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
    eval "${prefix}_pubkey_info=\"\${pubkey_algo:-Unknown} (\${pubkey_bits:-N/A})\""

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
echo -e "${BOLD}${CYAN}================================================================================${RESET}"
echo -e "${BOLD}${CYAN}               🔐 X.509 CERTIFICATE & SAN COMPARISON REPORT                    ${RESET}"
echo -e "${BOLD}${CYAN}================================================================================${RESET}"
echo -e "  ${BOLD}Cert [1]:${RESET} ${YELLOW}${TARGET1}${RESET}"
echo -e "  ${BOLD}Cert [2]:${RESET} ${YELLOW}${TARGET2}${RESET}"
echo -e "${CYAN}--------------------------------------------------------------------------------${RESET}"

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
    compare_field "Validity Status [1]" "$c1_status" "$c1_status"
    compare_field "Validity Status [2]" "$c2_status" "$c2_status"
    compare_field "Key Usage" "$c1_key_usage" "$c2_key_usage"
    compare_field "Ext Key Usage (EKU)" "$c1_ext_key_usage" "$c2_ext_key_usage"
    compare_field "Basic Constraints" "$c1_basic_constraints" "$c2_basic_constraints"
    compare_field "OCSP Responder" "$c1_ocsp" "$c2_ocsp"
    compare_field "Subject Key ID (SKI)" "$c1_ski" "$c2_ski"
    compare_field "Authority Key ID (AKI)" "$c1_aki" "$c2_aki"
    compare_field "SHA-256 Fingerprint" "$c1_sha256" "$c2_sha256"
fi

# ------------------------------------------------------------------------------
# SAN Analysis Section
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${MAGENTA}--- [ 2. Subject Alternative Name (SAN) Deep Analysis ] ---${RESET}"
echo -e "  • Total SANs in Cert [1]: ${BOLD}${C1_SAN_COUNT}${RESET}"
echo -e "  • Total SANs in Cert [2]: ${BOLD}${C2_SAN_COUNT}${RESET}"
echo -e "  • Common Matches:         ${GREEN}${BOLD}${COMMON_COUNT}${RESET}"
echo -e "  • Added in Cert [2]:      ${CYAN}${BOLD}${ADDED_COUNT}${RESET}"
echo -e "  • Removed from Cert [1]:  ${RED}${BOLD}${REMOVED_COUNT}${RESET}"
echo ""

if [[ $SAN_DIFF_COUNT -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}✔ SAN Status: EXACT MATCH (${C1_SAN_COUNT} entries identical)${RESET}"
    if [[ "$C1_SAN_COUNT" -gt 0 ]]; then
        echo -e "    ${DIM}Common SANs:${RESET}"
        while IFS= read -r san; do
            [[ -n "$san" ]] && echo -e "      ${GREEN}• $san${RESET}"
        done < "$COMMON_SANS"
    fi
else
    echo -e "  ${RED}${BOLD}✖ SAN Status: DIFFERENCES DETECTED (${SAN_DIFF_COUNT} delta entries)${RESET}\n"

    if [[ $ADDED_COUNT -gt 0 ]]; then
        echo -e "  ${CYAN}${BOLD}➕ Added in Cert [2] (${ADDED_COUNT}):${RESET}"
        while IFS= read -r san; do
            [[ -n "$san" ]] && echo -e "      ${CYAN}+ $san${RESET}"
        done < "$ADDED_SANS"
        echo ""
    fi

    if [[ $REMOVED_COUNT -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}➖ Removed from Cert [1] (${REMOVED_COUNT}):${RESET}"
        while IFS= read -r san; do
            [[ -n "$san" ]] && echo -e "      ${RED}- $san${RESET}"
        done < "$REMOVED_SANS"
        echo ""
    fi

    if [[ $COMMON_COUNT -gt 0 ]]; then
        echo -e "  ${GREEN}${BOLD}✔ Maintained / Common SANs (${COMMON_COUNT}):${RESET}"
        while IFS= read -r san; do
            [[ -n "$san" ]] && echo -e "      ${GREEN}• $san${RESET}"
        done < "$COMMON_SANS"
        echo ""
    fi
fi

# ------------------------------------------------------------------------------
# Final Summary Verdict
# ------------------------------------------------------------------------------
echo -e "${CYAN}================================================================================${RESET}"
if [[ $TOTAL_DIFFS -eq 0 && $SAN_DIFF_COUNT -eq 0 ]]; then
    echo -e "  ${BG_GREEN} VERDICT: CERTIFICATES ARE IDENTICAL ${RESET}"
    echo -e "  ${GREEN}All $TOTAL_CHECKS inspected parameters and all SAN entries matched perfectly.${RESET}"
elif [[ $SAN_DIFF_COUNT -eq 0 && $TOTAL_DIFFS -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠ VERDICT: EQUIVALENT SANS, BUT METADATA DIFFERS (${TOTAL_DIFFS} differences)${RESET}"
    echo -e "  ${YELLOW}SANs are identical, but Serial Number, Expiry, or Key material has changed.${RESET}"
else
    echo -e "  ${BG_RED} VERDICT: DIFFERENCES DETECTED ${RESET}"
    echo -e "  ${RED}Found ${TOTAL_DIFFS} parameter differences and ${SAN_DIFF_COUNT} SAN changes.${RESET}"
fi
echo -e "${CYAN}================================================================================${RESET}\n"

if [[ $TOTAL_DIFFS -gt 0 || $SAN_DIFF_COUNT -gt 0 ]]; then
    exit 1
else
    exit 0
fi
