#!/usr/bin/env bash
set -e

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating mock certificate test fixtures..."

# 1. Base Key & Renewal Key
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key1.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key2.pem"

# Cert 1: Currently Hosted Baseline (30 days validity)
openssl req -new -x509 -key "$DIR/key1.pem" -out "$DIR/hosted_baseline.pem" -days 30 -subj "/CN=prod.example.com" \
  -addext "subjectAltName=DNS:prod.example.com,DNS:api.example.com,DNS:www.example.com"

# Cert 2: Renewal Candidate (90 days validity, + dev.example.com)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/renewal_candidate.pem" -days 90 -subj "/CN=prod.example.com" \
  -addext "subjectAltName=DNS:prod.example.com,DNS:api.example.com,DNS:www.example.com,DNS:dev.example.com"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../cert-compare.sh"

echo -e "\n==================== TEST A: NORMAL ORDER (Baseline first, Candidate second) ===================="
"$BIN" "$DIR/hosted_baseline.pem" "$DIR/renewal_candidate.pem" || true

echo -e "\n==================== TEST B: REVERSE ORDER (Candidate first, Baseline second) ===================="
"$BIN" "$DIR/renewal_candidate.pem" "$DIR/hosted_baseline.pem" || true
