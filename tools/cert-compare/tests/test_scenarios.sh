#!/usr/bin/env bash
set -e

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating mock certificate test fixtures..."

# 1. Base Key
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key1.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key2.pem"

# Cert 1: Base (api.example.com, www.example.com)
openssl req -new -x509 -key "$DIR/key1.pem" -out "$DIR/base.pem" -days 30 -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com,DNS:api.example.com"

# Cert 2: Seamless Renewal (Same SANs, +90 days)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/renewal.pem" -days 90 -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com,DNS:api.example.com"

# Cert 3: SAN Expansion (+ dev.example.com, staging.example.com)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/expansion.pem" -days 90 -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com,DNS:api.example.com,DNS:dev.example.com,DNS:staging.example.com"

# Cert 4: SAN Contraction (Removed api.example.com - Breaking!)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/contraction.pem" -days 90 -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../cert-compare.sh"

echo -e "\n==================== TEST 1: SEAMLESS RENEWAL ===================="
"$BIN" "$DIR/base.pem" "$DIR/renewal.pem" || true

echo -e "\n==================== TEST 2: SAN EXPANSION ===================="
"$BIN" "$DIR/base.pem" "$DIR/expansion.pem" || true

echo -e "\n==================== TEST 3: SAN CONTRACTION (BREAKING) ===================="
"$BIN" "$DIR/base.pem" "$DIR/contraction.pem" || true
