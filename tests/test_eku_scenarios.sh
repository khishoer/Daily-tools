#!/usr/bin/env bash
set -e

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating EKU test fixtures..."

# 1. Base Key & Renewal Key
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key1.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key2.pem"

# Cert 1: Baseline with serverAuth + clientAuth (mTLS)
openssl req -new -x509 -key "$DIR/key1.pem" -out "$DIR/c1_mtls.pem" -days 30 -subj "/CN=api.internal.net" \
  -addext "subjectAltName=DNS:api.internal.net" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

# Cert 2: Candidate with only serverAuth (Lost clientAuth)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/c2_serveronly.pem" -days 90 -subj "/CN=api.internal.net" \
  -addext "subjectAltName=DNS:api.internal.net" \
  -addext "extendedKeyUsage=serverAuth"

# Cert 3: Candidate missing serverAuth (Only codeSigning - Fatal Web Misconfiguration!)
openssl req -new -x509 -key "$DIR/key2.pem" -out "$DIR/c3_nocertauth.pem" -days 90 -subj "/CN=api.internal.net" \
  -addext "subjectAltName=DNS:api.internal.net" \
  -addext "extendedKeyUsage=codeSigning"

echo -e "\n==================== TEST 1: EKU CONTRACTION (Lost mTLS clientAuth) ===================="
/Users/kishorekumarmurugan/tools/Daily-tools/scripts/san-compare.sh "$DIR/c1_mtls.pem" "$DIR/c2_serveronly.pem" || true

echo -e "\n==================== TEST 2: FATAL EKU MISCONFIGURATION (Missing serverAuth) ===================="
/Users/kishorekumarmurugan/tools/Daily-tools/scripts/san-compare.sh "$DIR/c1_mtls.pem" "$DIR/c3_nocertauth.pem" || true
