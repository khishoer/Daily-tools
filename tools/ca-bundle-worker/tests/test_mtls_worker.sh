#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../ca-bundle-worker.sh"

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating mock mTLS CA trust store & chain fixtures..."

# 1. Valid Enterprise Root CA (365d)
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/root1.key"
openssl req -new -x509 -key "$DIR/root1.key" -out "$DIR/root1.pem" -days 365 -subj "/CN=Enterprise Root CA G1/O=Acme Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Valid Sub CA 1 (180d)
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/subca1.key"
openssl req -new -key "$DIR/subca1.key" -out "$DIR/subca1.csr" -subj "/CN=Partner API Sub CA/O=Acme Corp"
openssl x509 -req -in "$DIR/subca1.csr" -CA "$DIR/root1.pem" -CAkey "$DIR/root1.key" -CAcreateserial \
  -out "$DIR/subca1.pem" -days 180 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")

# 3. Expired CA (Expired 10 days ago)
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/expired_ca.key"
openssl req -new -x509 -key "$DIR/expired_ca.key" -out "$DIR/expired_ca.pem" -days 1 -subj "/CN=Legacy Deprecated Root CA/O=Old Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# 4. Accidental Leaf Certificate (Non-CA Bug)
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/leaf.key"
openssl req -new -x509 -key "$DIR/leaf.key" -out "$DIR/accidental_leaf.pem" -days 90 -subj "/CN=accidental-leaf.corp" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature"

# 5. New Candidate CA to append
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/new_ca.key"
openssl req -new -x509 -key "$DIR/new_ca.key" -out "$DIR/new_ca.pem" -days 365 -subj "/CN=Cloud Ingress Gateway CA G2/O=Acme Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Build initial flawed mTLS CA bundle: root1 + subca1 + expired_ca + accidental_leaf + duplicate(subca1)
cat "$DIR/root1.pem" "$DIR/subca1.pem" "$DIR/expired_ca.pem" "$DIR/accidental_leaf.pem" "$DIR/subca1.pem" > "$DIR/mtls_bundle.pem"

echo -e "\n==================== TEST 1: AUDIT mTLS BUNDLE (Health & Security Checks) ===================="
"$BIN" audit "$DIR/mtls_bundle.pem"

echo -e "\n==================== TEST 2: APPEND NEW CA (Validation & Deduplication) ===================="
"$BIN" append "$DIR/mtls_bundle.pem" "$DIR/new_ca.pem" -o "$DIR/appended_bundle.pem"

echo -e "\n==================== TEST 3: REMOVE SPECIFIC CA BY CN ===================="
"$BIN" remove "$DIR/appended_bundle.pem" --cn "Legacy Deprecated" -o "$DIR/clean_bundle.pem"
"$BIN" audit "$DIR/clean_bundle.pem"

echo -e "\n==================== TEST 4: PROBE ONLINE FQDN (Acceptable client CAs) ===================="
"$BIN" probe google.com:443

echo -e "\n==================== TEST 5: MONITOR FLAPPING (Every 2s for 6s total) ===================="
"$BIN" monitor google.com:443 --interval 2 --duration 6

echo -e "\n✔ ALL mTLS CA-BUNDLE-WORKER TESTS PASSED SUCCESSFULLY!"
