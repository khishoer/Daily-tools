#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../ca-bundle-worker.sh"

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating mock CA trust store & chain fixtures..."

# 1. Root CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/root.key"
openssl req -new -x509 -key "$DIR/root.key" -out "$DIR/root.pem" -days 365 -subj "/CN=Enterprise Root CA G1/O=Acme Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/intermediate.key"
openssl req -new -key "$DIR/intermediate.key" -out "$DIR/intermediate.csr" -subj "/CN=Enterprise Sub CA 1/O=Acme Corp"
openssl x509 -req -in "$DIR/intermediate.csr" -CA "$DIR/root.pem" -CAkey "$DIR/root.key" -CAcreateserial \
  -out "$DIR/intermediate.pem" -days 180 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")

# 3. Leaf Certificate
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/leaf.key"
openssl req -new -key "$DIR/leaf.key" -out "$DIR/leaf.csr" -subj "/CN=api.acme.corp"
openssl x509 -req -in "$DIR/leaf.csr" -CA "$DIR/intermediate.pem" -CAkey "$DIR/intermediate.key" -CAcreateserial \
  -out "$DIR/leaf.pem" -days 90 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:api.acme.corp,DNS:www.acme.corp\n")

# Create multi-cert CA bundle (with a duplicate entry to test deduplication)
cat "$DIR/root.pem" "$DIR/intermediate.pem" "$DIR/leaf.pem" "$DIR/intermediate.pem" > "$DIR/test_bundle.pem"

# Create unordered chain (Leaf + Root + Intermediate out of order)
cat "$DIR/leaf.pem" "$DIR/root.pem" "$DIR/intermediate.pem" > "$DIR/unordered_chain.pem"

echo -e "\n==================== TEST 1: INSPECT BUNDLE ===================="
"$BIN" inspect "$DIR/test_bundle.pem"

echo -e "\n==================== TEST 2: SPLIT BUNDLE ===================="
"$BIN" split "$DIR/test_bundle.pem" "$DIR/extracted/"
ls -la "$DIR/extracted/"

echo -e "\n==================== TEST 3: MERGE & DEDUPLICATE ===================="
"$BIN" merge -o "$DIR/deduped_bundle.pem" "$DIR/extracted/"
"$BIN" inspect "$DIR/deduped_bundle.pem"

echo -e "\n==================== TEST 4: ORDER CHAIN (Hierarchical Fix) ===================="
"$BIN" order-chain "$DIR/unordered_chain.pem" -o "$DIR/ordered_chain.pem"

echo -e "\n==================== TEST 5: DIFF BUNDLES ===================="
cat "$DIR/root.pem" > "$DIR/bundle_v1.pem"
cat "$DIR/root.pem" "$DIR/intermediate.pem" > "$DIR/bundle_v2.pem"
"$BIN" diff "$DIR/bundle_v1.pem" "$DIR/bundle_v2.pem"

echo -e "\n==================== TEST 6: FIND IN BUNDLE ===================="
"$BIN" find "$DIR/test_bundle.pem" "Root"

echo -e "\n==================== TEST 7: FETCH LIVE CHAIN ===================="
"$BIN" fetch google.com:443 -o "$DIR/google_chain.pem"
"$BIN" inspect "$DIR/google_chain.pem"

echo -e "\n✔ ALL CA-BUNDLE-WORKER TESTS PASSED SUCCESSFULLY!"
