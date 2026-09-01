#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../ca-bundle-worker.sh"

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

echo "Generating unified test fixtures..."

# Root CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/root.key"
openssl req -new -x509 -key "$DIR/root.key" -out "$DIR/root.pem" -days 365 -subj "/CN=Enterprise Root CA G1/O=Acme Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Sub CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/subca.key"
openssl req -new -key "$DIR/subca.key" -out "$DIR/subca.csr" -subj "/CN=Enterprise Sub CA/O=Acme Corp"
openssl x509 -req -in "$DIR/subca.csr" -CA "$DIR/root.pem" -CAkey "$DIR/root.key" -CAcreateserial \
  -out "$DIR/subca.pem" -days 180 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")

# Leaf Cert
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/leaf.key"
openssl req -new -key "$DIR/leaf.key" -out "$DIR/leaf.csr" -subj "/CN=api.acme.corp"
openssl x509 -req -in "$DIR/leaf.csr" -CA "$DIR/subca.pem" -CAkey "$DIR/subca.key" -CAcreateserial \
  -out "$DIR/leaf.pem" -days 90 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:api.acme.corp\n")

# Expired CA
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/expired.key"
openssl req -new -x509 -key "$DIR/expired.key" -out "$DIR/expired.pem" -days 1 -subj "/CN=Legacy Deprecated Root CA/O=Old Corp" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Build Bundle
cat "$DIR/root.pem" "$DIR/subca.pem" "$DIR/expired.pem" "$DIR/root.pem" > "$DIR/bundle.pem"

echo -e "\n=== 1. AUDIT ==="
"$BIN" audit "$DIR/bundle.pem"

echo -e "\n=== 2. REMOVE BY CN ==="
"$BIN" remove "$DIR/bundle.pem" --cn "Legacy Deprecated" -o "$DIR/pruned.pem"

echo -e "\n=== 3. ORDER CHAIN ==="
cat "$DIR/leaf.pem" "$DIR/root.pem" "$DIR/subca.pem" > "$DIR/unordered.pem"
"$BIN" order-chain "$DIR/unordered.pem" -o "$DIR/ordered.pem"

echo -e "\n=== 4. DIFF ==="
"$BIN" diff "$DIR/bundle.pem" "$DIR/pruned.pem"

echo -e "\n=== 5. FIND ==="
"$BIN" find "$DIR/bundle.pem" "Acme"

echo -e "\n=== 6. SPLIT ==="
"$BIN" split "$DIR/pruned.pem" "$DIR/extracted/"

echo -e "\n=== 7. MERGE ==="
"$BIN" merge -o "$DIR/merged.pem" "$DIR/extracted/"

echo -e "\n=== 8. PROBE & MONITOR ==="
"$BIN" probe google.com:443
"$BIN" monitor google.com:443 --interval 1 --duration 2

echo -e "\n✔ ALL UNIFIED CA-BUNDLE-WORKER FEATURES PASSED!"
