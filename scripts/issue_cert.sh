#!/usr/bin/env bash

set -e

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <CA_DIR> <COMMON_NAME>"
  exit 1
fi

CA_DIR="$1"
CN="$2"

CERT_DIR="$CA_DIR/newcerts/$CN"

mkdir -p "$CERT_DIR"

echo "Using CA directory: $CA_DIR"
echo "Generating certificate for: $CN"

# Generate private key
openssl genrsa -out "$CERT_DIR/$CN.key.pem" 2048

# Create CSR
openssl req -new \
  -key "$CERT_DIR/$CN.key.pem" \
  -out "$CERT_DIR/$CN.csr.pem" \
  -subj "/CN=$CN"

# Sign certificate with CA
openssl x509 -req \
  -in "$CERT_DIR/$CN.csr.pem" \
  -CA "$CA_DIR/certs/ca.cert.pem" \
  -CAkey "$CA_DIR/private/ca.key.pem" \
  -CAcreateserial \
  -out "$CERT_DIR/$CN.cert.pem" \
  -days 365 \
  -sha256

echo ""
echo "Certificate created:"
echo "Key:  $CERT_DIR/$CN.key.pem"
echo "Cert: $CERT_DIR/$CN.cert.pem"