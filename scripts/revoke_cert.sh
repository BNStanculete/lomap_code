#!/bin/bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <TEST_NAME> <COMMON_NAME>

----------------------------------------------------------
TEST_NAME:
    Name of the testcase configuration file.

COMMON_NAME:
    Common Name (CN) of the CA
----------------------------------------------------------
EOF
}

# Require at least 4 args and allow optional 5th
if [ "$#" -lt 2 ] || [ "$#" -gt 2 ]; then
  usage
  exit 1
fi

TEST_NAME="$1"
COMMON_NAME="$2"

echo "[+] TEST_NAME  : $TEST_NAME"
echo "[+] COMMON_NAME: $COMMON_NAME"

# Find certificate path
CERT_PATH=$(find "$LOAP_PKI_PATH/$TEST_NAME" -type d -name "$COMMON_NAME" | head -n 1)
if [ -z "$CERT_PATH" ]; then
  echo "[-] Unable to locate CA $COMMON_NAME in $TEST_NAME."
  echo "[-] Maybe test or common name is wrong?"
  exit 1
fi
echo "[+] CERT_PATH: $CERT_PATH"

# Revoke certificate
echo "[+] Revoking certificate..."
openssl ca -config "$CERT_PATH/openssl-ca.cnf" \
    -in "$CERT_PATH/csr/Dummy.csr.pem" \
    -out "$CERT_PATH/revokedcerts/certificate.pem" \
    -batch

openssl ca -config "$CERT_PATH/openssl-ca.cnf" -revoke "$CERT_PATH/revokedcerts/certificate.pem"
