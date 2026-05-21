#!/bin/bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <TEST_NAME> <COMMON_NAME>

----------------------------------------------------------
TEST_NAME:
    Name of the testcase configuration file.

COMMON_NAME:
    Common Name (CN) of the CA.
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

CERT_PATH=$(find "$LOAP_PKI_PATH/$TEST_NAME" -type d -name "$COMMON_NAME" | head -n 1)
if [ -z "$CERT_PATH" ]; then
  echo "[-] Unable to locate certificate $COMMON_NAME in $TEST_NAME."
  echo "[-] Maybe test or common name is wrong?"
  exit 1
fi

echo "[+] CERT_PATH: $CERT_PATH"
echo "[+] Regenerating CRL..."
openssl ca -config "$CERT_PATH/openssl-ca.cnf" -gencrl -out "$CERT_PATH/crl/latest_crl.pem"