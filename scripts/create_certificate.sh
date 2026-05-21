#!/bin/bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <TEST_NAME> <CA_NAME> <COMMON_NAME> <SIGNATURE> [IS_CA]

----------------------------------------------------------
TEST_NAME:
    Name of the testcase configuration file.

CA_NAME:
    Name of the issuing CA.
    If empty, the resulting certificate will be a root CA.

COMMON_NAME:
    Common Name (CN) of the certificate being issued.

SIGNATURE:
    Signature algorithm identifier.
    Supported values:
      - RSA-2048
      - ECDSA-P256

IS_CA:
    Optional flag indicating whether this certificate is a CA.
    Accepted values:
      - true
      - false
----------------------------------------------------------
EOF
}

# Require at least 4 args and allow optional 5th
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  usage
  exit 1
fi

TEST_NAME="$1"
CA_NAME="$2"
COMMON_NAME="$3"
SIGNATURE="$4"
IS_CA="${5:-false}"

if [ -z "$CA_NAME" ]; then
    IS_CA="true"
fi

# Validate signature type
case "$SIGNATURE" in
  RSA-2048|ECDSA-P256)
    ;;
  *)
    echo "[-] Error: Unsupported SIGNATURE '$SIGNATURE'"
    usage
    exit 1
    ;;
esac

# Validate IS_CA
case "$IS_CA" in
  true|false)
    ;;
  *)
    echo "[-] Error: IS_CA must be 'true' or 'false'"
    usage
    exit 1
    ;;
esac

echo "[+] TEST_NAME  : $TEST_NAME"
echo "[+] CA_NAME    : $CA_NAME"
echo "[+] COMMON_NAME: $COMMON_NAME"
echo "[+] SIGNATURE  : $SIGNATURE"
echo "[+] IS_CA      : $IS_CA"

if [ ! -e "$LOAP_PKI_PATH/$TEST_NAME" ]; then
    echo "[+] Detected first sample. Creating test directory..."
    mkdir -p "$LOAP_PKI_PATH/$TEST_NAME"
fi


# Locate Relevant CA
if [ -z "$CA_NAME" ]; then
    CA_PATH=""
    CERT_DIR="$LOAP_PKI_PATH/$TEST_NAME/$COMMON_NAME"

    echo "[+] CA_PATH: Not Applicable (RootCA)"
else
    CA_PATH=$(find "$LOAP_PKI_PATH/$TEST_NAME" -type d -name "$CA_NAME" | head -n 1)
    CERT_DIR="$CA_PATH/newcerts/$COMMON_NAME"
    if [ -z "$CA_PATH" ]; then
        echo "[-] Unable to locate CA $CA_NAME in $TEST_NAME."
        echo "[-] Maybe test or CA name is wrong?"
        exit 1
    fi

    echo "[+] CA_PATH: $CA_PATH"
fi
echo "[+] Certificate Directory: $CERT_DIR"
mkdir -p "$CERT_DIR"
mkdir -p "$CERT_DIR/private"

# Generate the private key
case "$SIGNATURE" in
  RSA-2048)
    echo "[+] Generating RSA-2048 key pair..."
    openssl genrsa -out "$CERT_DIR/private/private_key.pem" 2048
  ;;
  ECDSA-P256)
    echo "[+] Generating ECDSA P-256 key pair..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/private/private_key.pem"
  ;;
esac

# Build the directory & file structure.
if [ "$IS_CA" = "true" ]; then
    echo "[+] Creating CA Directories..."
    mkdir -p "$CERT_DIR"/{crl,csr,newcerts,revokedcerts}

    echo "[+] Creating CA Databases..."
    touch "$CERT_DIR/index.txt"
    echo 1000 > "$CERT_DIR/serial"
    echo 1000 > "$CERT_DIR/crlnumber"

    echo "[+] Creating CA Extensions..."
    echo "[v3_extensions]" > "$CERT_DIR/extensions.txt"
    echo "basicConstraints = critical, CA:TRUE" >> "$CERT_DIR/extensions.txt"
    echo "keyUsage = critical, digitalSignature, cRLSign, keyCertSign" >> "$CERT_DIR/extensions.txt"
    echo "subjectKeyIdentifier = hash" >> "$CERT_DIR/extensions.txt"
    echo "authorityKeyIdentifier = keyid:always,issuer" >> "$CERT_DIR/extensions.txt"

    echo "[+] Creating CA Configuration file..."
    echo "[ ca ]" > "$CERT_DIR/openssl-ca.cnf"
    echo "default_ca = CA_default" >> "$CERT_DIR/openssl-ca.cnf"
    echo "" >> "$CERT_DIR/openssl-ca.cnf"
    echo "[ CA_default ]" >> "$CERT_DIR/openssl-ca.cnf"
    echo "dir               = $CERT_DIR" >> "$CERT_DIR/openssl-ca.cnf"
    echo "database          = \$dir/index.txt" >> "$CERT_DIR/openssl-ca.cnf"
    echo "new_certs_dir     = \$dir/newcerts" >> "$CERT_DIR/openssl-ca.cnf"
    echo "certificate       = \$dir/certificate.pem" >> "$CERT_DIR/openssl-ca.cnf"
    echo "private_key       = \$dir/private/private_key.pem" >> "$CERT_DIR/openssl-ca.cnf"
    echo "serial            = \$dir/serial" >> "$CERT_DIR/openssl-ca.cnf"
    echo "crlnumber         = \$dir/crlnumber" >> "$CERT_DIR/openssl-ca.cnf"
    echo "crl               = \$dir/crl/latest_crl.pem" >> "$CERT_DIR/openssl-ca.cnf"
    echo "crl_dir           = \$dir/crl" >> "$CERT_DIR/openssl-ca.cnf"
    echo "default_crl_days  = 30" >> "$CERT_DIR/openssl-ca.cnf"
    echo "default_md        = sha256" >> "$CERT_DIR/openssl-ca.cnf"
    echo "default_days      = 365" >> "$CERT_DIR/openssl-ca.cnf"
    echo "policy            = policy_loose" >> "$CERT_DIR/openssl-ca.cnf"
    echo "unique_subject    = no" >> "$CERT_DIR/openssl-ca.cnf"
    echo "" >> "$CERT_DIR/openssl-ca.cnf"
    echo "[ policy_loose ]" >> "$CERT_DIR/openssl-ca.cnf"
    echo "commonName = supplied" >> "$CERT_DIR/openssl-ca.cnf"

    echo "[+] Generating Dummy CSR for issuing CA..."
    openssl req -new \
        -key "$CERT_DIR/private/private_key.pem" \
        -out "$CERT_DIR/csr/Dummy.csr.pem" \
        -subj "/C=NL/ST=Overijssel/L=Enschede/O=LOAP/OU=LOAPIntermediate/CN=Dummy"
else
    echo "[+] Creating Leaf Extensions..."
    echo "[v3_extensions]" > "$CERT_DIR/extensions.txt"
    echo "basicConstraints = CA:FALSE" >> "$CERT_DIR/extensions.txt"
    echo "keyUsage = digitalSignature,keyEncipherment" >> "$CERT_DIR/extensions.txt"
    echo "extendedKeyUsage = serverAuth,clientAuth" >> "$CERT_DIR/extensions.txt"
fi

# If not a root CA, then generate the corresponding CSR
if [ -n "$CA_PATH" ]; then
    echo "[+] Generating CSR for issuing CA..."
    openssl req -new \
        -key "$CERT_DIR/private/private_key.pem" \
        -out "$CA_PATH/csr/$COMMON_NAME.csr.pem" \
        -subj "/C=NL/ST=Overijssel/L=Enschede/O=LOAP/OU=LOAPIntermediate/CN=$COMMON_NAME"

    echo "[+] Signing CSR with issuing CA..."
    openssl ca -config "$CA_PATH/openssl-ca.cnf" \
        -in "$CA_PATH/csr/$COMMON_NAME.csr.pem" \
        -out "$CERT_DIR/certificate.pem" \
        -batch \
        -extfile "$CERT_DIR/extensions.txt" \
        -extensions v3_extensions
else
    echo "[+] Generating root certificate..."
    openssl req -new \
        -key "$CERT_DIR/private/private_key.pem" \
        -out "$CERT_DIR/csr/$COMMON_NAME.csr.pem" \
        -subj "/C=NL/ST=Overijssel/L=Enschede/O=LOAP/OU=LOAPIntermediate/CN=$COMMON_NAME"

    openssl x509 -req \
        -in "$CERT_DIR/csr/$COMMON_NAME.csr.pem" \
        -signkey "$CERT_DIR/private/private_key.pem" \
        -days 3650 \
        -sha256 \
        -extfile "$CERT_DIR/extensions.txt" \
        -extensions v3_extensions \
        -out "$CERT_DIR/certificate.pem"
fi
