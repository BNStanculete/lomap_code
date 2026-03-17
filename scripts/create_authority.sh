#!/usr/bin/env bash

set -e

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <ROOT_COMMON_NAME> <COMMON_NAME>"
  exit 1
fi

ROOT_DIR="$PWD/data/certificates/$1"
CA_DIR="$ROOT_DIR/newcerts/$2"
KEY_SIZE=2048
DAYS=3650

# Create directory structure
mkdir -p $CA_DIR/{certs,crl,csr,newcerts,private,revokedcerts}

touch $CA_DIR/index.txt
echo 1000 > $CA_DIR/serial
echo 1000 > $CA_DIR/crlnumber

# Generate CA private key
openssl genrsa -out $CA_DIR/private/ca.key.pem $KEY_SIZE

# Generate CSR
openssl req -new \
  -key $CA_DIR/private/ca.key.pem \
  -out $CA_DIR/csr/ca.csr.pem \
  -subj "/C=NL/ST=Overijssel/L=Enschede/O=LocalDev/OU=DevIntermediate/CN=$2"

# Create extension file for intermediate CA
EXT_FILE="$CA_DIR/ca.ext"

cat > $EXT_FILE <<EOF
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# Sign the intermediate CSR with the root CA
openssl x509 -req \
  -in $CA_DIR/csr/ca.csr.pem \
  -CA $ROOT_DIR/certs/ca.cert.pem \
  -CAkey $ROOT_DIR/private/ca.key.pem \
  -CAcreateserial \
  -out $CA_DIR/certs/ca.cert.pem \
  -days $DAYS \
  -sha256 \
  -extfile $EXT_FILE

echo "[ ca ]" > "$CA_DIR/openssl-ca.cnf"
echo "default_ca = CA_default" >> "$CA_DIR/openssl-ca.cnf"
echo "" >> "$CA_DIR/openssl-ca.cnf"
echo "[ CA_default ]" >> "$CA_DIR/openssl-ca.cnf"
echo "dir               = ./data/certificates/$1/newcerts/$2" >> "$CA_DIR/openssl-ca.cnf"
echo "database          = \$dir/index.txt" >> "$CA_DIR/openssl-ca.cnf"
echo "new_certs_dir     = \$dir/newcerts" >> "$CA_DIR/openssl-ca.cnf"
echo "certificate       = \$dir/certs/ca.cert.pem" >> "$CA_DIR/openssl-ca.cnf"
echo "private_key       = \$dir/private/ca.key.pem" >> "$CA_DIR/openssl-ca.cnf"
echo "serial            = \$dir/serial" >> "$CA_DIR/openssl-ca.cnf"
echo "crlnumber         = \$dir/crlnumber" >> "$CA_DIR/openssl-ca.cnf"
echo "crl               = \$dir/crl/ca.crl.pem" >> "$CA_DIR/openssl-ca.cnf"
echo "crl_dir           = \$dir/crl" >> "$CA_DIR/openssl-ca.cnf"
echo "default_crl_days  = 30" >> "$CA_DIR/openssl-ca.cnf"
echo "default_md        = sha256" >> "$CA_DIR/openssl-ca.cnf"
