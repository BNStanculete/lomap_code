#!/usr/bin/env bash

set -e

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <COMMON_NAME>"
  exit 1
fi

CA_DIR="$PWD/data/certificates/$1"
KEY_SIZE=2048
DAYS=3650

echo "Creating local CA in $CA_DIR"

# Create directory structure
mkdir -p $CA_DIR/{certs,crl,newcerts,private,revokedcerts}

touch $CA_DIR/index.txt
echo 1000 > $CA_DIR/serial
echo 1000 > $CA_DIR/crlnumber

# Generate CA private key
openssl genrsa -out $CA_DIR/private/ca.key.pem $KEY_SIZE

# Generate root certificate
openssl req -x509 -new -nodes \
  -key $CA_DIR/private/ca.key.pem \
  -sha256 \
  -days $DAYS \
  -out $CA_DIR/certs/ca.cert.pem \
  -subj "/C=NL/ST=Overijssel/L=Enschede/O=LocalDev/OU=DevCA/CN=Local Dev Root CA"

echo "[ ca ]" > "$CA_DIR/openssl-ca.cnf"
echo "default_ca = CA_default" >> "$CA_DIR/openssl-ca.cnf"
echo "" >> "$CA_DIR/openssl-ca.cnf"
echo "[ CA_default ]" >> "$CA_DIR/openssl-ca.cnf"
echo "dir               = ./data/certificates/$1" >> "$CA_DIR/openssl-ca.cnf"
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

echo ""
echo "Local CA created!"
echo ""
echo "CA Key:  $CA_DIR/private/ca.key.pem"
echo "CA Cert: $CA_DIR/certs/ca.cert.pem"