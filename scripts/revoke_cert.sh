#!/bin/bash

set -e

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <CA_DIR> <CERT>"
  exit 1
fi

openssl ca -config "$PWD/data/certificates/$1/openssl-ca.cnf" -revoke "$PWD/data/certificates/$1/newcerts/$2/$2.cert.pem"
mv "$PWD/data/certificates/$1/newcerts/$2 "$PWD/data/certificates/$1/revokedcerts"