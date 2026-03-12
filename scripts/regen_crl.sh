#!/bin/bash

set -e

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <CA_DIR>"
  exit 1
fi

openssl ca -config "$PWD/data/certificates/$1/openssl-ca.cnf" -gencrl -out "$PWD/data/certificates/$1/crl/ca.crl.pem"