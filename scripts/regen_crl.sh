#!/bin/bash

set -e

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <CA_DIR>"
  exit 1
fi

openssl ca -config "$1/openssl-ca.cnf" -gencrl -out "$1/crl/ca.crl.pem"