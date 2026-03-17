#!/bin/bash

set -e

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <CA_DIR> <CERT>"
  exit 1
fi

openssl ca -config "$1/openssl-ca.cnf" -revoke "$1/newcerts/$2/$2.cert.pem"
rm -rf "$1/newcerts/$2"
