#!/bin/bash

# Ensure that env is set
source env.sh

# Run the TGS
if [ "$#" -ge 1 ]; then
    python3 generator.py -d
else
    python3 generator.py
fi

# Run the DCS
python3 preprocessor.py

# Run the PKI Verifier
python3 ./verifier/pki_verifier.py

# Run the LOAP Prover & Verifier
python3 ./loap.py