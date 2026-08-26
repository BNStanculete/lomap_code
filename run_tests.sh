#!/bin/bash

# Ensure that env is set
source env.sh

# Run the TGS
if [ ! -e "$(pwd)/artifacts/pki/.generated" ]; then
    if [ "$#" -ge 1 ]; then
        python3 generator.py -d
        touch "$(pwd)/artifacts/pki/.generated"
    else
        python3 generator.py
        touch "$(pwd)/artifacts/pki/.generated"
    fi
fi

if [ ! -e "$(pwd)/checkpoint_latest.py" ]; then
    # Run the DCS
    python3 preprocessor.py

    # Run the PKI Verifier
    python3 ./verifier/pki_verifier.py
fi

# Run the LOAP Prover & Verifier
python3 ./loap.py