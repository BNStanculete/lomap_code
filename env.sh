#!/bin/bash

# Test Specifications, Reproducibility Artifacts and Metrics Directory
export LOAP_TEST_SPECIFICATION_PATH="./tests"
export LOAP_PKI_PATH="./artifacts/pki"
export LOAP_RESULTS_PATH="./artifacts/results"
export LOAP_INTERFACE_PATH="./interfaces"

# Ephemeral Runtime (safe to delete)
export LOAP_RUNTIME_PATH="/tmp/loap"
export LOAP_PROOFS_PATH="$LOAP_RUNTIME_PATH/proofs"
export LOAP_ETS_PATH="$LOAP_RUNTIME_PATH/ets"
