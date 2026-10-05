1. Write the RSA-2048 modular reduction constraints for SQUARING
2. Add the Poseidon sub-trace to CRLUpdate and Authentication
3. Add the the non-serializer constraints to CRLUpdate and Authentication
4. Add non-revocation constraints (if not already there)
5. Resolve bug of missing ATTESTATION in MessageBuilder trace.
6. Investigate why different chain lengths produce the same prover benchmarks / traces / metrics.