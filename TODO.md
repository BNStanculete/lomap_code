- Ensure SHA256 Rust exposes raw constraints
        --> Exposes (function, degrees) list
        --> Due to shape of constraints, we need to create custom functions or something
        --> leave for after environment rework & f-128 porting

- RSA2048 Constraints
- Message Authentication Trace (Combine SHA256 + RSA2048)
- CRL Serializer Trace (*)                              * DEADLINE : 22.05
- CRL Serializer Constraints                            * DEADLINE : 02.06
- Certificate Serializer Trace (*)
- Certificate Serializer Constraints
- LOMAP Authentication Trace (*)
- LOMAP Authentication Constraints (*)

- LOMAP Prover Simulator                                
- LOMAP Verifier Simulator                              * Vineri - 22

** TES is ultimately just a shell script, coordinating the various sub-systems
** Next in line is F128 and then the splitting between what prover needs vs. what verifier needs
** Then we move to CRL trace.

- Port to 128-bit field                                 * Joi - 21


-----------------
Fix sliding windong.
        -> make it slide left -> right in BLOCK_ACCUMULATORS
        -> verify that the hash is correct at the end
        -> add the PKCS#1.5 encoding
        -> verify signature