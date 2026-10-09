
FRIDAY, 09.10 (2 weeks, 1 day before the deadline)
X 1. Uniformize the NUM_ROWS increment accross all trace builders
X 2. Fix the padding bug of the InitialAuthentication trace builder
X 3. Add the W_SELECTORS and update the SHA-256 and RSA-2048 control codes according to MessageAuthentication
4. Add the the non-serializer constraints to CRLUpdate and Authentication

REMAINING THINGS TO DO:
1. Add non-revocation constraints (if not already there)
2. Resolve bug of missing ATTESTATION in RSA-2048 sub trace.
3. Implement a proper message parsing
4. Add assertions based on the parsed messages for verification & proving
5. Revisit the Control Codes and implement already the split accross TraceSelector and TraceSpecific control codes.
6. Add the Poseidon sub-trace to CRLUpdate and Authentication

IF ALL OF THESE ARE DONE, THE ONLY THING LEFT IS THE REWORK.