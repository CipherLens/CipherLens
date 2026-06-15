# PKCS12 PBMAC1 Null Salt Reconstruction Plan

## Inference

`pbmac1_null_salt.p12` suggests a PKCS#12 object using PBMAC1 where PBKDF2 salt is absent, NULL, wrong type, or otherwise malformed. Relevant structures are `MACData`, PBMAC1 `AlgorithmIdentifier`, PBKDF2 parameters, and the salt CHOICE/OCTET STRING.

## Local Evidence

OpenSSL 3.5.5 includes related malformed PBMAC1 vectors such as `pbmac1_256_256.no-salt.p12`, `bad-salt-type.p12`, and `bad-salt.p12`. Source code in `p12_mutl.c` validates salt type/nullness in the current version.

## Decision

- reconstruction_feasibility: `feasible_but_high_uncertainty`
- reconstruction_method: `source_test_vector_adaptation`
- risk_of_false_reproduction: `high`
- generated_seed_status: `not_generated`

No equivalent seed was generated because DER patching without the original sanitizer stack/input would carry high false reproduction risk.
