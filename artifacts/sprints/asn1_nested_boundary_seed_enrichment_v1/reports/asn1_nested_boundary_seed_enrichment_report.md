# ASN.1 Nested Boundary Seed Enrichment Report

## Summary

- Original `/tmp/pbmac1_null_salt.p12` found: `false`
- Only placeholder input: `true`
- Sanitizer log found: `false`
- Equivalent seed generated: `false`
- Crash reproduced: `false`
- Confirmed vulnerability: `false`

## Reconstruction

The filename suggests PBMAC1/PBKDF2 salt is absent, NULL, wrong type, or malformed in PKCS12 MACData / PBMAC1 AlgorithmIdentifier parameters. OpenSSL 3.5.5 includes related malformed PBMAC1 test vectors, but they are not the original seed.

## Validation

OpenSSL source test vectors `pbmac1_256_256.no-salt.p12`, `bad-salt-type.p12`, and `bad-salt.p12` were validated with local OpenSSL 3.5.5. They returned exit `1` with parse/mac-generation errors and no crash.

## Classification

`real_seed_not_found`, `equivalent_seed_not_generated`, `generated_seed_parse_error_no_crash`, `blocked_seed_missing`, `blocked_high_uncertainty_reconstruction`, `not_enough_for_claim`

## Next

`framework_automation_schema_unification_v1`
