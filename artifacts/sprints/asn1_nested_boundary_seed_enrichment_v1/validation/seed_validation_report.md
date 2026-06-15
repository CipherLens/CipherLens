# Seed Validation Report

- original_seed_available: `false`
- generated_seed_available: `false`
- source_test_vector_candidates_validated: `true`
- validation_result: `generated_seed_parse_error_no_crash` for source-test-vector adaptation candidates only
- crash_observed: `false`

Validated OpenSSL source test vectors:

- `pbmac1_256_256.no-salt.p12`: exit `1`, parse/mac generation error, no crash.
- `pbmac1_256_256.bad-salt-type.p12`: exit `1`, parse/mac generation error, no crash.
- `pbmac1_256_256.bad-salt.p12`: exit `1`, mac verify error, no crash.

These are not original issue reproductions.
