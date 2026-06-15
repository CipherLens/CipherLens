# issue_30581 Artifact Summary

- artifact_found: `true`
- metadata_found: `true`
- original_input_path_mentioned: `true`
- original_input_filename: `pbmac1_null_salt.p12`
- bundled_input_files: `['datasets/openssl/poc_artifacts/issue_30581/inputs/test.p12']`
- bundled_sanitizer_log: `false`
- bundled_poc_code: `true`
- placeholder_confirmed: `true`

## Reconstruction Hints

- The filename suggests PBMAC1/PBKDF2 salt is missing, NULL, or malformed.
- OpenSSL 3.5.5 includes PBMAC1 malformed salt vectors in `test/recipes/80-test_pkcs12_data/`.
- Current `crypto/pkcs12/p12_mutl.c` validates PBKDF2 salt type/nullness before use.
