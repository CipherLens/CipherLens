# Unit Test / Example Evidence: MBEDTLS-POC-0028 PSA AEAD Invalid Tag Length

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

status: found_in_local_tests

## APIs Covered

- `psa_aead_decrypt_setup`
- internal `psa_aead_setup`
- internal `psa_validate_tag_length`

## Evidence

- `tf-psa-crypto/tests/suites/test_suite_psa_crypto.function`
  - Multiple direct calls to `psa_aead_decrypt_setup()`.
  - `aead_multipart_setup` imports a key, calls encrypt setup, aborts, then calls decrypt setup and checks the expected setup status.

- `tf-psa-crypto/tests/suites/test_suite_psa_crypto_op_fail.generated.data`
  - Contains generated invalid-argument cases for `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM,63)` with expected `PSA_ERROR_INVALID_ARGUMENT`.
  - These cases prove local tests cover invalid shortened CCM tag length setup rejection, although not tag length `3` specifically in the searched lines.

- `tf-psa-crypto/tests/suites/test_suite_psa_crypto_driver_wrappers.function`
  - Exercises decrypt setup status propagation through driver wrapper hooks.

## Harness Relevance

- Local tests cover the same setup-time invalid shortened tag-length validation class used by the PoC.
- The exact PoC value `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3)` should still be kept in generated migration harnesses.
