# Unit Test / Example Evidence: MBEDTLS-POC-0020 RSA DER Trailing Garbage

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

status: found_in_local_tests

## APIs Covered

- `mbedtls_pk_parse_key`
- internal `mbedtls_rsa_parse_key`
- internal `mbedtls_rsa_parse_pubkey`

## Evidence

- `tf-psa-crypto/tests/suites/test_suite_rsa.function`
  - Defines `rsa_parse_pkcs1_key`.
  - Calls:

```c
TEST_EQUAL(mbedtls_rsa_parse_pubkey(&rsa_ctx, input->x, input->len), exp_ret_val);
TEST_EQUAL(mbedtls_rsa_parse_key(&rsa_ctx, input->x, input->len), exp_ret_val);
```

- `tf-psa-crypto/tests/suites/test_suite_rsa.data`
  - Contains private RSA parser cases with trailing bytes inside the top-level sequence:
    - expected `MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`
  - Contains private RSA parser cases with bytes outside the top-level sequence:
    - expected `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`
  - Contains public RSA parser cases with trailing bytes inside and outside the top-level sequence:
    - expected `MBEDTLS_ERR_ASN1_LENGTH_MISMATCH` or `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`.

- `tf-psa-crypto/tests/suites/test_suite_pkparse.function`
  - Direct `mbedtls_pk_parse_key()` coverage for higher-level key parsing.

## Harness Relevance

- Local RSA tests directly exercise the internal APIs used by the PoC and distinguish inside-sequence trailing data from outside-sequence trailing garbage.
- This is strong evidence for `MBEDTLS-POC-0020`.
