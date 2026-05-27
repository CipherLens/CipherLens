# Unit Test / Example Evidence: MBEDTLS-POC-0011 PEM Underflow

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

status: found_in_local_tests

## APIs Covered

- `mbedtls_pem_read_buffer`
- internal `pem_check_pkcs_padding` through encrypted PEM parsing

## Evidence

- `tf-psa-crypto/tests/suites/test_suite_pem.function`
  - Defines a direct test function named `mbedtls_pem_read_buffer`.
  - Calls:

```c
ret = mbedtls_pem_read_buffer(&ctx, header, footer, (unsigned char *) data,
                              (unsigned char *) pwd, pwd_len, &use_len);
```

- `tf-psa-crypto/tests/suites/test_suite_pem.data`
  - Contains malformed encrypted AES-128-CBC PEM cases:
    - empty content -> `MBEDTLS_ERR_PEM_BAD_INPUT_DATA`
    - malformed AES-128-CBC 3-byte ciphertext -> `MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH`
    - malformed AES-128-CBC 1-byte ciphertext -> `MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH`
    - empty ciphertext -> `MBEDTLS_ERR_PEM_BAD_INPUT_DATA`
    - base64 with missing equals -> `MBEDTLS_ERR_BASE64_INVALID_CHARACTER`

## Harness Relevance

- Local tests cover malformed encrypted PEM decoding and return-code expectations.
- They do not assert ASAN heap-underflow directly, but they cover the parser route used by the PoC.

## Missing Local Evidence

- No local test was found that explicitly asserts the historical buggy ASAN one-byte heap-buffer-underflow.
