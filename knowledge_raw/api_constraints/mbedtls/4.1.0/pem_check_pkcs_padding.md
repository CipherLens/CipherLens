# API Constraints: pem_check_pkcs_padding (mbedTLS 4.1.0 internal)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `pem_check_pkcs_padding`
- Visibility: `static` internal helper
- Implementation file: `tf-psa-crypto/utilities/pem.c`
- Signature:

```c
static int pem_check_pkcs_padding(unsigned char *input,
                                  size_t input_len,
                                  size_t *data_len);
```

## Parameter Semantics

- `input`: decrypted PEM payload buffer, writable because the caller owns the decoded/decrypted temporary buffer.
- `input_len`: number of bytes in `input`.
- `data_len`: output pointer receiving the unpadded payload length.

## Return Value Semantics

- `0`: valid PKCS padding; `*data_len` is updated.
- `MBEDTLS_ERR_PEM_INVALID_DATA`: `input_len < 1`.
- `MBEDTLS_ERR_PEM_PASSWORD_MISMATCH`: padding byte is larger than input length or padding bytes mismatch.

## Ownership and Buffer Constraints

- Does not allocate or free memory.
- Reads `input[input_len - 1]` only after the current-source `input_len < 1` guard.
- The caller (`mbedtls_pem_read_buffer`) frees the decoded buffer on error.

## Harness Generation Notes

- This is an internal helper; public harnesses should normally reach it through `mbedtls_pem_read_buffer()`.
- A minimal white-box harness can expose it only if building against source internals, but adapter YAML should record it as an internal function.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0011`.
- The root migration feature is the missing/added zero-length guard before reading the last padding byte.
- Target APIs should not be reduced to generic PEM parse failure; preserve the short decoded buffer reaching a final-byte padding check.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_pem.data`: malformed encrypted PEM cases exercise this helper through `mbedtls_pem_read_buffer()`.
