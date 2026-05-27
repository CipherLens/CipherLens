# API Constraints: mbedtls_get_pkcs_padding / get_pkcs_padding (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- Function name in current source: `mbedtls_get_pkcs_padding`
- Historical/internal name in PoC notes: `get_pkcs_padding`
- Source file: `tf-psa-crypto/drivers/builtin/src/cipher.c`
- Testable declaration: `tf-psa-crypto/drivers/builtin/src/cipher_invasive.h`
- Signature:

```c
MBEDTLS_STATIC_TESTABLE int mbedtls_get_pkcs_padding(unsigned char *input,
                                                     size_t input_len,
                                                     size_t *data_len,
                                                     size_t *invalid_padding);
```

## Parameter Semantics

- `input`: decrypted final block. Must be non-NULL.
- `input_len`: block size. Current comment states this must be the cipher block size.
- `data_len`: non-NULL pointer receiving plaintext length after padding removal.
- `invalid_padding`: pointer receiving a mask-like invalid-padding indicator.

## Return Value Semantics

- `0`: completed padding check. Invalid padding is represented through `*invalid_padding`.
- `MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA`: invalid NULL input or `data_len`.

## Ownership and Buffer Constraints

- The function reads and may inspect the caller-provided final block.
- It writes only scalar output values through `data_len` and `invalid_padding`.
- Current source sets `*data_len` to `0` when padding is invalid.

## Harness Generation Notes

- Direct unit tests can include `cipher_invasive.h` or use generated test framework access.
- For public API harnesses, prefer reaching this function through `mbedtls_cipher_finish()`.
- Mutation point for `MBEDTLS-POC-0004`: reject or mask `padding_len == 0 || padding_len > input_len` before using `input_len - padding_len` as an output length.

## Vulnerability-Pattern Migration Notes

- Relevant to invalid PKCS padding output-length underflow.
- Target migration should preserve last-byte-derived padding length, block-size boundary, and caller-visible output length after finalization.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_cipher.function`: direct test wrapper `get_pkcs_padding` around lines 1573 and 1580.
- `tf-psa-crypto/tests/suites/test_suite_cipher.constant_time.data`: direct cases for valid and invalid padding, including final byte `00` and `11`.
