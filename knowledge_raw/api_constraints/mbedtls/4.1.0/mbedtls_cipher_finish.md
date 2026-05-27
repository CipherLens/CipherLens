# API Constraints: mbedtls_cipher_finish (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_cipher_finish`
- Source file: `tf-psa-crypto/drivers/builtin/src/cipher.c`
- Declaration: `tf-psa-crypto/drivers/builtin/include/mbedtls/private/cipher.h`
- Signature:

```c
int mbedtls_cipher_finish(mbedtls_cipher_context_t *ctx,
                          unsigned char *output, size_t *olen);
```

## Parameter Semantics

- `ctx`: initialized generic cipher context bound to a key and operation.
- `output`: caller-provided writable output buffer of at least one block for block modes.
- `olen`: non-NULL output length pointer.

## Return Value Semantics

- `0`: success.
- `MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA`: parameter or context validation failure.
- `MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED`: decrypt finalization expected a full block.
- `MBEDTLS_ERR_CIPHER_INVALID_PADDING`: invalid padding while decrypting.
- Other cipher-specific negative errors can occur.

## Ownership and Buffer Constraints

- The output buffer is caller-owned and written by the library.
- The API exposes caller-visible output length through `olen`.
- In current source, `mbedtls_cipher_finish()` calls `mbedtls_cipher_finish_padded()` and maps `invalid_padding` to `MBEDTLS_ERR_CIPHER_INVALID_PADDING`.

## Harness Generation Notes

- Set up cipher info, key, IV, operation, padding mode, and call update before finish.
- For padded CBC decryption, output length on invalid-padding paths is important.
- Good oracles: return code, `*olen`, output canary, and sanitizer result.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0004`.
- The migration-relevant path is finalization with PKCS padding and caller-visible output length on error.
- Target APIs should preserve finalization output pointer and length pointer behavior.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_cipher.function`: many direct calls, including invalid context, CBC update/final, padding finalization, and expected finish results.
- `tf-psa-crypto/docs/psa-transition.md`: documents update/finish usage flow.
