# API Constraints: EVP_DecryptUpdate (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_DecryptUpdate`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/evp_enc.c`
- Signature:

```c
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx,
                      unsigned char *out,
                      int *outl,
                      const unsigned char *in,
                      int inl);
```

## Semantics

- Processes ciphertext or AEAD AAD/length phases depending on mode and arguments.
- Sets `*outl = 0` at function entry when `outl` is non-NULL.
- For CCM, a call with `out == NULL`, `in == NULL` can set total ciphertext length before AAD/data processing.

## Return Value Semantics

- Returns `1` on successful update.
- Returns `0` on invalid context, wrong operation direction, unsupported update, overlap, or provider failure.

## Ownership and Buffer Constraints

- `out` is caller-owned writable output when non-NULL.
- `outl` must be non-NULL.
- `in` is caller-owned readable input when non-NULL.

## Harness Generation Notes

- For GCM/CCM decrypt, use separate calls for AAD and ciphertext.
- For CCM, final authentication result may be returned by the ciphertext update call rather than `EVP_DecryptFinal_ex()`.

## Vulnerability-Pattern Migration Notes

- Companion API for `MBEDTLS-POC-0028` OpenSSL AEAD migration.
- May be where invalid tag length or authentication failure becomes observable for CCM.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: AEAD update tests.
- `demos/cipher/aesccm.c`, `demos/cipher/aesgcm.c`: decrypt update flows.
