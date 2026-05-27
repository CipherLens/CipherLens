# API Constraints: EVP_DecryptInit_ex (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_DecryptInit_ex`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/evp_enc.c`
- Signature:

```c
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                       const EVP_CIPHER *cipher,
                       ENGINE *impl,
                       const unsigned char *key,
                       const unsigned char *iv);
```

## Semantics

- Initializes or updates an EVP cipher context for decryption.
- Calls `EVP_CipherInit_ex(..., enc = 0)`.
- For AEAD modes, may be called in stages: select cipher, set controls/params, then set key/IV.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on initialization, provider, cipher, key, or parameter failure.

## Ownership and Buffer Constraints

- `ctx` is caller-owned and freed with `EVP_CIPHER_CTX_free()`.
- Key and IV buffers are caller-owned and read by the library.

## Harness Generation Notes

- For GCM/CCM, initialize context, select `EVP_aes_128_gcm()` or `EVP_aes_128_ccm()`, set AEAD controls, then set key/IV.
- Observe return code at setup-time for invalid AEAD tag/IV parameters.

## Vulnerability-Pattern Migration Notes

- Candidate for `MBEDTLS-POC-0028` because it represents AEAD decrypt setup.
- OpenSSL often sets tag length through `EVP_CIPHER_CTX_ctrl()` or params rather than encoding it in the algorithm identifier.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: stepwise cipher initialization and AEAD tests.
- `demos/cipher/aesccm.c`, `demos/cipher/aesgcm.c`: decrypt setup examples.
