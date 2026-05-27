# API Constraints: EVP_CIPHER_CTX_ctrl (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_CIPHER_CTX_ctrl`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/evp_enc.c`
- Signature:

```c
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx,
                        int type,
                        int arg,
                        void *ptr);
```

## Semantics

- Generic control interface for cipher context options.
- AEAD controls include `EVP_CTRL_AEAD_SET_TAG`, `EVP_CTRL_AEAD_GET_TAG`, and GCM IV length controls.
- Provider-backed ciphers translate controls to `OSSL_PARAM` where possible.

## Return Value Semantics

- Returns positive/success value for supported controls.
- Returns `0` or unsupported code on invalid context, unsupported control, or invalid parameter.

## Ownership and Buffer Constraints

- `ctx` is caller-owned.
- `ptr` semantics depend on control type; for AEAD set tag it points to caller-provided tag bytes.
- No ownership of `ptr` is transferred.

## Harness Generation Notes

- For `MBEDTLS-POC-0028`, use this API to set AEAD tag length/value in OpenSSL-style GCM/CCM decrypt setup.
- Invalid tag length behavior may be observed here or during later decrypt/final calls depending on cipher/mode.

## Vulnerability-Pattern Migration Notes

- Important OpenSSL companion API for AEAD tag-length migration.
- Unlike PSA, tag length is not encoded in the algorithm macro; adapter must map shortened-tag semantics to ctrl/params.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: `EVP_CTRL_AEAD_SET_TAG`, `EVP_CTRL_AEAD_GET_TAG`, and `EVP_CTRL_GCM_SET_IVLEN`.
- `demos/cipher/aesccm.c`, `demos/cipher/aesgcm.c`: AEAD tag configuration.
