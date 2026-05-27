# API Constraints: EVP_DecryptFinal_ex (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_DecryptFinal_ex`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/evp_enc.c`
- Manpage: `doc/man3/EVP_EncryptInit.pod`
- Signature:

```c
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
    int *outl);
```

## Semantics

- Finalizes decryption and checks final block padding where applicable.
- Writes final plaintext bytes to `outm` and count to `outl`.
- Current implementation sets `*outl = 0` at function entry when `outl` is not NULL.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` if decrypt failed, including padding failure.

## Object and Buffer Constraints

- `EVP_CIPHER_CTX` is opaque. Harnesses must not access internal fields.
- `outm` is caller-owned output buffer.
- `outl` is caller-visible output length pointer and must not be NULL.

## Adapter Generation Notes

- Uses caller-provided output buffer: yes.
- Exposes explicit output length: yes, `int *outl`.
- Writes into caller buffer: yes.
- Good oracle for padding migration: return `0` on invalid padding and `outl` remains zero in current source.

## Vulnerability-Pattern Migration Notes

- Stronger target than `EVP_CipherFinal_ex` for mbedTLS invalid-padding output-length safety because it directly represents decrypt finalization.
- Preserve invalid-padding error path and output length observation.

## Related Tests or Examples Found Locally

- `test/aesgcmtest.c`: direct call around line 95.
- `test/evp_extra_test.c`: direct call around line 6307.
- Demos: `demos/cipher/aesgcm.c`, `demos/cipher/aeskeywrap.c`, `demos/cipher/ariacbc.c`.
- Internal callers include `crypto/pem/pem_lib.c`, `crypto/pkcs12/p12_decr.c`, `crypto/hpke/hpke.c`.
