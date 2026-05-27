# API Constraints: PEM_bytes_read_bio (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `PEM_bytes_read_bio`
- Header declaration: `include/openssl/pem.h`
- Implementation file: `crypto/pem/pem_lib.c`
- Signature:

```c
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, BIO *bp,
                       pem_password_cb *cb, void *u);
```

## Semantics

- Reads a named PEM block from a BIO and returns decoded bytes.
- Uses EAY-compatible PEM parsing flags.
- Encrypted PEM headers are processed through `PEM_do_header()`, which derives a key and calls `EVP_DecryptInit_ex()`, `EVP_DecryptUpdate()`, and `EVP_DecryptFinal_ex()`.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on PEM, decrypt, password, allocation, or decode failure.

## Ownership and Buffer Constraints

- On success, `*pdata` points to an OpenSSL-allocated decoded buffer; caller frees with `OPENSSL_free()` or the matching secure free path if secure memory was used.
- `*plen` receives decoded/decrypted length.
- `*pnm` receives the PEM name if requested.

## Harness Generation Notes

- Good low-level target for `MBEDTLS-POC-0011` because it exposes decoded byte length and encrypted PEM processing.
- Build malformed encrypted PEM input in a BIO, call `PEM_bytes_read_bio()`, and observe return code/error queue/sanitizer.

## Vulnerability-Pattern Migration Notes

- Strong OpenSSL target candidate for PEM encrypted short-body migration.
- Preserves parser boundary: armored input -> base64 decode -> optional decrypt/padding finalization.

## Related Tests or Examples Found Locally

- `crypto/pem/pem_pkey.c`: key readers call `PEM_bytes_read_bio()` / `_secmem()`.
- `crypto/pem/pem_oth.c`, `crypto/pem/pem_all.c`: additional low-level PEM byte readers.
- Direct local unit tests primarily exercise higher-level PEM read APIs rather than this low-level function.
