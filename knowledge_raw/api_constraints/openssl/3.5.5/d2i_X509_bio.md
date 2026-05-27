# API Constraints: d2i_X509_bio (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_X509_bio`
- Header declaration: `include/openssl/x509.h`
- Implementation file: `crypto/x509/x_all.c`
- Signature:

```c
X509 *d2i_X509_bio(BIO *bp, X509 **x509);
```

## Semantics

- DER-decodes an X.509 certificate from a BIO through `ASN1_item_d2i_bio()`.

## Return Value Semantics

- Returns `X509 *` on success.
- Returns `NULL` on read or ASN.1 parse failure.

## Ownership and Buffer Constraints

- Returned object is caller-owned.
- Input stream is caller-owned; exact pointer-consumption observation is weaker than memory `d2i_X509()`.

## Harness Generation Notes

- Use `BIO_new_mem_buf(der, len)` for in-memory DER.
- Prefer `d2i_X509()` when a harness needs exact trailing-byte pointer checks.

## Vulnerability-Pattern Migration Notes

- Candidate for X.509 parser boundary migration with BIO input.
- Useful when target harness framework standardizes on BIOs.

## Related Tests or Examples Found Locally

- `test/pkcs7_test.c`: direct `d2i_X509_bio()`.
- `test/http_test.c`: parses response BIO via `d2i_X509_bio()`.
- `crypto/x509/by_file.c`: DER certificate lookup path uses `d2i_X509_bio()`.
