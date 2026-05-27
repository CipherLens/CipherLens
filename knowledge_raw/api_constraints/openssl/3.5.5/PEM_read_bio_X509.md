# API Constraints: PEM_read_bio_X509 (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `PEM_read_bio_X509`
- Header/manpage: `include/openssl/pem.h`, `doc/man3/PEM_read_bio_PrivateKey.pod`
- Implementation family: PEM ASN.1 read macros and X.509 DER decode
- Signature:

```c
X509 *PEM_read_bio_X509(BIO *bp, X509 **x,
                        pem_password_cb *cb, void *u);
```

## Semantics

- Reads PEM certificate armor from a BIO and decodes the DER certificate into `X509`.
- For X.509 certificates, password callback is normally unused unless encrypted PEM wrapper features are involved.

## Return Value Semantics

- Returns `X509 *` on success.
- Returns `NULL` on PEM or DER parse failure.

## Ownership and Buffer Constraints

- Returned certificate is caller-owned and freed with `X509_free()`.
- If `x != NULL`, the pointed object may be reused/replaced according to OpenSSL d2i conventions.

## Harness Generation Notes

- Use `BIO_new_mem_buf(cert_pem, len)`, call `PEM_read_bio_X509()`, assert NULL/non-NULL, then free.
- For `MBEDTLS-POC-0017`, DER-level `d2i_X509()` gives tighter control over malformed nested ASN.1 bytes.

## Vulnerability-Pattern Migration Notes

- Candidate for X.509 parser boundary migration when input is PEM wrapped.
- Preserve malformed nested ASN.1 structure and parse failure oracle; avoid treating it only as text armor failure.

## Related Tests or Examples Found Locally

- `test/x509_test.c`, `test/crltest.c`, `test/algorithmid_test.c`, `test/v3ext.c`, `test/x509_check_cert_pkey_test.c`: direct `PEM_read_bio_X509()` usage.
