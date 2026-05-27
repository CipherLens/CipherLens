# API Constraints: PEM_read_bio_PUBKEY (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `PEM_read_bio_PUBKEY`
- Header/manpage: `include/openssl/pem.h`, `doc/man3/PEM_read_bio_PrivateKey.pod`
- Implementation file: `crypto/pem/pem_pkey.c`
- Signature:

```c
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
                              pem_password_cb *cb, void *u);
```

## Semantics

- Reads a PEM SubjectPublicKeyInfo public key into an `EVP_PKEY`.
- Decoder path can skip unsupported PEM blocks while looking for a usable public key.

## Return Value Semantics

- Returns `EVP_PKEY *` on success.
- Returns `NULL` on parse/decode/unsupported-key failure.

## Ownership and Buffer Constraints

- Returned `EVP_PKEY` is caller-owned.
- Input memory belongs to the BIO.
- The API hides decoded DER buffers from the caller.

## Harness Generation Notes

- Use `BIO_new_mem_buf(public_pem, len)` and call `PEM_read_bio_PUBKEY()`.
- For `MBEDTLS-POC-0020`, this API is useful as a high-level public-key parser, but direct DER APIs such as `d2i_PUBKEY()` or `d2i_RSA_PUBKEY()` better expose top-level trailing-garbage behavior.

## Vulnerability-Pattern Migration Notes

- Relevant to public-key parsing target discovery.
- Stronger for PEM wrapper migration than exact DER boundary migration.

## Related Tests or Examples Found Locally

- `test/algorithmid_test.c`: `PEM_read_bio_X509_PUBKEY`.
- `test/evp_extra_test.c`: `PEM_read_bio_PUBKEY_ex`.
- `engines/e_ossltest.c`: direct `PEM_read_bio_PUBKEY()` usage.
