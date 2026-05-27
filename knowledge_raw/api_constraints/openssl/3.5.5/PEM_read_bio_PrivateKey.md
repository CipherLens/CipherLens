# API Constraints: PEM_read_bio_PrivateKey (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `PEM_read_bio_PrivateKey`
- Header/manpage: `include/openssl/pem.h`, `doc/man3/PEM_read_bio_PrivateKey.pod`
- Implementation file: `crypto/pem/pem_pkey.c`
- Signature:

```c
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u);
```

## Semantics

- Reads a PEM private key from `BIO`.
- Uses decoder path first, then legacy PEM byte extraction / DER decode fallback.
- Supports encrypted PEM through password callback.

## Return Value Semantics

- Returns `EVP_PKEY *` on success.
- Returns `NULL` on parse, decode, password, or unsupported-key failure; callers inspect OpenSSL error queue.

## Ownership and Buffer Constraints

- Returned key is caller-owned and must be freed with `EVP_PKEY_free()`.
- If `x != NULL`, any previous `*x` can be replaced/freed by the read routine.
- Input bytes are owned by the BIO; internal decoded buffers are OpenSSL-owned temporaries.

## Harness Generation Notes

- Create an in-memory BIO with `BIO_new_mem_buf()`, call read API, check NULL vs non-NULL, then free `EVP_PKEY` and `BIO`.
- For encrypted PEM migration from `MBEDTLS-POC-0011`, include password callback behavior and malformed/short base64 input.

## Vulnerability-Pattern Migration Notes

- Candidate for encrypted PEM parser migration.
- Strong if malformed encrypted PEM reaches base64/decrypt/padding paths with observable failure.
- Weaker than lower-level `PEM_bytes_read_bio` for decoded-buffer boundary visibility.

## Related Tests or Examples Found Locally

- `test/bio_pw_callback_test.c`: encrypted/private-key PEM read callback tests.
- `test/threadstest.c`, `test/ocspapitest.c`, `test/x509_check_cert_pkey_test.c`: direct private-key PEM reads.
- `crypto/pem/pem_lib.c`: legacy encrypted PEM decrypt path uses `PEM_do_header()`.
