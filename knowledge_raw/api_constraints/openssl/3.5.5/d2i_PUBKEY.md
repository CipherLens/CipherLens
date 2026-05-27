# API Constraints: d2i_PUBKEY (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_PUBKEY`
- Header/manpage: `include/openssl/x509.h`, `doc/man3/X509_PUBKEY_new.pod`
- Implementation file: `crypto/x509/x_pubkey.c`
- Signature:

```c
EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a,
                     const unsigned char **pp,
                     long length);
```

## Semantics

- DER-decodes an `EVP_PKEY` public key using RFC 5280 `SubjectPublicKeyInfo`.
- Advances `*pp` after successful decode.

## Return Value Semantics

- Returns `EVP_PKEY *` on success.
- Returns `NULL` on ASN.1, provider, or unsupported-key failure.

## Ownership and Buffer Constraints

- Returned key is caller-owned and freed with `EVP_PKEY_free()`.
- Input buffer remains caller-owned.
- Pointer advancement is observable for exact-consumption checks.

## Harness Generation Notes

- Use `const unsigned char *p = der; EVP_PKEY *k = d2i_PUBKEY(NULL, &p, len);`.
- For RSA public-key migration, confirm whether the adapter emits SPKI rather than raw PKCS#1.

## Vulnerability-Pattern Migration Notes

- Candidate for `MBEDTLS-POC-0020` public-key parser migration.
- Good if harness checks both success/failure and `p == der + len` or detects accepted trailing bytes.

## Related Tests or Examples Found Locally

- `test/x509_test.c`: direct `d2i_PUBKEY(NULL, &p, sizeof(pubkeydata))`.
- `test/provider_pkey_test.c`, provider tests: public-key DER decode examples.
