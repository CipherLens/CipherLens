# API Constraints: d2i_PrivateKey (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_PrivateKey`
- Header/manpage: `include/openssl/evp.h`, `doc/man3/d2i_PrivateKey.pod`
- Implementation file: `crypto/asn1/d2i_pr.c`
- Signature:

```c
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a,
                        const unsigned char **pp, long length);
```

## Semantics

- DER-decodes a private key of a specified algorithm type.
- Attempts key-specific format and PKCS#8 unencrypted `PrivateKeyInfo`.
- Advances `*pp` after successful decode.

## Return Value Semantics

- Returns `EVP_PKEY *` on success.
- Returns `NULL` on decode/type mismatch/fetch failure.

## Ownership and Buffer Constraints

- Returned key is caller-owned and freed with `EVP_PKEY_free()`.
- If `a != NULL`, `*a` can be overwritten with the returned key.
- Input bytes are caller-owned.

## Harness Generation Notes

- For RSA use `EVP_PKEY_RSA` as `type`.
- Compare return pointer and `p == input + consumed_len` to evaluate trailing data handling.

## Vulnerability-Pattern Migration Notes

- Candidate for `MBEDTLS-POC-0020` private-key DER migration.
- Stronger exact target is `d2i_RSAPrivateKey()` for PKCS#1 RSA; this API is useful for generic EVP private-key parsing.

## Related Tests or Examples Found Locally

- `test/x509_test.c`: `d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(privkeydata))`.
- `test/pkcs12_format_test.c`: `d2i_PrivateKey_ex(EVP_PKEY_RSA, ...)`.
