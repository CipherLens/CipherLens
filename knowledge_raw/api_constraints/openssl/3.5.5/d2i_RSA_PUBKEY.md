# API Constraints: d2i_RSA_PUBKEY (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_RSA_PUBKEY`
- Header/manpage: `include/openssl/rsa.h`, `doc/man3/d2i_RSAPrivateKey.pod`
- Implementation file: `crypto/x509/x_pubkey.c`
- Signature:

```c
RSA *d2i_RSA_PUBKEY(RSA **a,
                    const unsigned char **pp,
                    long length);
```

## Semantics

- Deprecated OpenSSL 3.x API for DER decoding an RSA public key in `SubjectPublicKeyInfo` form.
- Internally decodes through the EVP public-key path and extracts an `RSA`.
- Advances `*pp` after successful decode.

## Return Value Semantics

- Returns `RSA *` on success.
- Returns `NULL` on decode or non-RSA key failure.

## Ownership and Buffer Constraints

- Returned RSA key is caller-owned.
- Input bytes remain caller-owned.
- Pointer advancement is observable.

## Harness Generation Notes

- For PKCS#1 raw `RSAPublicKey`, OpenSSL also has `d2i_RSAPublicKey()`; this requested API is SPKI-wrapped.
- For `MBEDTLS-POC-0020`, include a clear note whether the migrated input is PKCS#1 or SPKI.

## Vulnerability-Pattern Migration Notes

- Candidate for public-key trailing-garbage migration when adapting to SPKI public key format.
- If the source PoC is raw PKCS#1, format conversion is a nontrivial adapter step.

## Related Tests or Examples Found Locally

- `crypto/x509/x_pubkey.c`: implementation uses `ossl_d2i_PUBKEY_legacy`.
- Local tests more commonly call `d2i_PUBKEY()` or `d2i_X509_PUBKEY()` than `d2i_RSA_PUBKEY()` directly.
