# API Constraints: d2i_RSAPrivateKey (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_RSAPrivateKey`
- Header/manpage: `include/openssl/rsa.h`, `doc/man3/d2i_RSAPrivateKey.pod`
- Implementation family: ASN.1 item functions for `RSAPrivateKey`
- Signature:

```c
RSA *d2i_RSAPrivateKey(RSA **a,
                       const unsigned char **ppin,
                       long length);
```

## Semantics

- Deprecated OpenSSL 3.x API for DER decoding a PKCS#1 `RSAPrivateKey`.
- Expects PKCS#1 RSA private key structure.
- Advances `*ppin` after successful decode.

## Return Value Semantics

- Returns `RSA *` on success.
- Returns `NULL` on ASN.1/RSA decode failure.

## Ownership and Buffer Constraints

- Returned `RSA` is caller-owned and freed with `RSA_free()`.
- Input bytes remain caller-owned.
- Pointer advancement can reveal unconsumed trailing bytes.

## Harness Generation Notes

- Build with deprecated API visibility enabled as needed.
- For `MBEDTLS-POC-0020`, feed PKCS#1 DER plus trailing INTEGER and check whether decode succeeds and where `*ppin` stops.

## Vulnerability-Pattern Migration Notes

- Strong OpenSSL target for RSA private DER trailing-garbage migration.
- Preserves RSA-specific top-level sequence and exact pointer-consumption behavior.

## Related Tests or Examples Found Locally

- `test/evp_extra_test2.c`: legacy `d2i_RSAPrivateKey()` path.
- `crypto/rsa/rsa_ameth.c`, `crypto/rsa/rsa_backend.c`: internal RSA DER decode.
