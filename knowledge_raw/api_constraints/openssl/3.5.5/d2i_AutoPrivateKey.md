# API Constraints: d2i_AutoPrivateKey (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `d2i_AutoPrivateKey`
- Header/manpage: `include/openssl/evp.h`, `doc/man3/d2i_PrivateKey.pod`
- Implementation file: `crypto/asn1/d2i_pr.c`
- Signature:

```c
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a,
                             const unsigned char **pp,
                             long length);
```

## Semantics

- DER-decodes a private key while auto-detecting key format/type.
- Uses decoder path, then legacy ASN.1 sequence inspection fallback.
- Advances `*pp` after successful decode.

## Return Value Semantics

- Returns `EVP_PKEY *` on success.
- Returns `NULL` on decode failure.

## Ownership and Buffer Constraints

- Returned key is caller-owned.
- Input bytes remain caller-owned.
- Pointer advancement is available as an oracle for exact consumption.

## Harness Generation Notes

- Use for generic DER key migration when key type may vary.
- For RSA PKCS#1 trailing-garbage migration, also test `d2i_RSAPrivateKey()` because it preserves RSA-specific structure.

## Vulnerability-Pattern Migration Notes

- Candidate for `MBEDTLS-POC-0020`.
- A good harness should verify that DER plus trailing garbage does not silently become success without exposing unconsumed bytes.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: `test_d2i_AutoPrivateKey` asserts `p == input + input_len`.
- `test/evp_extra_test2.c`: `test_d2i_AutoPrivateKey_ex`.
- `test/pkcs12_format_test.c`: `d2i_AutoPrivateKey()`.
