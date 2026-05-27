# API Constraints: mbedtls_rsa_parse_pubkey (mbedTLS 4.1.0 internal)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_rsa_parse_pubkey`
- Internal declaration: `tf-psa-crypto/drivers/builtin/src/rsa_internal.h`
- Implementation file: `tf-psa-crypto/drivers/builtin/src/rsa.c`
- Signature:

```c
int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context *rsa,
                             const unsigned char *key,
                             size_t keylen);
```

## Parameter Semantics

- `rsa`: initialized RSA context to populate.
- `key`: DER-encoded PKCS#1 `RSAPublicKey`.
- `keylen`: exact public key buffer length.

## Return Value Semantics

- `0`: public RSA key parsed and checked.
- `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`: top-level boundary mismatch, invalid MPI data, or public-key check failure.
- `MBEDTLS_ERR_ASN1_*`: ASN.1 parse failure; trailing bytes inside the sequence can produce `MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`.

## Ownership and Buffer Constraints

- Does not own `key`.
- Initializes/imports `N` and `E` into `rsa`.
- On error, frees imported MPI values.
- Current source checks `end == p + len` after the top-level SEQUENCE and later checks `p == end` after reading fields.

## Harness Generation Notes

- Initialize `mbedtls_rsa_context`, call parser with DER public key bytes, observe `ret`, then free.
- For `MBEDTLS-POC-0020`, use a valid public key followed by an extra DER INTEGER outside the top-level SEQUENCE.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0020`.
- Preserve top-level object boundary enforcement and accept-vs-reject oracle for trailing garbage.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_rsa.function`: direct public/private parser harness.
- `tf-psa-crypto/tests/suites/test_suite_rsa.data`: public RSA parser tests include malformed top-level object, truncated fields, trailing inside-sequence mismatch, and outside-sequence trailing bytes.
