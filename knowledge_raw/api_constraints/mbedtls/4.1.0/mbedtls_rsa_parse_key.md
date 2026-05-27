# API Constraints: mbedtls_rsa_parse_key (mbedTLS 4.1.0 internal)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_rsa_parse_key`
- Internal declaration: `tf-psa-crypto/drivers/builtin/src/rsa_internal.h`
- Implementation file: `tf-psa-crypto/drivers/builtin/src/rsa.c`
- Signature:

```c
int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa,
                          const unsigned char *key,
                          size_t keylen);
```

## Parameter Semantics

- `rsa`: initialized RSA context to populate.
- `key`: DER-encoded PKCS#1 `RSAPrivateKey`.
- `keylen`: exact key buffer length in bytes.

## Return Value Semantics

- `0`: private RSA key parsed and checked.
- `MBEDTLS_ERR_RSA_BAD_INPUT_DATA`: invalid RSA top-level structure, version, zero MPI, unsupported size, or malformed top-level length.
- `MBEDTLS_ERR_RSA_KEY_CHECK_FAILED`: RSA consistency check failed.
- `MBEDTLS_ERR_ASN1_*`: ASN.1 parse failure; trailing bytes inside the top-level sequence can yield `MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`.

## Ownership and Buffer Constraints

- Does not own `key`; imports MPI values into `rsa`.
- On error, the function frees the RSA context contents.
- Current source verifies `end == p + len` immediately after reading the top-level SEQUENCE length, rejecting bytes outside the top-level DER object.

## Harness Generation Notes

- Initialize `mbedtls_rsa_context`, pass DER bytes, compare return code, then call `mbedtls_rsa_free()`.
- For `MBEDTLS-POC-0020`, append an extra ASN.1 INTEGER outside the top-level PKCS#1 SEQUENCE and expect `MBEDTLS_ERR_RSA_BAD_INPUT_DATA` in fixed/current source.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0020`.
- The root feature is top-level DER object boundary enforcement: `end != p + len` must reject trailing garbage.
- Strong target APIs should reject valid RSA private key DER followed by extra bytes and expose pointer-consumption or return status.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_rsa.function`: `rsa_parse_pkcs1_key` calls this parser directly.
- `tf-psa-crypto/tests/suites/test_suite_rsa.data`: private-key cases include valid PKCS#1 DER, malformed fields, trailing bytes inside the sequence (`MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`), and bytes outside the sequence (`MBEDTLS_ERR_RSA_BAD_INPUT_DATA`).
