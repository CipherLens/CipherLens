# API Constraints: mbedtls_x509_crt_parse_der (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_x509_crt_parse_der`
- Header declaration: `include/mbedtls/x509_crt.h`
- Implementation file: `library/x509_crt.c`
- Signature:

```c
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen);
```

## Parameter Semantics

- `chain`: initialized `mbedtls_x509_crt` chain. Parsed certificates are appended to the chain.
- `buf`: DER-encoded certificate bytes.
- `buflen`: exact input length in bytes.

## Return Value Semantics

- `0`: certificate parsed and appended.
- Negative `MBEDTLS_ERR_X509_*` errors, often combined with `MBEDTLS_ERR_ASN1_*` via `MBEDTLS_ERROR_ADD`.
- Relevant boundary errors include `MBEDTLS_ERR_ASN1_OUT_OF_DATA`, `MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`, and `MBEDTLS_ERR_ASN1_UNEXPECTED_TAG`.

## Ownership and Buffer Constraints

- `mbedtls_x509_crt_parse_der()` calls the internal parser with `make_copy = 1`, so it makes an internal copy of `buf`.
- `mbedtls_x509_crt_parse_der_nocopy()` is the stricter lifetime variant.
- On parse failure, temporary chain nodes are freed or detached.

## Harness Generation Notes

- Initialize with `mbedtls_x509_crt_init()`, call `psa_crypto_init()` if required by the build, parse DER, observe `ret`, then call `mbedtls_x509_crt_free()`.
- For `MBEDTLS-POC-0017`, use malformed DER whose nested issuer `AttributeTypeAndValue` substructure is empty or shorter than the parent parser would allow.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0017`.
- The source path is nested ASN.1 parsing where inner substructure bounds must be `*p + len`, not the parent object end.
- Good target candidates include DER/X.509 APIs exposing different parse error classes or at least observable reject behavior for nested-boundary malformed inputs.

## Related Tests or Examples Found Locally

- `tests/suites/test_suite_x509parse.function`: direct calls to `mbedtls_x509_crt_parse_der()`, `_nocopy()`, and `_with_ext_cb()`.
- `tests/suites/test_suite_x509parse.data`: malformed certificate cases, including "X509 CRT ASN1 (TBS, inv Issuer, 2nd AttributeTypeValue empty)" with `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA`.
- `programs/ssl/mini_client.c`, `programs/ssl/ssl_client2.c`, `programs/ssl/ssl_server2.c`: application examples that parse DER certificates.
