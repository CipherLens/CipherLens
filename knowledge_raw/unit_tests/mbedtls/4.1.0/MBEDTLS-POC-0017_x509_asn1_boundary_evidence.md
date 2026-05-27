# Unit Test / Example Evidence: MBEDTLS-POC-0017 X.509 ASN.1 Boundary

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

status: found_in_local_tests

## APIs Covered

- `mbedtls_x509_crt_parse_der`
- `mbedtls_x509_crt_parse_der_nocopy`
- `mbedtls_x509_crt_parse_der_with_ext_cb`
- internal `x509_get_attr_type_value`
- certificate/CRL extension parser boundary paths

## Evidence

- `tests/suites/test_suite_x509parse.function`
  - Directly invokes all certificate DER parse variants with the same DER bytes and expected result.
  - Relevant calls:

```c
res = mbedtls_x509_crt_parse_der(&crt, buf->x, buf->len);
res = mbedtls_x509_crt_parse_der_nocopy(&crt, buf->x, buf->len);
res = mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 0, NULL, NULL);
res = mbedtls_x509_crt_parse_der_with_ext_cb(&crt, buf->x, buf->len, 1, NULL, NULL);
```

- `tests/suites/test_suite_x509parse.data`
  - Contains the regression-relevant case:
    - `X509 CRT ASN1 (TBS, inv Issuer, 2nd AttributeTypeValue empty)`
    - expected error: `MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, MBEDTLS_ERR_ASN1_OUT_OF_DATA)`
  - Contains many additional malformed nested ASN.1 boundary cases for CRT, CRL, CSR, authority key id, subject key id, and RSASSA-PSS parameters.

## Harness Relevance

- Local tests preserve the exact parser-boundary oracle class used by the PoC: malformed nested structure should produce an inner-boundary out-of-data/length mismatch error rather than crossing into parent bytes.
