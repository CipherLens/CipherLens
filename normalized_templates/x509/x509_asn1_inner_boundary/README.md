# X.509 ASN.1 Inner Substructure Boundary Template

## Source

This normalized template comes from `MBEDTLS-POC-0017`, based on Mbed TLS PR
#2442. The source library is mbedTLS and the public source API is
`mbedtls_x509_crt_parse_der`.

The local PoC is:

```text
data/pocs/core10/MBEDTLS-POC-0017/poc/poc_x509_asn1_bounds.c
```

## API

The harness calls:

```c
mbedtls_x509_crt_parse_der(&crt, der, der_len)
```

The affected lower-level parser path includes:

- `x509_get_attr_type_value`
- `mbedtls_x509_get_crt_ext`
- `mbedtls_x509_get_crl_ext`

## Vulnerability

The vulnerability pattern is an ASN.1 nested substructure boundary error. The
buggy parser uses the parent object end pointer while parsing an inner
substructure. That lets parsing cross the inner ASN.1 boundary.

The reproduced malformed DER certificate contains a TBSCertificate issuer with
two empty inner `AttributeTypeAndValue` structures.

## Oracle

The oracle is a differential parser error-code oracle:

- Buggy signal: `ret == -9186`, corresponding to
  `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG`.
- Fixed/safe signal: `ret == -9184`, corresponding to
  `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA`.

The template reports:

```text
[BUG] buggy behavior: parser crossed inner ASN.1 substructure bounds.
[OK] fixed behavior: parser obeyed inner ASN.1 substructure bounds.
```

## Mutation Points

- `INNER_END_BOUND`: inner parser should set `end = *p + len`.
- `TRAILING_INNER_DATA_CHECK`: parser should reject data remaining after the
  inner substructure.
- `EMPTY_EXTENSION_RETURN`: empty extension substructures should return before
  parsing past the inner end.
- `MALFORMED_DER_STRUCTURE`: regression-test-derived malformed certificate with
  empty inner AttributeTypeAndValue structures.

## Notes

This template does not claim that OpenSSL has the same numeric error codes.
Cross-library migration should preserve the semantic path: DER/X.509/ASN.1
nested parser input, inner substructure length boundary, and an observable
accept/reject or error-path oracle.
