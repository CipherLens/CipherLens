# API Constraints: X.509 / ASN.1 Nested Parsing Helpers (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## APIs

- Internal helper: `x509_get_attr_type_value`
- Related extension parser paths: certificate extension parsing in `library/x509_crt.c`, CRL extension parsing in `library/x509_crl.c`
- Source files:
  - `library/x509.c`
  - `library/x509_crt.c`
  - `library/x509_crl.c`

## Relevant Signatures

```c
static int x509_get_attr_type_value(unsigned char **p,
                                    const unsigned char *end,
                                    mbedtls_x509_name *cur);
```

The current source also uses local parser end boundaries such as:

```c
end = *p + len;
end = crt->v3_ext.p + crt->v3_ext.len;
end = ext->p + ext->len;
```

## Parameter Semantics

- `p`: in/out ASN.1 cursor; successful parsing advances it.
- `end`: end pointer for the current ASN.1 object being parsed.
- `cur`: parsed X.509 name node storing OID and value buffers.

## Return Value Semantics

- `0`: nested object parsed and cursor ends exactly at the nested object end.
- `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA`: not enough bytes inside the nested structure.
- `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG`: unexpected type/value tag.
- `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH`: trailing bytes remain inside the nested object.
- Extension helpers similarly return `MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_*`.

## Ownership and Buffer Constraints

- These helpers do not own the input DER buffer.
- They store pointers into the parsed certificate buffer, so the surrounding certificate object controls lifetime.
- Cursor/end arithmetic is the critical safety boundary.

## Harness Generation Notes

- Prefer public entry points such as `mbedtls_x509_crt_parse_der()` and malformed DER bytes.
- White-box harnesses can target `x509_get_attr_type_value()` only when compiling against source internals.
- Oracles should compare return-code class, especially `OUT_OF_DATA` vs `UNEXPECTED_TAG` or `LENGTH_MISMATCH`.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0017`.
- The migration feature is parent-end vs inner-end parsing, not certificate validation in general.
- Target APIs such as OpenSSL `d2i_X509()`/`ASN1_item_d2i()` should be evaluated on whether malformed nested substructures are rejected at the child object boundary.

## Related Tests or Examples Found Locally

- `tests/suites/test_suite_x509parse.data`: many synthetic malformed DER certificates/CRLs with expected ASN.1 boundary errors.
- Specific local evidence includes "X509 CRT ASN1 (TBS, inv Issuer, 2nd AttributeTypeValue empty)".
