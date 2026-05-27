# Reproduction Result: MBEDTLS-POC-0017

## Status

reproduced

## Source

PR #2442

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0017-buggy
- commit: 7af080a9f9601449601e9c97d21256bdc2205d02^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0017-fixed
- commit: 7af080a9f9601449601e9c97d21256bdc2205d02

## Library fix commit

- 12f62fb82c81aa3f52bed49dff0f9e038d115f75

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0017/poc/poc_x509_asn1_bounds.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0017/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0017/poc/poc_fixed

## Trigger

The PoC uses a regression-test-derived malformed DER certificate:

X509 Certificate ASN1 (TBSCertificate, issuer two inner set datas)

The malformed issuer contains two empty AttributeTypeAndValue structures.

## Buggy output

calling mbedtls_x509_crt_parse_der...
ret=-9186
expected_buggy=-9186
expected_fixed=-9184
[BUG] buggy behavior: parser crossed inner ASN.1 substructure bounds.

## Fixed output

calling mbedtls_x509_crt_parse_der...
ret=-9184
expected_buggy=-9186
expected_fixed=-9184
[OK] fixed behavior: parser obeyed inner ASN.1 substructure bounds.

## Root cause

In the buggy version, some X.509 ASN.1 parsing routines keep using the parent structure's end pointer when parsing nested substructures. This allows fields inside an ASN.1 substructure to cross the substructure boundary.

For this PoC, the parser incorrectly crosses the zero-length AttributeTypeAndValue substructure boundary and reports:

MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG

The fixed version updates the parsing bound to the inner substructure and reports:

MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA

## Confirmed mutation points

- library/x509.c: x509_get_attr_type_value()
  - `end = *p + len;`
  - `if (*p != end) { return MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH; }`

- library/x509_crt.c: x509_get_crt_ext()
  - `if (*p == end) return 0;`
  - `end = crt->v3_ext.p + crt->v3_ext.len;`

- library/x509_crl.c: x509_get_crl_ext()
  - `if (*p == end) return 0;`
  - `end = ext->p + ext->len;`

## Occlusion candidates

- identifier-level: `end`, `len`, `*p`
- expression-level: `*p + len`, `*p != end`, `*p == end`
- statement-level: `end = *p + len;`
- statement-level: `end = crt->v3_ext.p + crt->v3_ext.len;`
- block-level: inner ASN.1 substructure boundary check
