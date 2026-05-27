# MBEDTLS-POC-0017: X.509 ASN.1 inner substructure boundary

## Source

This pattern comes from Mbed TLS PR #2442 and issues #2430, #2431, and #2437.
The affected public API for the local PoC is `mbedtls_x509_crt_parse_der`.
The root cause is in lower-level X.509 ASN.1 parsing helpers.

The confirmed fixed merge commit is
`7af080a9f9601449601e9c97d21256bdc2205d02`; the local buggy worktree used
`7af080a9f9601449601e9c97d21256bdc2205d02^1`. The library fix commit is
`12f62fb82c81aa3f52bed49dff0f9e038d115f75`.

## Root Cause

Some parser routines used the parent ASN.1 structure's `end` pointer while
parsing a nested substructure. This allowed fields inside an inner structure to
cross the inner boundary.

The central fixed behavior is to set the parse bound to the inner structure:

```c
end = *p + len;
```

and reject trailing inner data, for example:

```c
if (*p != end) {
    return MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
}
```

## Trigger Condition

The PoC calls `mbedtls_x509_crt_parse_der()` with a regression-test-derived
malformed DER certificate:

- X.509 Certificate ASN.1
- malformed TBSCertificate issuer
- two empty inner AttributeTypeAndValue structures

## Buggy and Fixed Behavior

Buggy behavior:

```text
calling mbedtls_x509_crt_parse_der...
ret=-9186
expected_buggy=-9186
expected_fixed=-9184
[BUG] buggy behavior: parser crossed inner ASN.1 substructure bounds.
```

Fixed behavior:

```text
calling mbedtls_x509_crt_parse_der...
ret=-9184
expected_buggy=-9186
expected_fixed=-9184
[OK] fixed behavior: parser obeyed inner ASN.1 substructure bounds.
```

## Oracle

Bug signal:

- return value is `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG`,
- parser crossed inner ASN.1 substructure bounds.

Fixed signal:

- return value is `MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA`,
- parser obeyed the inner substructure boundary.

## Mutation Points

- `INNER_END_BOUND`: `end = *p + len;`
- `TRAILING_INNER_DATA_CHECK`: `*p != end` rejection block.
- `EMPTY_EXTENSION_RETURN`: `if (*p == end) return 0;`
- `MALFORMED_DER_STRUCTURE`: crafted DER with empty inner structures.

## Vulnerability Path Features

Must preserve:

- ASN.1 DER parser entrypoint,
- nested substructure length field,
- parent-end versus inner-end boundary,
- malformed nested empty structure,
- differential parser error or rejection path.

Optional:

- X.509 certificate DER,
- issuer name AttributeTypeAndValue,
- CRT/CRL extension helper paths.

Not required:

- exact DER bytes,
- exact numeric error values,
- exact helper names.

## Migration Guidance

Good target APIs parse DER/ASN.1 nested structures, maintain explicit parent
and child end pointers, expose parse error classes, and allow harnesses to feed
malformed nested input. Preserve the inner-boundary path; this is not merely a
generic malformed-certificate pattern.

## References

- PR: `https://github.com/Mbed-TLS/mbedtls/pull/2442`
- Evidence: `data/pocs/core10/MBEDTLS-POC-0017/reproduction_result.md`
- PoC: `data/pocs/core10/MBEDTLS-POC-0017/poc/poc_x509_asn1_bounds.c`
- Logs: `data/pocs/core10/MBEDTLS-POC-0017/poc/run_buggy.log`, `data/pocs/core10/MBEDTLS-POC-0017/poc/run_fixed.log`
