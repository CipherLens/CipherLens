# API Constraints: mbedtls_asn1_store_named_data (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_asn1_store_named_data`
- Source file: `tf-psa-crypto/utilities/asn1write.c`
- Declaration: `tf-psa-crypto/include/mbedtls/asn1write.h`
- Signature:

```c
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(mbedtls_asn1_named_data **list,
                                                       const char *oid, size_t oid_len,
                                                       const unsigned char *val,
                                                       size_t val_len);
```

## Parameter Semantics

- `list`: pointer to the head pointer of a named-data list; updated when a new entry is added.
- `oid`/`oid_len`: OID bytes and length used to find or create an entry.
- `val`: associated value. If NULL, no data is copied.
- `val_len`: required value buffer length. If 0, no value buffer is allocated; existing value storage is freed.

## Return Value Semantics

- Returns a pointer to the new or existing entry on success.
- Returns NULL on allocation failure.

## Ownership and Buffer Constraints

- The list and entries are owned by the caller and should be freed with the corresponding ASN.1 named-data cleanup API.
- The function allocates, resizes, shrinks, or frees internal `cur->val.p` to match `val_len`.
- Current source resets `cur->val.len = 0` when `val_len == 0`.

## Harness Generation Notes

- Repeated calls with the same OID exercise update semantics.
- For CVE-style harnesses, observe `ret->val.p` and `ret->val.len` after a zero-length update and then after a same-length nonzero update.
- Good oracles: pointer/length consistency, safe reallocation, no NULL dereference.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0005`.
- Pattern is pointer-length consistency across repeated mutable metadata updates, not ASN.1 encoding alone.
- Cross-library targets should preserve mutable named entry, zero-length update, separate pointer/length state, and later reallocation or copy behavior.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_asn1write.function`: direct calls around lines 508, 563, and 601.
- `library/x509_create.c`: callers around lines 531 and 573.
