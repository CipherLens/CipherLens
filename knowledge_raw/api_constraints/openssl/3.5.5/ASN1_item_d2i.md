# API Constraints: ASN1_item_d2i (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `ASN1_item_d2i`
- Header declaration: `include/openssl/asn1.h`
- Implementation file: `crypto/asn1/tasn_dec.c`
- Signature:

```c
ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val,
                          const unsigned char **in,
                          long len,
                          const ASN1_ITEM *it);
```

## Semantics

- Generic DER decoder for a supplied ASN.1 item descriptor.
- `ASN1_item_d2i()` calls `ASN1_item_d2i_ex(..., NULL, NULL)`.
- Recursive decoder enforces constructed nesting limits and ASN.1 template boundaries.

## Return Value Semantics

- Returns decoded `ASN1_VALUE *` on success.
- Returns `NULL` on parse failure.

## Ownership and Buffer Constraints

- Returned value ownership depends on the ASN.1 item type and must be freed with the matching item free routine.
- Input bytes remain caller-owned.
- `*in` is advanced on successful decode.

## Harness Generation Notes

- Use when target migration wants to isolate nested ASN.1 item parsing rather than full X.509 objects.
- Requires selecting the correct `ASN1_ITEM` descriptor, e.g. `ASN1_ITEM_rptr(X509)`.

## Vulnerability-Pattern Migration Notes

- Strong generic target for `MBEDTLS-POC-0017` if a harness can select nested item descriptors.
- Preserve child-length/end-boundary behavior and pointer advancement oracle.

## Related Tests or Examples Found Locally

- `crypto/x509/v3_lib.c`: decodes extension values with `ASN1_item_d2i`.
- `crypto/x509/x_req.c`, `crypto/x509/x_all.c`, provider tests: internal uses through ASN.1 item decode wrappers.
