# Working Notes

## Manual tasks

- [ ] Confirm exact fixing commit.
- [ ] Locate exact regression test case.
- [ ] Extract minimal PoC or API call sequence.
- [ ] Identify buggy and fixed versions.
- [ ] Run reproduction test locally.
- [ ] Record failure signal.
- [ ] Confirm AST mutation point.
- [ ] Prepare RAG context sources.

## Investigation log

- TBD

## Candidate commands

```bash
# Inspect source files
cat library_files.txt

# Inspect test files
cat test_files.txt

# Inspect commits
cat commits.txt
```

## Exact fixing commit confirmed

Confirmed PR #8942 merge commit:

- b2b90682646629698ddc0287b4e3967591e1cebc

The merge contains:

- test_trigger_commit=d59caf4e515b5ba52f42146f60d2ddf8020e3aea
- library_fix_commit=07500fd874fd8688d008e28d349a948a5dd00835
- test_update_commit=da47518554b5e56e3c5d08fdad304fb282baaba4

Root cause:
mbedtls_pk_verify_ext() entered the RSA-PSS verification path without first checking that the PK context is actually an RSA context. For opaque/non-RSA contexts, mbedtls_pk_rsa(ctx) can return NULL, causing NULL dereference.

Confirmed fixed check:

if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

Regression test evidence:
test_suite_pk: extend pk_psa_wrap_sign_ext() to call verify_ext() with opaque keys. The pre-fix test path can crash; the fixed version returns MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE.

## Exact fixing commit and mutation point confirmed

Confirmed fixed merge commit:

- b2b90682646629698ddc0287b4e3967591e1cebc

Buggy version:

- b2b90682646629698ddc0287b4e3967591e1cebc^1

Confirmed library fix commit:

- 07500fd874fd8688d008e28d349a948a5dd00835

Confirmed regression-test trigger commit:

- d59caf4e515b5ba52f42146f60d2ddf8020e3aea

Root cause:
mbedtls_pk_verify_ext() entered the RSA-PSS path without checking that the PK context type is MBEDTLS_PK_RSA. For opaque keys, mbedtls_pk_rsa(*ctx) can return NULL, causing NULL dereference.

Fixed check:
if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

Confirmed mutation point:
library/pk.c: mbedtls_pk_verify_ext(), type check before RSA-PSS verification path.
