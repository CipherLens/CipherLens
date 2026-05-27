# PK Template: pk_verify_ext opaque RSA-PSS null dereference

## Source PoC

`poc_pk_verify_ext_null_deref_v2.c`

## Source API

`mbedtls_pk_verify_ext`

## Vulnerability Pattern

This template creates a legacy RSA key, imports it into PSA, converts the PK context into an opaque context, and then calls `mbedtls_pk_verify_ext` using the RSA-PSS verification path.

The fixed behavior is to reject the unsupported opaque verification path safely with `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE`. A buggy implementation may dereference a NULL RSA context.

## Key Mutation Points

- `[KEY_BITS]`: RSA key size
- `[HASH_LEN]`: hash buffer length
- `[SIG_LEN]`: signature buffer length
- `[MD_ALG]`: message digest algorithm
- `[PK_VERIFY_TYPE]`: verify extension type, primarily `MBEDTLS_PK_RSASSA_PSS`
- `[EXPECTED_SALT_LEN]`: RSA-PSS salt length policy

## Oracle

- Crash or ASAN null dereference: potential true positive
- `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE`: fixed safe behavior
- Other nonzero return without crash: semantic triage needed
- Setup failure before trigger call: harness construction issue

## Cross-library Status

This template is initially mbedTLS-specific because the trigger path depends on PSA opaque-key integration and `mbedtls_pk_context` internals.
