# MBEDTLS-POC-0003: mbedtls_pk_verify_ext opaque RSA-PSS null dereference

## Source

This pattern comes from Mbed TLS PR #8942 and issue #8937. The affected API is
`mbedtls_pk_verify_ext` in `library/pk.c`.

The confirmed merge commit is `b2b90682646629698ddc0287b4e3967591e1cebc`.
The local buggy worktree used `b2b90682646629698ddc0287b4e3967591e1cebc^1`,
and the library fix commit is `07500fd874fd8688d008e28d349a948a5dd00835`.

## Root Cause

In the buggy version, `mbedtls_pk_verify_ext()` can enter the RSA-PSS-specific
verification path without first checking that the supplied PK context is an RSA
context. For opaque keys, `mbedtls_pk_rsa(*ctx)` can return `NULL`. The
RSA-PSS path then dereferences the missing RSA context and crashes.

The fixed behavior adds a type guard before RSA-specific access:

```c
if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}
```

## Trigger Condition

The v2 minimal PoC creates a legacy RSA key, imports it into PSA, replaces the
PK context with an opaque key via `mbedtls_pk_setup_opaque()`, and calls:

```c
mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS,
                      &pss_opts,
                      &pk,
                      MBEDTLS_MD_SHA256,
                      hash,
                      sizeof(hash),
                      sig,
                      sizeof(sig));
```

The important mismatch is that the call requests RSA-PSS verification while the
PK context is opaque rather than a direct `MBEDTLS_PK_RSA` context.

## Buggy and Fixed Behavior

Buggy output:

```text
opaque pk type = 7
calling mbedtls_pk_verify_ext...
exit_code=139
```

Fixed output:

```text
opaque pk type = 7
calling mbedtls_pk_verify_ext...
verify_ext ret=-14720
expected fixed ret=-14720
[OK] fixed behavior: unsupported opaque verify_ext rejected safely.
```

The oracle is crash versus safe `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE` return.

## Mutation Points

- `VERIFY_TYPE`: controls entry into the RSA-PSS verification path.
- `PK_CONTEXT_KIND`: controls whether the key context is opaque or direct RSA.
- `TYPE_GUARD`: the fixed statement that rejects non-RSA contexts.
- `HASH_LENGTH`: keeps the verification call realistic.
- `SIGNATURE_LENGTH`: keeps the signature input plausible for the trigger call.

## Multi-granularity Masking Guidance

### Identifier-level Candidates

- `ctx`: generic PK context pointer.
- `type`: verification type argument.
- `pk_info`: key-dispatch metadata.
- `mbedtls_pk_rsa`: RSA context extraction helper.

### Expression-level Candidates

- `mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA`

### Statement-level Candidates

- `return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;`
- `mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, ...)`

### Block-level Candidates

```c
if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}
```

## Vulnerability Path Features

The migrated target API should preserve these features:

- signature verification API,
- RSA-PSS-specific verification path,
- opaque or incompatible key context,
- missing type or NULL validation before RSA access,
- internal RSA context lookup can return NULL,
- observable crash or safe error return.

Optional features:

- PSA opaque key import,
- exact hash algorithm,
- exact signature length.

Not required features:

- exact Mbed TLS error-code value,
- exact key size,
- exact random generation sequence.

## Migration Guidance

This pattern is about generic-key dispatch safety, not just RSA-PSS signature
verification.

Good target API features:

- accepts a generic or polymorphic public-key context,
- has an RSA-PSS verification mode or type argument,
- internally dispatches from a generic key context to RSA-specific state,
- can represent opaque, provider-backed, or otherwise incompatible key handles,
- returns observable error codes for unsupported key/type combinations.

Weak target API features:

- performs RSA-PSS verification but only accepts a concrete RSA key type,
- rejects incompatible keys before reaching an internal dispatch path.

Bad target API features:

- has no generic key dispatch layer,
- cannot represent opaque or incompatible key contexts,
- does not expose a safe error-vs-crash oracle.

## Expected Oracle

Bug candidate signals:

- segmentation fault,
- exit code `139`,
- sanitizer NULL dereference.

Safe or fixed behavior:

- return value is `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE`,
- unsupported key type is rejected safely,
- no crash.

## Evidence Files

- Metadata: `data/pocs/core10/MBEDTLS-POC-0003/metadata.json`
- Notes: `data/pocs/core10/MBEDTLS-POC-0003/notes.md`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0003/reproduction_result.md`
- PoC source: `data/pocs/core10/MBEDTLS-POC-0003/poc/poc_pk_verify_ext_null_deref_v2.c`
- Buggy log: `data/pocs/core10/MBEDTLS-POC-0003/poc/run_v2_buggy.log`
- Fixed log: `data/pocs/core10/MBEDTLS-POC-0003/poc/run_v2_fixed.log`
- Library files: `data/pocs/core10/MBEDTLS-POC-0003/library_files.txt`
- Test files: `data/pocs/core10/MBEDTLS-POC-0003/test_files.txt`
- Commits: `data/pocs/core10/MBEDTLS-POC-0003/commits.txt`
- Fix commits: `data/pocs/core10/MBEDTLS-POC-0003/fix_commits.txt`

## Notes

The older PoC and logs did not trigger the crash because signing failed before
the verification call. This pattern intentionally uses the v2 PoC and
`run_v2_*` logs. No local `fix.patch` file is present for this PoC.
