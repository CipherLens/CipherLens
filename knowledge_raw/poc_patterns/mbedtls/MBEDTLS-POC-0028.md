# MBEDTLS-POC-0028: PSA AEAD invalid shortened tag setup

## Source

This pattern comes from Mbed TLS PR #5350 and issue #5285. The affected public
API used by the local PoC is `psa_aead_decrypt_setup`; the root cause is in the
shared `psa_aead_setup()` path and its missing tag-length validation.

The confirmed fixed merge commit is
`6d6d93ea4abe7b374ad9e2080c948c59c9752823`; the local buggy worktree used
`6d6d93ea4abe7b374ad9e2080c948c59c9752823^1`. The library fix commit is
`f881601c912b608a7fa62c100b2d0aa7352996ee`.

## Root Cause

The buggy `psa_aead_setup()` path accepts AEAD algorithms with invalid shortened
tag lengths. For CCM, tag length `3` is invalid, but the buggy
`psa_aead_decrypt_setup()` returns `PSA_SUCCESS`.

The fixed setup path validates the tag length:

```c
if( ( status = psa_validate_tag_length( operation, alg ) ) != PSA_SUCCESS )
    goto exit;
```

## Trigger Condition

The PoC initializes PSA crypto, imports a 128-bit AES key, and calls:

```c
psa_aead_decrypt_setup(&operation, key_id,
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3));
```

CCM only allows tag lengths `4, 6, 8, 10, 12, 14, 16`, so tag length `3` must
be rejected.

## Buggy and Fixed Behavior

Buggy behavior:

```text
setup status=0
expected_buggy=0
expected_fixed=-135
[BUG] invalid AEAD tag length accepted during setup.
```

Fixed behavior:

```text
setup status=-135
expected_buggy=0
expected_fixed=-135
[OK] invalid AEAD tag length rejected during setup.
```

## Oracle

Bug signal:

- `psa_aead_decrypt_setup()` returns `PSA_SUCCESS`,
- invalid CCM tag length `3` is accepted.

Safe signal:

- `psa_aead_decrypt_setup()` returns `PSA_ERROR_INVALID_ARGUMENT`,
- invalid AEAD tag length is rejected during setup.

## Mutation Points

- `AEAD_ALGORITHM`: shortened-tag CCM algorithm expression.
- `TAG_LENGTH`: invalid tag length `3`.
- `AEAD_SETUP_CALL`: `psa_aead_decrypt_setup(...)`.
- `TAG_LENGTH_VALIDATION_CALL`: `psa_validate_tag_length(...)`.

## Vulnerability Path Features

Must preserve:

- PSA-style AEAD setup entrypoint,
- AEAD algorithm with shortened tag,
- algorithm-specific tag length rules,
- invalid parameter accepted versus rejected,
- observable status return.

Optional:

- AES key type,
- CCM algorithm,
- decrypt setup path.

Not required:

- exact key bytes,
- exact key identifier,
- exact driver wrapper path.

## Migration Guidance

Good target APIs expose AEAD setup with tag-length-bearing algorithms or
parameters, enforce algorithm-specific tag length constraints, and return an
observable invalid-argument status during setup. Preserve setup-time validation;
this is not an authentication-failure pattern.

## References

- PR: `https://github.com/Mbed-TLS/mbedtls/pull/5350`
- Evidence: `data/pocs/core10/MBEDTLS-POC-0028/reproduction_result.md`
- PoC: `data/pocs/core10/MBEDTLS-POC-0028/poc/poc_psa_aead_invalid_tag_setup.c`
- Logs: `data/pocs/core10/MBEDTLS-POC-0028/poc/run_buggy.log`, `data/pocs/core10/MBEDTLS-POC-0028/poc/run_fixed.log`
