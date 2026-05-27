# Reproduction Result: MBEDTLS-POC-0028

## Status

reproduced

## Source

PR #5350

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0028-buggy
- commit: 6d6d93ea4abe7b374ad9e2080c948c59c9752823^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0028-fixed
- commit: 6d6d93ea4abe7b374ad9e2080c948c59c9752823

## Library fix commit

- f881601c912b608a7fa62c100b2d0aa7352996ee

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0028/poc/poc_psa_aead_invalid_tag_setup.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0028/poc/poc_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0028/poc/poc_fixed

## Trigger

The PoC calls `psa_aead_decrypt_setup()` with:

- key type: AES
- algorithm: `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3)`

CCM only allows tag lengths:

- 4, 6, 8, 10, 12, 14, 16

Therefore tag length 3 is invalid.

## Buggy output

calling psa_crypto_init...
psa_crypto_init status=0
importing AES key...
psa_import_key status=0
calling psa_aead_decrypt_setup with CCM invalid tag length 3...
setup status=0
expected_buggy=0
expected_fixed=-135
[BUG] invalid AEAD tag length accepted during setup.

## Fixed output

calling psa_crypto_init...
psa_crypto_init status=0
importing AES key...
psa_import_key status=0
calling psa_aead_decrypt_setup with CCM invalid tag length 3...
setup status=-135
expected_buggy=0
expected_fixed=-135
[OK] invalid AEAD tag length rejected during setup.

## Root cause

In the buggy version, `psa_aead_setup()` does not validate whether the requested AEAD shortened tag length is legal for the selected AEAD algorithm.

For CCM, tag length 3 is invalid, but the buggy version accepts the operation setup and returns `PSA_SUCCESS`.

## Confirmed fix

The fixed version adds tag length validation during `psa_aead_setup()` through:

psa_validate_tag_length()

The setup now rejects invalid tag lengths with:

PSA_ERROR_INVALID_ARGUMENT

## Confirmed mutation point

library/psa_crypto.c: psa_aead_setup()

Statement-level mutation point:

if( ( status = psa_validate_tag_length( operation, alg ) ) != PSA_SUCCESS )
    goto exit;

Helper-level mutation point:

psa_validate_tag_length()

## Occlusion candidates

- identifier-level: `tag_len`, `alg`
- expression-level: `tag_len < 4`, `tag_len > 16`, `tag_len % 2`
- statement-level: `psa_validate_tag_length( operation, alg )`
- block-level: CCM/GCM/ChaCha20-Poly1305 tag length validation switch
