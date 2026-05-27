# API Constraints: psa_aead_setup (mbedTLS 4.1.0 internal)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `psa_aead_setup`
- Visibility: `static` internal core helper
- Implementation file: `tf-psa-crypto/core/psa_crypto.c`
- Signature:

```c
static psa_status_t psa_aead_setup(psa_aead_operation_t *operation,
                                   int is_encrypt,
                                   mbedtls_svc_key_id_t key,
                                   psa_algorithm_t alg);
```

## Parameter Semantics

- `operation`: caller-owned PSA AEAD operation.
- `is_encrypt`: nonzero for encrypt setup, zero for decrypt setup.
- `key`: PSA key identifier.
- `alg`: AEAD algorithm with optional shortened tag encoding.

## Return Value Semantics

- `PSA_SUCCESS`: setup succeeded and operation records base algorithm and direction.
- `PSA_ERROR_BAD_STATE`: operation already active or partially started.
- `PSA_ERROR_INVALID_ARGUMENT`: invalid key/algorithm compatibility or invalid tag length.
- `PSA_ERROR_NOT_SUPPORTED`: unsupported AEAD algorithm.
- Key-slot, policy, driver, memory, hardware, and storage errors may be propagated.

## Ownership and Buffer Constraints

- The helper locks the key slot, calls driver setup, then unlocks.
- On failure, it calls `psa_aead_abort(operation)`.
- Current source validates tag length before driver setup via `psa_validate_tag_length(alg)`.

## Harness Generation Notes

- Public harnesses should call `psa_aead_encrypt_setup()` or `psa_aead_decrypt_setup()`.
- White-box harnesses can inspect this helper only in source builds.
- The best oracle is return status from the public setup API.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0028`.
- The fixed statement is the setup-time `psa_validate_tag_length(alg)` check.
- Do not migrate this as a decrypt-final authentication failure; the pattern is invalid parameter acceptance during setup.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_psa_crypto.function`: `aead_multipart_setup` exercises both encrypt and decrypt setup status.
- `tf-psa-crypto/tests/suites/test_suite_psa_crypto_op_fail.generated.data`: generated setup/operation failures include invalid shortened CCM tag lengths.
