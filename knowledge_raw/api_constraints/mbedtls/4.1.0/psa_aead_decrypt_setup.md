# API Constraints: psa_aead_decrypt_setup (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `psa_aead_decrypt_setup`
- Header declaration: `tf-psa-crypto/include/psa/crypto.h`
- Implementation file: `tf-psa-crypto/core/psa_crypto.c`
- Signature:

```c
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg);
```

## Parameter Semantics

- `operation`: initialized inactive AEAD operation object.
- `key`: key identifier that must remain valid until the operation terminates and must allow `PSA_KEY_USAGE_DECRYPT`.
- `alg`: AEAD algorithm; may include `PSA_ALG_AEAD_WITH_SHORTENED_TAG(...)`.

## Return Value Semantics

- `PSA_SUCCESS`: operation set up for authenticated decryption.
- `PSA_ERROR_BAD_STATE`: crypto subsystem not initialized or operation already active.
- `PSA_ERROR_INVALID_HANDLE`, `PSA_ERROR_NOT_PERMITTED`: key lookup/policy failures.
- `PSA_ERROR_INVALID_ARGUMENT`: key is incompatible with algorithm or tag length is invalid for the selected AEAD algorithm.
- `PSA_ERROR_NOT_SUPPORTED`: unsupported or non-AEAD algorithm.

## Ownership and Buffer Constraints

- The operation object remains caller-owned.
- On setup failure, current source aborts/resets the operation.
- Key storage remains managed by PSA; callers destroy keys separately with `psa_destroy_key()`.

## Harness Generation Notes

- Initialize PSA, import an AES key with `PSA_KEY_USAGE_DECRYPT`, set algorithm policy, then call setup.
- For `MBEDTLS-POC-0028`, use `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3)` and expect `PSA_ERROR_INVALID_ARGUMENT` in current/fixed source.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0028`.
- The migration feature is setup-time rejection of algorithm-specific invalid shortened AEAD tag lengths.
- Target APIs should support configuring AEAD tag length before decrypt and expose invalid-parameter status before full authentication.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_psa_crypto.function`: many `psa_aead_decrypt_setup()` direct calls.
- `tf-psa-crypto/tests/suites/test_suite_psa_crypto_op_fail.generated.data`: generated invalid-parameter cases for `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM,63)`.
- `tf-psa-crypto/tests/suites/test_suite_psa_crypto_driver_wrappers.function`: driver wrapper setup status propagation.
