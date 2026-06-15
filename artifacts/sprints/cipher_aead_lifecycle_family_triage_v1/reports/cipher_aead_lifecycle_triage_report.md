# cipher_aead_lifecycle Family Triage Report

## Why This Family

`cipher_aead_lifecycle` was selected because the scheduler rerank after
`secure_heap_state_lifecycle` closure recommended it as the next main exploration
family. It has multiple historical seeds and a good fit with lifecycle lessons
from MAC and secure heap work.

## Historical Seeds

- `MBEDTLS-POC-0004`: invalid padding output length on cipher finalization.
- `MBEDTLS-POC-0028`: missing AEAD tag length validation from PSA drivers.
- `OPENSSL-ISSUE-17715`: incomplete cipher state before update path.
- `OPENSSL-ISSUE-8980`: EVP AES-GCM context copy / uninitialized state.

## RAG Evidence

RAG recalled OpenSSL EVP AEAD constraints and unit-test evidence, including GCM
and EVP init/update/final/tag-control behavior. It also recalled `MBEDTLS-POC-0028`
and PSA AEAD tag-length setup evidence.

The evidence partially supports A-path, but the initial route should be B-path
because mode-specific ordering and tag semantics are not yet recipe-slot precise.

## API Groups

OpenSSL EVP AEAD:

- init: `EVP_EncryptInit_ex`, `EVP_DecryptInit_ex`
- AAD/data update: `EVP_EncryptUpdate`, `EVP_DecryptUpdate`
- final: `EVP_EncryptFinal_ex`, `EVP_DecryptFinal_ex`
- tag set/get: `EVP_CIPHER_CTX_ctrl`
- cleanup/reuse: `EVP_CIPHER_CTX_free`, `EVP_CIPHER_CTX_reset`, reinit/copy

mbedTLS / PSA AEAD:

- setup: `psa_aead_encrypt_setup`, `psa_aead_decrypt_setup`
- AAD/data update: `psa_aead_update_ad`, `psa_aead_update`
- finish/verify: `psa_aead_finish`, `psa_aead_verify`
- GCM/CCM helpers: `mbedtls_gcm_*`, `mbedtls_ccm_*`
- cleanup: `psa_aead_abort`, `mbedtls_gcm_free`, `mbedtls_ccm_free`

## Root Cause Hypotheses

- terminal state reuse
- tag order mismatch
- AAD/data order mismatch
- init failure followed by operation
- cleanup/free followed by reuse
- encrypt/decrypt mode confusion
- invalid tag length acceptance
- error-path output state pollution

## Mutation Points

- operation order
- tag length
- tag set/get timing
- AAD timing
- repeated final
- context reuse
- decrypt verify path
- cleanup timing

## Oracles

- `strict_bad_state_reject`
- `permissive_terminal_reuse`
- `crash_or_sanitizer`
- `unexpected_success`
- `semantic_divergence`
- `normal_defined_behavior`

## Execution Route

```text
recommended_path: B_controlled_family_mutation
fallback_path: D_then_A
```

GLM was not used. This sprint did not run cases. It produced a 24-case draft
matrix for the next sprint.

## Vulnerability Conclusion

No new vulnerability was found or claimed in this sprint.

Next task:

```text
cipher_aead_lifecycle_mutation_v1
```
