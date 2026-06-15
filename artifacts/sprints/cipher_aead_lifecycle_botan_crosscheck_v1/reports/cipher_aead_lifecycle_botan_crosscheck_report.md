# Cipher AEAD Lifecycle Botan Crosscheck Report

- Botan local build available: yes
- Botan version: 3.10.0
- pkg-config: `-I/home/wen/work/clean_sources/botan-3.10.0/_install/include/botan-3 -L/home/wen/work/clean_sources/botan-3.10.0/_install/lib -lbotan-3 -fstack-protector -m64 -pthread`
- compile_status: ok
- run_status: ok
- exit_code: 0

## Candidate Results

- `aead_006_final_without_update_gcm_encrypt`: Botan `finish()` on empty plaintext with AAD succeeded and produced output size 16; classification `legal_semantics`.
- `aead_009_set_tag_after_final_gcm_decrypt`: no Botan post-final SET_TAG equivalent found; classification `mapping_gap`, retaining prior `permissive_but_harmless` cross-library judgment.
- `aead_012_wrong_tag_length_gcm_decrypt`: Botan `AES-128/GCM(8)` encrypted/decrypted successfully with plaintext match; classification `legal_semantics`.

## Claim Boundary

- semantic_divergence_candidate: no
- crash_candidate: no
- D-path needed: no
- A-path needed: no
- confirmed vulnerability: no

## Next Step

Keep these three candidates downgraded. Return to scheduler or expand AEAD lifecycle exploration to CCM / ctx copy / init-failure.
