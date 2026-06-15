# Cipher AEAD Lifecycle Semantic Crosscheck Report

## Checked Candidates

- `aead_006_final_without_update_gcm_encrypt`: `semantic_divergence_candidate` -> `legal_semantics`
- `aead_009_set_tag_after_final_gcm_decrypt`: `permissive_behavior` -> `permissive_but_harmless`
- `aead_012_wrong_tag_length_gcm_decrypt`: `semantic_divergence_candidate` -> `legal_semantics`

## OpenSSL Evidence

- `final_without_update`: legal empty-message/AAD-only GCM encryption behavior; final may produce no ciphertext and still produce a tag.
- `set_tag_after_final`: docs require tag before decrypt final; source indicates post-final ctrl success is permissive state behavior, not proof of changed authentication.
- `wrong_tag_length`: 8-byte tag is allowed truncated-tag GCM under OpenSSL because decrypt SET_TAG permits 1..16 bytes.
- doc evidence: sufficient for the three targeted questions.

## Cross Library

- mbedTLS: completed with PSA AEAD multipart/one-shot cases.
- Botan: not completed; source exists but required build artifacts were not found.
- mapping_gap: PSA has no post-final tag setter equivalent to OpenSSL `EVP_CTRL_GCM_SET_TAG`.

## Reclassification

- `aead_006_final_without_update_gcm_encrypt`: claim `legal_semantics`; next: downgrade; keep as negative feedback for AEAD lifecycle scheduler.
- `aead_009_set_tag_after_final_gcm_decrypt`: claim `permissive_but_harmless`; next: do not promote to A-path; optional version matrix only if older OpenSSL state handling is suspected.
- `aead_012_wrong_tag_length_gcm_decrypt`: claim `legal_semantics`; next: downgrade; rename future case from wrong_tag_length to truncated_tag_length unless using truly invalid lengths.

## Safety Claim Boundary

- confirmed vulnerability: no
- CVE claim: no
- exploitable claim: no
- crash_candidate: no
- ASAN/UBSAN needed: no for current evidence
- version matrix: optional only if older OpenSSL behavior becomes relevant
- A-path recipe-slot migration: not supported for these three candidates

## Next Step

Return to scheduler, or broaden AEAD research to CCM / ctx copy / init-failure rather than promoting these GCM observations.
