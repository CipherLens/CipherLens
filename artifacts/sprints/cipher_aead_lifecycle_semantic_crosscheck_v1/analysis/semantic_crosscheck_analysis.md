# AEAD Lifecycle Semantic Crosscheck Analysis

- mbedTLS cases: 3
- mbedTLS raw_status_counts: `{'run_ok': 3}`
- mbedTLS classification_counts: `{'legal_semantics': 2, 'mapping_gap': 1}`
- Botan completed: false
- confirmed vulnerability found: false

## Reclassification

- `aead_006_final_without_update_gcm_encrypt`: `semantic_divergence_candidate` -> `legal_semantics`; claim `legal_semantics`
- `aead_009_set_tag_after_final_gcm_decrypt`: `permissive_behavior` -> `permissive_but_harmless`; claim `permissive_but_harmless`
- `aead_012_wrong_tag_length_gcm_decrypt`: `semantic_divergence_candidate` -> `legal_semantics`; claim `legal_semantics`
