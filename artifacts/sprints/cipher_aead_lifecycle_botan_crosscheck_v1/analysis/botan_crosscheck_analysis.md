# Botan Crosscheck Analysis

- semantic_divergence_candidate_count: 0
- crash_candidate_count: 0
- confirmed vulnerability found: false
- needs D-path: false
- needs A-path: false

## Classification

- `aead_006_final_without_update_gcm_encrypt`: `legal_semantics`
- `aead_009_set_tag_after_final_gcm_decrypt`: `mapping_gap`; prior `permissive_but_harmless` remains appropriate.
- `aead_012_wrong_tag_length_gcm_decrypt`: `legal_semantics`
