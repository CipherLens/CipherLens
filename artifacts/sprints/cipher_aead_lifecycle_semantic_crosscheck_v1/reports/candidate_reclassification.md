# Candidate Reclassification

- `aead_006_final_without_update_gcm_encrypt`: `legal_semantics` / `legal_semantics`. downgrade; keep as negative feedback for AEAD lifecycle scheduler.
- `aead_009_set_tag_after_final_gcm_decrypt`: `permissive_but_harmless` / `permissive_but_harmless`. do not promote to A-path; optional version matrix only if older OpenSSL state handling is suspected.
- `aead_012_wrong_tag_length_gcm_decrypt`: `legal_semantics` / `legal_semantics`. downgrade; rename future case from wrong_tag_length to truncated_tag_length unless using truly invalid lengths.
