# Mutation Input Summary

## Inputs Read

- `cipher_aead_lifecycle_triage_report.md`
- `cipher_aead_lifecycle_triage_report.yaml`
- `aead_lifecycle_mutation_plan.yaml`
- `aead_lifecycle_render_matrix_draft.yaml`
- `aead_api_group_report.md`
- `aead_lifecycle_pattern_abstraction.md`

## Selected Cases

This sprint selects 12 cases from the 24-case draft matrix.

Normal controls:

- `aead_000_normal_encrypt_gcm`
- `aead_001_normal_decrypt_gcm`

Mutation cases:

- `aead_004_repeated_final_gcm_encrypt`
- `aead_005_update_after_final_gcm_encrypt`
- `aead_006_final_without_update_gcm_encrypt`
- `aead_007_get_tag_before_final_gcm_encrypt`
- `aead_009_set_tag_after_final_gcm_decrypt`
- `aead_010_aad_after_data_update_gcm_encrypt`
- `aead_011_decrypt_without_set_tag_gcm`
- `aead_012_wrong_tag_length_gcm_decrypt`
- `aead_013_ctx_reuse_after_final_gcm_encrypt`
- `aead_014_cleanup_then_update_gcm`

## Why These Cases

The selected set prioritizes `aes-128-gcm`, runs normal controls first, and then
covers terminal-state reuse, operation ordering, tag timing, missing tag, wrong
tag length, context reuse, and cleanup-then-use.

If normal controls fail, mutation interpretation stops.
