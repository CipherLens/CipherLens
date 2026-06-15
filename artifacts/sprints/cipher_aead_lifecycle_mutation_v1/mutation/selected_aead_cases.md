# Selected AEAD Cases

This sprint selects 12 high-value cases from the 24-case draft matrix. It does
not run the full draft matrix.

## Selection Rationale

- Run normal controls first.
- Prioritize `aes-128-gcm`.
- Cover terminal-state reuse, tag timing, AAD ordering, missing tag, wrong tag
  length, context reuse, and cleanup-then-use.
- Keep the first mutation run compact enough for manual triage.

## Normal Controls

- `aead_000_normal_encrypt_gcm`
- `aead_001_normal_decrypt_gcm`

If either normal control fails, mutation conclusions must stop.

## Mutation Cases

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

All mutation verdicts must be interpreted as expected reject, permissive
behavior, semantic divergence candidate, crash candidate, or needs triage. No
case can be promoted directly to confirmed vulnerability.
