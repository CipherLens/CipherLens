# Cross Library Feasibility

- mbedTLS available: yes (`mbedtls-4.1.0`, `mbedtls-3.6.4`)
- Botan available: source yes; build artifacts no
- selected mbedTLS API: PSA AEAD multipart

## Mapping

- `final_without_update`: maps to `psa_aead_finish()` after zero data updates.
- `set_tag_after_final`: mapping_gap; PSA uses `psa_aead_verify(tag)` as finalization and has no post-final tag setter.
- `wrong_tag_length`: maps to shortened-tag GCM via `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8)`.

## Suitability

- A-path recipe-slot migration: not recommended yet; this is semantic cross-check evidence, not a stable vulnerability-path migration.
- semantic cross-check: suitable.
