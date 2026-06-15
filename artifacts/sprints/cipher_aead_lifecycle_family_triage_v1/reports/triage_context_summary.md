# Triage Context Summary

## Why `cipher_aead_lifecycle`

The scheduler selected `cipher_aead_lifecycle` after `secure_heap_state_lifecycle`
was closed for the main exploration track and moved to external validation.
The family scored highest among the next candidates because it has several
existing seeds, clear lifecycle/state-machine structure, and observable oracles.

Existing seed families include:

- `MBEDTLS-POC-0004`
- `MBEDTLS-POC-0028`
- `OPENSSL-ISSUE-17715`
- `OPENSSL-ISSUE-8980`

## Reusable Lessons

From `mac_lifecycle`:

- Terminal-looking `final` behavior may differ across APIs.
- Repeated final or update-after-final is not automatically a vulnerability.
- Return code, output length, and output state must be interpreted together.

From `secure_heap_state_lifecycle`:

- Same-family state expansion can find new state combinations.
- Safe controls are mandatory.
- Contract, sanitizer, and version evidence should remain separate validation
  tracks.

## Possible Routes

- `A_recipe_slot_cross_library_migration`: feasible later if EVP AEAD and
  mbedTLS PSA/GCM/CCM mappings become recipe-slot precise.
- `B_controlled_family_mutation`: recommended first path.
- `C_app_level_validation_gap`: only if the evidence shifts to CLI/app behavior.
- `D_crash_sanitizer_evidence_audit`: useful for OpenSSL crash/sanitizer seeds.

## Why Triage First

This family mixes CBC padding finalization, AEAD setup/tag length, and EVP context
state issues. Rendering immediately would blur root causes and oracles. This
sprint therefore builds inventory, API groups, root-cause hypotheses, mutation
points, and a draft matrix without running cases.
