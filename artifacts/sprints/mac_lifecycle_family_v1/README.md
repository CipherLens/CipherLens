# MAC Lifecycle Family v1 Runnable Sprint

This sprint promotes `mac_lifecycle` from preparation to a runnable recipe-slot A-path family. It is not a confirmed vulnerability report and it does not claim a CVE.

## Why MAC Lifecycle

MAC APIs expose state-sensitive transitions: init/setup, update, final, repeated final, update after final, abort/reset, and cleanup. Prior evidence linked OpenSSL CMAC lifecycle behavior, `OPENSSL-ISSUE-22842`, and mbedTLS PSA strict bad-state behavior. That makes the family useful for cross-library lifecycle semantic migration.

## A-Path Evidence Chain

This sprint keeps the recipe-slot migration chain:

- AST-lite style mask context: `mask/mask_report.yaml`
- selected mask units: `mask/selected_mask_units.yaml`
- RAG evidence: `evidence/*.json`
- recipe-slot adapter: `recipe/adapter.yaml`
- adapter validation: `recipe/adapter_validate_report.json`
- controlled renderer: `mutation.apply_mac_lifecycle_matrix_to_template`
- rendered cases: `rendered_cases/`
- compile/run/analyze outputs: `results/`

No LLM free-form C harness generation was used.

## Mutation Dimensions

The v1 render matrix uses 48 cases:

- `lifecycle_sequence`: `normal_init_update_final`, `repeated_final`, `update_after_final`, `abort_then_update`
- `algorithm`: `cmac_aes`
- `input_length`: `0`, `1`, `16`, `64`
- `key_length`: `valid`, `zero`, `short`

Each case renders an OpenSSL side and an mbedTLS PSA side, with a `case_manifest.yaml`.

## Results

Total cases: 48

Verdict counts:

- `behavior_divergence_candidate`: 8
- `normal_success`: 4
- `strict_bad_state`: 4
- `needs_manual_triage`: 32
- `harness_error`: 0
- `permissive_legacy_behavior`: 0

The stable divergence candidates are valid-key `repeated_final` and `update_after_final` cases. OpenSSL CMAC can accept continued operation after a terminal-looking finalization, while mbedTLS PSA rejects post-finish operations with bad-state-like status.

The `zero` and `short` key cases are classified as `needs_manual_triage` because key import/init fails before reaching the lifecycle oracle. `abort_then_update` is partly a projection limitation on the OpenSSL side because EVP_MAC does not expose a direct PSA-style abort API.

## Interpretation

The observed result is a lifecycle semantic divergence candidate. It is not a crash, not a confirmed vulnerability, and not a CVE. OpenSSL permissive behavior may be provider or legacy semantics; it needs documentation review and caller-impact analysis before any stronger claim.

## Next Triage

1. Minimize valid-key repeated-final and update-after-final cases.
2. Check OpenSSL EVP_MAC/CMAC documentation for intended post-final semantics.
3. Identify caller contexts where finalization is assumed to be terminal.
4. Keep zero/short key cases as setup-validation triage, not lifecycle divergence evidence.
