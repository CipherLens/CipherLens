# MAC Lifecycle GLM Full A-Path Completion

## Conclusion

MAC lifecycle has now completed the GLM-assisted full A-path:

```text
GLM slot filling -> adapter_validate -> cross_generator_from_adapters -> render_cases -> compile_run -> generic analyze_results/analyze_cross_results.
```

- `can_claim_glm_used_in_a_path`: `true`
- `can_claim_full_a_path_compliant`: `true`
- manual adapter used: `false`
- GLM reinvoked in this sprint: `false`
- old controlled renderer used as main path: `false`

## Standard Results

- total_cases: `8`
- raw_status_counts: `{"run_ok": 8}`
- verdict_counts: `{"safe_reject_behavior": 6, "normal_behavior_needs_triage": 2}`
- total_pairs: `4`
- migration_verdict_counts: `{"migrated_safe": 2, "migration_needs_triage": 2}`
- crash evidence: `none`

## What Was Extended

- `template_maker/cross_generator_from_adapters.py`
  - Added sprint-local `source_template/` path resolution.
  - Added reusable `mac_lifecycle` recipe renderer.
  - Generates standard `tmpl_openssl.c` and `tmpl_mbedtls.c` pair templates from GLM `slot_bindings`.

- `runner/analyze_results.py`
  - Added generic `mac_lifecycle` verdict rules for `lifecycle_state_transition_semantic_oracle`.

- `runner/compile_run.py`
  - Maps aggregate `cross_library` metadata back to the detected concrete library for result metadata.

## Semantic Interpretation

The standard run covers:

- `normal_init_update_final`
- `repeated_final`
- `update_after_final`
- `abort_then_update`

The normal and abort-then-update pairs are `migrated_safe`. The repeated-final and update-after-final pairs are `migration_needs_triage` because OpenSSL accepts terminal-state reuse while mbedTLS PSA rejects with a bad-state-like status. This is semantic divergence evidence, not a confirmed vulnerability.

No ASAN, UBSAN, SEGV, canary corruption, or explicit unsafe output-state evidence was observed.
