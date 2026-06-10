# MAC Lifecycle A-Path Compliance Audit

## Conclusion

- final_compliance_status: `full_a_path_compliant`
- can_continue_to_d_path: `true`

MAC lifecycle has now completed the GLM-assisted full A-path:

```text
GLM slot filling -> adapter_validate -> cross_generator_from_adapters -> render_cases -> compile_run -> generic analyze_results/analyze_cross_results.
```

## GLM Slot-Filling Verification

- status: `verified`
- reason: `GLM strict recipe-slot filling produced _llm_status=ok and adapter_validate status ok.`
- can_claim_glm_used_in_a_path: `true`
- can_claim_full_a_path_compliant: `true`
- report: `artifacts/sprints/mac_lifecycle_family_v1/llm_slot_filling_verification/glm_slot_filling_report.yaml`

`migration.adapter_filler` was run in strict recipe mode with `--use-llm`, `--adapter-recipe`, and `--require-recipes`. The generated GLM adapter has `_adapter_mode: recipe_slot_filling`, `_llm_status: ok`, `slot_bindings`, no disallowed free-form block fields, and no manual/fallback markers. `migration.adapter_validate` accepted the adapter with `status: ok` and `needs_repair: 0`.

This verifies the LLM/GLM slot-filling step, and the validated GLM adapter has now been routed through the remaining standard `cross_generator_from_adapters`, `render_cases`, compile/run, and generic analysis chain.

## Critical Deviations

None for the completed full A-path run.

## Acceptable Shortcuts

- selected_mask_units are preserved as trace context
- verified GLM recipe-slot bindings avoid free-form C generation

## Must Fix Before Claiming Full A-Path

None.

## Full A-Path Result

- report: `artifacts/migrations/mac_lifecycle_glm_full_a_path/full_a_path_completion_report.yaml`
- total_cases: `8`
- raw_status_counts: `{"run_ok": 8}`
- verdict_counts: `{"safe_reject_behavior": 6, "normal_behavior_needs_triage": 2}`
- total_pairs: `4`
- migration_verdict_counts: `{"migrated_safe": 2, "migration_needs_triage": 2}`
- crash evidence: `none`

The two triage pairs are OpenSSL repeated-final and update-after-final permissive behavior relative to mbedTLS PSA bad-state rejection. They are semantic triage results, not vulnerability claims.

## Step Audit

| step | status | manual shortcut | violates runbook | evidence |
| --- | --- | --- | --- | --- |
| `real_poc_or_issue_seed` | `present` | `false` | `false` | OPENSSL-ISSUE-22842 pattern seed is available. |
| `root_cause_or_oracle_extraction` | `present` | `false` | `false` | Pattern YAML records root_cause and mac_context_size_lifecycle_oracle. |
| `poc_pattern_knowledge` | `present` | `false` | `false` | PoC pattern knowledge exists under knowledge_raw. |
| `normalized_source_template` | `present` | `false` | `false` | MAC lifecycle source template exists in sprint source_template. |
| `template_meta` | `present` | `false` | `false` | Template metadata exists. |
| `mask_report` | `present` | `false` | `false` | Mask report exists. |
| `ast_mask_report` | `present` | `false` | `false` | AST report exists in main-chain or migration artifacts. |
| `selected_mask_units` | `present` | `false` | `false` | Selected mask units are available and validator records them as trace context. |
| `rag_evidence` | `present` | `false` | `false` | RAG evidence JSON files are present. |
| `candidates_yaml` | `present` | `false` | `false` | Sprint-local candidates.yaml is present for the MAC lifecycle recipe-slot verification. |
| `candidates_with_evidence` | `present` | `false` | `false` | candidates_with_evidence.yaml is present in main-chain artifacts. |
| `adapter_recipe` | `present` | `false` | `false` | Reusable MAC lifecycle recipe exists. |
| `llm_slot_bindings_only` | `present` | `false` | `false` | GLM adapter_filler strict recipe mode produced _llm_status='ok', _adapter_mode='recipe_slot_filling', slot_bindings present, and disallowed free-form blocks present=False. |
| `adapter_yaml` | `present` | `false` | `false` | Structured adapter.yaml exists. |
| `adapter_validate` | `present` | `false` | `false` | adapter_validate report and validated adapter exist. |
| `cross_generator_from_adapters` | `present` | `false` | `false` | Standard template_maker.cross_generator_from_adapters generated OpenSSL and mbedTLS PSA pair templates from the validated GLM adapter. |
| `render_cases` | `present` | `false` | `false` | Standard template_maker.render_cases rendered four lifecycle sequences into eight source files. |
| `compile_run` | `present` | `false` | `false` | Standard runner.compile_run compiled and ran 8 cases with raw_status_counts {'run_ok': 8}. |
| `analyze_results` | `present` | `false` | `false` | Generic runner.analyze_results produced verdict_counts {'safe_reject_behavior': 6, 'normal_behavior_needs_triage': 2}. |
| `analyze_cross_results` | `present` | `false` | `false` | Generic runner.analyze_cross_results produced 4 pairs with {'migrated_safe': 2, 'migration_needs_triage': 2}. |

## Reason

MAC lifecycle has now completed the GLM-assisted full A-path. It preserves template, mask, selected_mask_units, recipe-slot adapter shape, adapter validation, standard cross generation, standard rendering, compile/run, and generic analysis. The remaining semantic interpretation is triage for OpenSSL permissive terminal-state reuse, not a confirmed vulnerability.
