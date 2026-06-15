# Input Summary

```yaml
schema: mutation_policy_refinement_input_summary_v1
generated_at: '2026-06-12T08:08:52+00:00'
inputs:
  oracle_aware_analysis: artifacts/sprints/analyze_results_oracle_aware_v1/case_analysis/oracle_aware_case_analysis.yaml
  oracle_semantics: artifacts/sprints/analyze_results_oracle_aware_v1/oracle_semantics/oracle_semantics_summary.yaml
  mutation_effectiveness: artifacts/sprints/analyze_results_oracle_aware_v1/mutation_effectiveness/mutation_effectiveness.yaml
  original_mutation_case_matrix: artifacts/sprints/family_adapter_mutation_planner_v1/mutation_case_matrix/mutation_case_matrix.yaml
  rendered_case_index: artifacts/sprints/render_cases_v1/case_index/rendered_case_index.yaml
  instrumented_case_index: artifacts/sprints/oracle_instrumentation_enrichment_v1/case_index/instrumented_case_index.yaml
  family_template_root: normalized_templates/wolfssl_family
why_refinement_needed:
  accepted_true: 0
  accepted_false: 21
  all_cases_rejected: true
  reason: accepted_true=0 means current mutations did not reach successful parser paths; refinement should
    produce valid-prefix / near-valid / trailing-only variants.
full_consumption_false_policy: full_consumption=false on reject/error paths is not a full-consumption
  gap by itself.
scope:
  generate_supplemental_mutation_cases_only: true
  render: false
  compile: false
  run: false
  feedback: false
  glm: false
family_template_status:
  pkcs_container_parsing:
    mutation_slots: true
    oracle_plan: true
    selected_mask_units: true
  asn1_nested_boundary:
    mutation_slots: true
    oracle_plan: true
    selected_mask_units: true
```
