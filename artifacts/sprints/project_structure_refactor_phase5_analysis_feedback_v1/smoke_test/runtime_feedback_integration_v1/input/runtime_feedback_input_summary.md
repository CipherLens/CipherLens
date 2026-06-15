# Input Summary

```yaml
schema: runtime_feedback_integration_input_summary_v1
generated_at: '2026-06-12T09:39:18+00:00'
inputs:
  valid_prefix_pipeline_status: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/reports/pipeline_status.yaml
  valid_prefix_case_analysis: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/analyze/case_analysis/oracle_aware_case_analysis.yaml
  valid_prefix_family_analysis: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/analyze/family_analysis/oracle_aware_family_analysis.yaml
  valid_prefix_oracle_semantics: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/analyze/oracle_semantics/oracle_semantics_summary.yaml
  valid_prefix_mutation_effectiveness: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/analyze/mutation_effectiveness/mutation_effectiveness.yaml
  valid_prefix_candidate_labels: artifacts/sprints/valid_prefix_pipeline_to_analyze_v1/analyze/candidate_labels/oracle_aware_candidate_labels.yaml
  previous_oracle_aware_mutation_effectiveness: artifacts/sprints/analyze_results_oracle_aware_v1/mutation_effectiveness/mutation_effectiveness.yaml
  mutation_policy_refinement: artifacts/sprints/mutation_policy_refinement_for_valid_prefix_v1/policy_refinement/mutation_policy_refinement.yaml
  seed_inventory: artifacts/sprints/mutation_policy_refinement_for_valid_prefix_v1/seed_inventory/seed_inventory.yaml
  out_dir: artifacts/sprints/project_structure_refactor_phase5_analysis_feedback_v1/smoke_test/runtime_feedback_integration_v1
  staged_feedback_dir: artifacts/sprints/project_structure_refactor_phase5_analysis_feedback_v1/smoke_test/staged_feedback/runtime_feedback_integration_v1
pipeline_stages:
  render_plan:
    executed: true
    status: pass
    render_jobs: 6
  render_cases:
    executed: true
    status: pass
    rendered_cases: 6
  compile_run:
    executed: true
    status: pass
    compile_success: 6
    compile_failed: 0
    run_attempted: 6
    oracle_events: 18
  analyze:
    executed: true
    status: pass
    cases_analyzed: 6
    accepted_true: 5
    accepted_false: 1
    full_consumption_gap_candidates: 3
case_analysis_cases: 6
pkcs_seed_available: false
scope:
  offline_only: true
  oracle_semantic_triage_performed: false
  staged_feedback_only: true
  main_knowledge_written: false
```
