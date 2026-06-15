# mac_lifecycle_register_and_full_pipeline_v1 Report

## Selection

- source recommendation: artifacts/reports/family_inventory_registry_reconcile_v2/next_family_recommendation.yaml
- selected family: mac_lifecycle
- selected track: lifecycle
- selected archetype: mac_context_lifecycle
- target library: openssl
- newly registered: true

## Baseline

- rag_glm_baseline_loaded: True
- slot_bindings_schema_valid: True
- adapter_validate_passed: True
- mapping_gate_bypassed: False
- api_key_logged: False

## Pipeline Results

- enabled seeds: 6
- mutation cases: 8
- rendered cases: 8
- compile success: 8
- compile failed: 0
- run attempted: 8
- oracle events parsed: True

## Candidate Queue

- candidate_count: 0
- unexpected_success_after_invalid_state_count: 0
- unexpected_failure_on_valid_sequence_count: 0
- semantic_divergence_count: 0
- crash_candidate_count: 0
- sanitizer_candidate_count: 0
- needs_triage_count: 0

## Policy Checks

No DER parsing, trailing-garbage input, full-consumption oracle, unsafe UAF execution,
main feedback write, pattern-bank update, git operation, or confirmed vulnerability
claim was made. Observation behavior is recorded as observation only.

## Quality

- quality_status: pass_no_candidate
