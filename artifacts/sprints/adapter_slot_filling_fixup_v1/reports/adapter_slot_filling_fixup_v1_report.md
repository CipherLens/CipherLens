# Adapter Slot Filling Fixup V1 Report

```yaml
schema: adapter_slot_filling_fixup_v1_report
generated_at: '2026-06-11T15:08:28+00:00'
only_fixed_pkcs_container_parsing_openssl: true
previous_failure_reason:
- plan_echo
- missing_cleanup_mapping
- missing_oracle_mapping
- missing_input_mapping
- missing_mutation_slot_mapping
glm_called: true
glm_available: true
glm_call_error: null
glm_output_plan_echo: false
fixed_slot_bindings_generated: true
fixed_slot_bindings_validation_status: pass
c_generation_detected: false
blocked_api_used: false
confirmed_equivalence_claim: false
adapter_recipes_old_file_overwritten: false
proposed_replacement: artifacts/sprints/adapter_slot_filling_fixup_v1/write_summary/proposed_replacement/adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/slot_bindings.yaml
next_task_name: apply_pkcs_slot_bindings_and_adapter_validate_v1
actions_not_performed:
  run_poc: false
  render: false
  compile_run: false
  generated_c: false
  pattern_bank_modified: false
  scheduler_seed_modified: false
  knowledge_raw_modified: false
  knowledge_base_modified: false
validation:
  adapter_id: pkcs_container_parsing_openssl
  slot_bindings_exists: true
  binding_status: filled_by_glm
  all_required_top_level_fields_present: true
  api_mapping_present: true
  api_mapping_nonempty: true
  cleanup_mapping_present: true
  cleanup_mapping_nonempty: true
  oracle_mapping_present: true
  oracle_mapping_nonempty: true
  input_mapping_present: true
  mutation_slot_mapping_present: true
  blocked_targets_respected: true
  no_confirmed_equivalence_claim: true
  no_c_generation_detected: true
  allowed_target_apis_only: true
  plan_echo_detected: false
  selected_trigger_apis:
  - PKCS12_parse
  - PKCS7_verify
  cleanup_apis:
  - PKCS12_free
  - PKCS7_free
  forbidden_api_used: []
  validation_status: pass
  notes: []
```
