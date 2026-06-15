# apply_pkcs_slot_bindings_and_adapter_validate_v1

```yaml
schema: apply_pkcs_slot_bindings_and_adapter_validate_v1_report
generated_at: '2026-06-11T15:17:08+00:00'
pkcs_fixed_slot_bindings_applied: true
old_file_backed_up: true
only_pkcs_slot_bindings_overwritten: true
adapter_recipe_yaml_modified: false
slot_filling_plan_yaml_modified: false
adapter_validate_results:
- adapter_id: pkcs_container_parsing_openssl
  family: pkcs_container_parsing
  target_library: openssl
  adapter_recipe_exists: true
  slot_filling_plan_exists: true
  slot_bindings_exists: true
  binding_status: filled_by_glm
  render_ready: true
  required_top_level_fields_present: true
  api_mapping_nonempty: true
  cleanup_mapping_nonempty: true
  oracle_mapping_nonempty: true
  input_mapping_present: true
  mutation_slot_mapping_present: true
  blocked_targets_respected: true
  allowed_target_apis_only: true
  no_confirmed_equivalence_claim: true
  no_c_generation_detected: true
  candidate_mapping_not_promoted: true
  adapter_recipe_not_modified: true
  slot_filling_plan_not_modified: true
  selected_apis:
  - PKCS12_parse
  - PKCS7_verify
  cleanup_apis:
  - PKCS12
  - PKCS12_free
  - PKCS7
  - PKCS7_free
  forbidden_apis_used: []
  forbidden_terms_used: []
  validation_status: pass
  notes: []
- adapter_id: asn1_nested_boundary_openssl
  family: asn1_nested_boundary
  target_library: openssl
  adapter_recipe_exists: true
  slot_filling_plan_exists: true
  slot_bindings_exists: true
  binding_status: blocked_by_mapping_gate
  render_ready: false
  required_top_level_fields_present: true
  api_mapping_nonempty: true
  cleanup_mapping_nonempty: false
  oracle_mapping_nonempty: false
  input_mapping_present: false
  mutation_slot_mapping_present: true
  blocked_targets_respected: true
  allowed_target_apis_only: true
  no_confirmed_equivalence_claim: true
  no_c_generation_detected: true
  candidate_mapping_not_promoted: true
  adapter_recipe_not_modified: true
  slot_filling_plan_not_modified: true
  selected_apis: []
  cleanup_apis: []
  forbidden_apis_used: []
  forbidden_terms_used: []
  validation_status: fail
  notes:
  - adapter expected pass but binding_status is blocked
  - cleanup_mapping empty
  - oracle_mapping empty
- adapter_id: asn1_nested_boundary_mbedtls
  family: asn1_nested_boundary
  target_library: mbedtls
  adapter_recipe_exists: true
  slot_filling_plan_exists: true
  slot_bindings_exists: true
  binding_status: blocked_by_mapping_gate
  render_ready: false
  required_top_level_fields_present: true
  api_mapping_nonempty: true
  cleanup_mapping_nonempty: false
  oracle_mapping_nonempty: false
  input_mapping_present: false
  mutation_slot_mapping_present: true
  blocked_targets_respected: true
  allowed_target_apis_only: true
  no_confirmed_equivalence_claim: true
  no_c_generation_detected: true
  candidate_mapping_not_promoted: true
  adapter_recipe_not_modified: true
  slot_filling_plan_not_modified: true
  selected_apis: []
  cleanup_apis: []
  forbidden_apis_used: []
  forbidden_terms_used: []
  validation_status: blocked_expected
  notes: []
render_ready_adapters:
- adapter_id: pkcs_container_parsing_openssl
  family: pkcs_container_parsing
  target_library: openssl
  reason: validation pass; render may be planned next but not run in this sprint
blocked_expected_adapters:
- adapter_id: asn1_nested_boundary_mbedtls
  family: asn1_nested_boundary
  target_library: mbedtls
  reason: blocked placeholder preserved; render_ready=false
not_ready_adapters:
- adapter_id: asn1_nested_boundary_openssl
  family: asn1_nested_boundary
  target_library: openssl
  reason: adapter expected pass but binding_status is blocked; cleanup_mapping empty;
    oracle_mapping empty
run_poc: false
render: false
compile_run: false
generated_c: false
glm: false
pattern_bank_modified: false
scheduler_seed_modified: false
knowledge_raw_modified: false
next_task_name: adapter_slot_filling_regression_fixup_v1
```
