# Adapter Slot Filling V1 Report

```yaml
schema: adapter_slot_filling_v1_report
generated_at: '2026-06-11T14:04:52+00:00'
input_summary: artifacts/sprints/adapter_slot_filling_v1/input/adapter_slot_filling_input_summary.yaml
glm_inventory: artifacts/sprints/adapter_slot_filling_v1/glm_inventory/glm_slot_filling_tooling_inventory.yaml
validation:
  schema: slot_binding_validation_results_v1
  generated_at: '2026-06-11T14:04:52+00:00'
  total: 3
  status_counts:
    fail: 1
    pass: 1
    blocked: 1
  results:
  - adapter_id: pkcs_container_parsing.openssl.family_adapter_recipe_v1
    family: pkcs_container_parsing
    target_library: openssl
    binding_status: filled_by_glm
    validation_status: fail
    errors:
    - no selected target API in api_mapping
    - cleanup_mapping is required but empty
    - oracle_mapping is required but empty
    - GLM returned the slot filling plan rather than slot bindings
    warnings:
    - validation_notes does not explicitly include no_confirmed_equivalence_claim=true
    selected_target_apis: []
    required_fields_present: true
    cleanup_mapping_present: false
    oracle_mapping_present: false
    blocked_targets_respected: true
    no_c_generation_detected: true
    no_confirmed_equivalence_claim: true
  - adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
    family: asn1_nested_boundary
    target_library: openssl
    binding_status: candidate
    validation_status: pass
    errors: []
    warnings: []
    selected_target_apis:
    - ASN1_item_d2i
    required_fields_present: true
    cleanup_mapping_present: true
    oracle_mapping_present: true
    blocked_targets_respected: true
    no_c_generation_detected: true
    no_confirmed_equivalence_claim: true
  - adapter_id: asn1_nested_boundary.mbedtls.family_adapter_recipe_v1
    family: asn1_nested_boundary
    target_library: mbedtls
    binding_status: blocked_by_mapping_gate
    validation_status: blocked
    errors: []
    warnings: []
    selected_target_apis: []
    required_fields_present: true
    cleanup_mapping_present: false
    oracle_mapping_present: false
    blocked_targets_respected: true
    no_c_generation_detected: true
    no_confirmed_equivalence_claim: true
  required_fields_present: true
  cleanup_mapping_present: true
  oracle_mapping_present: true
  blocked_targets_respected: true
  no_c_generation_detected: true
  no_confirmed_equivalence_claim: true
write_summary:
  schema: slot_bindings_write_summary_v1
  generated_at: '2026-06-11T14:04:52+00:00'
  write_enabled: true
  written_count: 0
  collision_count: 3
  draft_only_count: 3
  adapter_recipe_yaml_modified: false
  slot_filling_plan_yaml_modified: false
  records:
  - adapter_id: pkcs_container_parsing.openssl.family_adapter_recipe_v1
    family: pkcs_container_parsing
    target_library: openssl
    write_attempted: true
    source_path: artifacts/sprints/adapter_slot_filling_v1/slot_bindings/pkcs_container_parsing/openssl/slot_bindings.yaml
    target_path: adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/slot_bindings.yaml
    written: false
    collision: true
    draft_only: true
    draft_path: artifacts/sprints/adapter_slot_filling_v1/write_summary/draft_slot_bindings/pkcs_container_parsing/openssl/slot_bindings.yaml
  - adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
    family: asn1_nested_boundary
    target_library: openssl
    write_attempted: true
    source_path: artifacts/sprints/adapter_slot_filling_v1/slot_bindings/asn1_nested_boundary/openssl/slot_bindings.yaml
    target_path: adapter_recipes/wolfssl_family/asn1_nested_boundary/openssl/slot_bindings.yaml
    written: false
    collision: true
    draft_only: true
    draft_path: artifacts/sprints/adapter_slot_filling_v1/write_summary/draft_slot_bindings/asn1_nested_boundary/openssl/slot_bindings.yaml
  - adapter_id: asn1_nested_boundary.mbedtls.family_adapter_recipe_v1
    family: asn1_nested_boundary
    target_library: mbedtls
    write_attempted: true
    source_path: artifacts/sprints/adapter_slot_filling_v1/slot_bindings/asn1_nested_boundary/mbedtls/slot_bindings.yaml
    target_path: adapter_recipes/wolfssl_family/asn1_nested_boundary/mbedtls/slot_bindings.yaml
    written: false
    collision: true
    draft_only: true
    draft_path: artifacts/sprints/adapter_slot_filling_v1/write_summary/draft_slot_bindings/asn1_nested_boundary/mbedtls/slot_bindings.yaml
blocked_targets:
  schema: blocked_targets_respected_v1
  generated_at: '2026-06-11T14:04:52+00:00'
  respected: true
  pkcs_container_parsing_mbedtls: not requested for slot filling; blocked/no_direct_counterpart
    records preserved
  weak_evidence_mappings: not promoted to confirmed equivalence; forbidden APIs rejected
  needs_manual_review_mappings: asn1_nested_boundary.mbedtls written as blocked_by_mapping_gate
    placeholder
  blocked_records_seen:
  - family: pkcs_container_parsing
    target_library: openssl
    blocked_reason: weak_evidence
    blocked_apis:
    - d2i_PKCS7
    why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
      slot filling
    recommendation:
    - do_not_generate_adapter
    - manual_review_before_adapter
    notes:
    - not adapter-ready under current evidence gate
    - candidate_only mappings are not confirmed equivalence.
  - family: asn1_nested_boundary
    target_library: openssl
    blocked_reason: needs_manual_review
    blocked_apis:
    - d2i_X509
    why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
      slot filling
    recommendation:
    - manual_review_before_adapter
    - manual_review_before_adapter
    notes:
    - not adapter-ready under current evidence gate
    - candidate_only mappings are not confirmed equivalence.
  - family: asn1_nested_boundary
    target_library: mbedtls
    blocked_reason: needs_manual_review
    blocked_apis:
    - mbedtls_x509_crt_parse_der
    why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
      slot filling
    recommendation:
    - manual_review_before_adapter
    - manual_review_before_adapter
    notes:
    - not adapter-ready under current evidence gate
    - candidate_only mappings are not confirmed equivalence.
next_action:
  schema: next_action_after_adapter_slot_filling_v1
  generated_at: '2026-06-11T14:04:52+00:00'
  next_task_name: adapter_slot_filling_fixup_v1
  why: At least one generated binding failed structural or gate validation.
  do_not_run_yet:
  - render_cases
  - compile_run
  - PoC execution
actions_not_performed:
  run_poc: false
  compile_run: false
  glm: true
  render: false
  generated_c: false
  pattern_bank_modified: false
  scheduler_seed_modified: false
  knowledge_raw_modified: false
  git_add_commit_push: false
```
