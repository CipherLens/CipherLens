# Slot Binding Validation Results

```yaml
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
```
