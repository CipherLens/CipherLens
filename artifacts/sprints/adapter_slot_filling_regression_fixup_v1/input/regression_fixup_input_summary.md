# Regression Fixup Input Summary

```yaml
schema: regression_fixup_input_summary_v1
generated_at: '2026-06-11T15:32:23+00:00'
scope: only fix asn1_nested_boundary -> OpenSSL
pkcs_should_remain_unchanged: true
asn1_mbedtls_should_remain_blocked_expected: true
no_glm_unless_no_candidate: true
glm_called: false
no_render_compile_run: true
no_c_generation: true
inputs:
  candidate_bindings: artifacts/sprints/adapter_slot_filling_v1/slot_bindings/asn1_nested_boundary/openssl/slot_bindings.yaml
  target_bindings: adapter_recipes/wolfssl_family/asn1_nested_boundary/openssl/slot_bindings.yaml
  adapter_root: adapter_recipes/wolfssl_family
  previous_validation: artifacts/sprints/adapter_slot_filling_v1/validation/slot_binding_validation_results.yaml
  validation_rules: artifacts/sprints/adapter_slot_filling_plan_v1/validation_rules/adapter_slot_binding_validation_rules.yaml
  mapping_gate: artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/gate_results/cross_library_mapping_gate_results.yaml
  blocked_mappings: artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml
```
