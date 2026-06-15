# Mutation Planner Input Summary

```yaml
schema: mutation_planner_input_summary_v1
generated_at: '2026-06-12T08:08:17+00:00'
why_not_direct_render: Insert controlled family-level mutation planning before render to avoid direct
  historical-PoC migration.
render_ready_adapters:
- pkcs_container_parsing_openssl
- asn1_nested_boundary_openssl
blocked_adapters:
- asn1_nested_boundary_mbedtls
pkcs_openssl_enters_mutation: true
asn1_openssl_enters_mutation: true
asn1_mbedtls_blocked: true
no_c_generation: true
no_render_compile_run: true
no_glm: true
inputs:
  adapter_root: adapter_recipes/wolfssl_family
  family_template_root: normalized_templates/wolfssl_family
  adapter_validate_results: artifacts/sprints/adapter_slot_filling_regression_fixup_v1/validation/adapter_validate_results.yaml
  render_readiness: artifacts/sprints/adapter_slot_filling_regression_fixup_v1/validation/render_readiness_summary.yaml
  mapping_gate: artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/gate_results/cross_library_mapping_gate_results.yaml
  blocked_mappings: artifacts/sprints/cross_library_mapping_refinement_and_gate_v1/blocked_mappings/blocked_or_no_direct_counterpart_mappings.yaml
```
