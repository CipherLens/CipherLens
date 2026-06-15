# Adapter Slot Filling Input Summary

```yaml
schema: adapter_slot_filling_input_summary_v1
generated_at: '2026-06-11T14:04:52+00:00'
slot_plan_root: artifacts/sprints/adapter_slot_filling_plan_v1
adapter_recipe_root: adapter_recipes/wolfssl_family
family_template_root: normalized_templates/wolfssl_family
targets:
- adapter_id: pkcs_container_parsing.openssl.family_adapter_recipe_v1
  family: pkcs_container_parsing
  target_library: openssl
  plan_path: artifacts/sprints/adapter_slot_filling_plan_v1/slot_filling_plans/pkcs_container_parsing/openssl/slot_filling_plan.yaml
  schema_path: artifacts/sprints/adapter_slot_filling_plan_v1/schemas/pkcs_container_parsing_openssl_slot_bindings_schema.yaml
  prompt_context_path: artifacts/sprints/adapter_slot_filling_plan_v1/prompt_contexts/pkcs_container_parsing_openssl_prompt_context.md
  adapter_recipe_path: adapter_recipes/wolfssl_family/pkcs_container_parsing/openssl/adapter_recipe.yaml
  blocked_by_mapping_gate: false
  blocked_reasons:
  - weak_evidence
- adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
  family: asn1_nested_boundary
  target_library: openssl
  plan_path: artifacts/sprints/adapter_slot_filling_plan_v1/slot_filling_plans/asn1_nested_boundary/openssl/slot_filling_plan.yaml
  schema_path: artifacts/sprints/adapter_slot_filling_plan_v1/schemas/asn1_nested_boundary_openssl_slot_bindings_schema.yaml
  prompt_context_path: artifacts/sprints/adapter_slot_filling_plan_v1/prompt_contexts/asn1_nested_boundary_openssl_prompt_context.md
  adapter_recipe_path: adapter_recipes/wolfssl_family/asn1_nested_boundary/openssl/adapter_recipe.yaml
  blocked_by_mapping_gate: false
  blocked_reasons:
  - needs_manual_review
- adapter_id: asn1_nested_boundary.mbedtls.family_adapter_recipe_v1
  family: asn1_nested_boundary
  target_library: mbedtls
  plan_path: artifacts/sprints/adapter_slot_filling_plan_v1/slot_filling_plans/asn1_nested_boundary/mbedtls/slot_filling_plan.yaml
  schema_path: artifacts/sprints/adapter_slot_filling_plan_v1/schemas/asn1_nested_boundary_mbedtls_slot_bindings_schema.yaml
  prompt_context_path: artifacts/sprints/adapter_slot_filling_plan_v1/prompt_contexts/asn1_nested_boundary_mbedtls_prompt_context.md
  adapter_recipe_path: adapter_recipes/wolfssl_family/asn1_nested_boundary/mbedtls/adapter_recipe.yaml
  blocked_by_mapping_gate: true
  blocked_reasons:
  - needs_manual_review
forbidden_actions:
- no_poc_run
- no_compile_run
- no_render_cases
- no_c_generation
- no_adapter_recipe_yaml_modification
- no_family_template_modification
- no_knowledge_layer_modification
- no_git_add_commit_push
```
