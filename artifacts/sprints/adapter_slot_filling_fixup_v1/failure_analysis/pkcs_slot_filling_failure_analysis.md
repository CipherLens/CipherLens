# PKCS Slot Filling Failure Analysis

```yaml
schema: pkcs_slot_filling_failure_analysis_v1
adapter_id: pkcs_container_parsing_openssl
family: pkcs_container_parsing
target_library: openssl
previous_binding_status: filled_by_glm
previous_validation_status: fail
failure_reasons:
- plan_echo
- missing_cleanup_mapping
- missing_oracle_mapping
- missing_input_mapping
- missing_mutation_slot_mapping
plan_echo: true
api_mapping_missing: false
cleanup_mapping_missing: true
oracle_mapping_missing: true
input_mapping_missing: true
mutation_slot_mapping_missing: true
c_generation_detected: false
blocked_api_used: true
confirmed_equivalence_claim: false
old_prompt_risks:
- prompt bundle was too long and included the full slot_filling_plan
- GLM copied context instead of filling the minimal slot_bindings schema
recommended_fix: Use a shorter YAML-only prompt with explicit allowed APIs, forbidden
  APIs, and a minimal output skeleton.
notes:
- Do not accept plan echo as valid slot binding.
- Do not use d2i_PKCS7 or any mbedTLS API.
```
