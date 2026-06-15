# auto_scheduler_v1 Input Summary

## Loaded Sources

pattern_bank: artifacts/pattern_bank/unified_pattern_bank.yaml
scheduler_seed: artifacts/pattern_bank/scheduler_seed.yaml
feedback_files:
- artifacts/feedback/asn1_nested_boundary_d_path_audit_feedback.jsonl
- artifacts/feedback/asn1_nested_boundary_minimal_reproducer_feedback.jsonl
- artifacts/feedback/asn1_nested_boundary_seed_enrichment_feedback.jsonl
- artifacts/feedback/cipher_aead_lifecycle_botan_crosscheck_feedback.jsonl
- artifacts/feedback/cipher_aead_lifecycle_gcm_closure_feedback.jsonl
- artifacts/feedback/cipher_aead_lifecycle_mutation_feedback.jsonl
- artifacts/feedback/cipher_aead_lifecycle_semantic_crosscheck_feedback.jsonl
- artifacts/feedback/der_full_consumption_feedback.jsonl
- artifacts/feedback/mac_lifecycle_feedback.jsonl
- artifacts/feedback/mutation_feedback.jsonl
- artifacts/feedback/secure_heap_init_failed_then_query_candidate_feedback.jsonl
- artifacts/feedback/secure_heap_state_lifecycle_feedback.jsonl
- artifacts/feedback/secure_heap_state_lifecycle_pattern_expansion_feedback.jsonl
schema_files:
- artifacts/sprints/framework_automation_schema_unification_v1/schema/family_profile_schema.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/schema/route_decision_schema.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/gates/evidence_gate.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/gates/a_path_glm_gate.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/schema/feedback_schema.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/scheduler/scheduler_scoring_schema.yaml
- artifacts/sprints/framework_automation_schema_unification_v1/automation_plan/auto_scheduler_v1_design.yaml
knowledge_raw_files:
- knowledge_raw/poc_patterns/core10_patterns.md
- knowledge_raw/poc_patterns/der_full_consumption_ossl_store_evidence.md
- knowledge_raw/poc_patterns/openssl_issue_patterns.md
- knowledge_raw/poc_patterns/unified_patterns.md

## Missing Sources

[]

## Parse Errors

[]
