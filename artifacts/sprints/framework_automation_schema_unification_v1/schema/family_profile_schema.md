# Family Profile Schema

The family profile is the scheduler input contract. It separates family identity, evidence, APIs, mutation space, prior feedback, and next action.

## Required Fields

```yaml
family_id: string_stable_identifier
family_name: human_readable_name
category:
  one_of:
  - lifecycle
  - parser_boundary
  - app_validation
  - arithmetic_semantics
  - provider_or_context
  - memory_or_state
source_seeds:
- seed identifiers, PoC ids, issue ids, or patch/regression references
target_libraries:
- library ids
api_groups:
- source/target API clusters with roles
root_cause_hypotheses:
- explicit hypotheses, not claims
mutation_points:
- state, parameter, buffer, parser boundary, or app-level input mutations
oracle_types:
- return code, output state, pointer consumption, sanitizer, app visible behavior
previous_feedback:
- feedback jsonl rows or sprint summaries
current_status:
  one_of:
  - ready_for_triage
  - ready_for_mutation
  - ready_for_A_path
  - external_validation_track
  - closed_negative_feedback
  - blocked_seed_missing
  - needs_more_evidence
last_sprint: latest sprint id
recommended_next_action: scheduler-readable task id
```

## Example Table

| family_id | category | current_status | last_sprint | recommended_next_action |
| --- | --- | --- | --- | --- |
| mac_lifecycle | lifecycle | ready_for_A_path | mac_lifecycle_family_v1 | mac_lifecycle_documentation_and_caller_impact_triage |
| der_full_consumption | app_validation | external_validation_track | ossl_store_full_consumption | minimal_reproducer_or_upstream_inquiry |
| secure_heap_state_lifecycle | memory_or_state | external_validation_track | secure_heap_init_failed_then_query_candidate_validation | secure_heap_external_validation_track |
| cipher_aead_lifecycle | lifecycle | closed_negative_feedback | cipher_aead_lifecycle_gcm_closure_v1 | scheduler_rerank_or_non_gcm_aead_triage_later |
| asn1_nested_boundary | parser_boundary | blocked_seed_missing | asn1_nested_boundary_seed_enrichment_v1 | framework_automation_schema_unification_v1 |
