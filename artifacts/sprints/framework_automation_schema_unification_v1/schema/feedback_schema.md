# Feedback Schema

Feedback JSONL rows are the scheduler memory. They must be conservative: a row may promote, keep, demote, close, block, or move a candidate to external validation, but must not invent vulnerability claims.

```yaml
schema_version: 1
feedback_record:
  timestamp: ISO-8601 string
  family: family id
  sprint: sprint id
  route: A|B|C|D|D_then_A|blocked
  seed_id: seed id or null
  case_id: case id or null
  library: library id or null
  api_group: api group id
  evidence_strength: strong|medium|weak|insufficient
  classification: allowed analysis label
  claim_level: allowed claim level
  observed_behavior: short summary
  negative_feedback: bool
  scheduler_action:
    one_of:
    - promote
    - keep
    - demote
    - close
    - block
    - external_validation
  next_action: task id
  notes: free text but no vulnerability claim without evidence
examples:
- family: secure_heap_state_lifecycle
  sprint: secure_heap_init_failed_then_query_candidate_validation
  route: B_controlled_family_mutation
  seed_id: OPENSSL-ISSUE-28669
  case_id: secure_heap_exp_0003_new_state_init_failed_then_used
  library: openssl
  api_group: CRYPTO_secure_used
  evidence_strength: strong
  classification: crash_candidate
  claim_level: validated_new_state_candidate
  observed_behavior: current-version init_failed_then_query candidate reproduced with
    gdb evidence; upstream claim still pending
  negative_feedback: false
  scheduler_action: external_validation
  next_action: secure_heap_external_validation_track
- family: cipher_aead_lifecycle
  sprint: cipher_aead_lifecycle_gcm_closure_v1
  route: B_controlled_family_mutation
  seed_id: null
  case_id: aead_012_truncated_tag_length_gcm_decrypt
  library: openssl/mbedtls/botan
  api_group: GCM AEAD
  evidence_strength: strong
  classification: legal_semantics
  claim_level: no_claim
  observed_behavior: 8-byte GCM tag accepted as legal semantics across checked libraries
  negative_feedback: true
  scheduler_action: close
  next_action: do_not_promote_gcm_truncated_tag_length
- family: asn1_nested_boundary
  sprint: asn1_nested_boundary_seed_enrichment_v1
  route: D_crash_sanitizer_evidence_audit
  seed_id: OPENSSL-ISSUE-30581
  case_id: null
  library: openssl
  api_group: PKCS12/PBMAC1 ASN.1
  evidence_strength: insufficient
  classification: blocked_seed_missing
  claim_level: no_claim
  observed_behavior: original /tmp/pbmac1_null_salt.p12 not found; placeholder only
  negative_feedback: false
  scheduler_action: block
  next_action: framework_automation_schema_unification_v1
- family: der_full_consumption
  sprint: ossl_store_full_consumption
  route: C_app_level_validation_gap
  seed_id: MBEDTLS-POC-0020
  case_id: app_der_valid_prefix_malformed_tail
  library: openssl
  api_group: openssl app DER commands
  evidence_strength: strong
  classification: app_level_validation_gap_candidate
  claim_level: semantic_divergence_candidate
  observed_behavior: app accepts valid DER prefix plus malformed tail while rejecting
    malformed-only tail
  negative_feedback: false
  scheduler_action: promote
  next_action: minimal_reproducer_or_upstream_inquiry
- family: mac_lifecycle
  sprint: mac_lifecycle_family_v1
  route: A_recipe_slot_cross_library_migration
  seed_id: OPENSSL-ISSUE-22842
  case_id: mac_lifecycle_update_after_final
  library: openssl/mbedtls
  api_group: EVP_MAC/PSA_MAC
  evidence_strength: medium
  classification: needs_triage
  claim_level: needs_triage
  observed_behavior: safe/divergence pair needs caller impact triage
  negative_feedback: false
  scheduler_action: keep
  next_action: mac_lifecycle_documentation_and_caller_impact_triage
```
