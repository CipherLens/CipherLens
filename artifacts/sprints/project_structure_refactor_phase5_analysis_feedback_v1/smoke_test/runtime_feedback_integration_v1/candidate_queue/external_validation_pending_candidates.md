# External Validation Pending Candidates

```yaml
schema: external_validation_pending_candidates_v1
generated_at: '2026-06-12T09:39:18+00:00'
source_task: valid_prefix_pipeline_to_analyze_v1
candidates:
- case_id: asn1_nested_boundary_openssl__supp_001__valid_der_plus_trailing_garbage
  family: asn1_nested_boundary
  target_library: openssl
  candidate_type: full_consumption_gap_candidate
  observed_condition: accepted_true_and_full_consumption_false
  local_triage_performed: false
  external_validation_status: pending
  assigned_to: teammate
  claim_policy:
    confirmed_vulnerability: false
    cve: false
    exploitable: false
- case_id: asn1_nested_boundary_openssl__supp_002__valid_prefix_trailing_only_ff00
  family: asn1_nested_boundary
  target_library: openssl
  candidate_type: full_consumption_gap_candidate
  observed_condition: accepted_true_and_full_consumption_false
  local_triage_performed: false
  external_validation_status: pending
  assigned_to: teammate
  claim_policy:
    confirmed_vulnerability: false
    cve: false
    exploitable: false
- case_id: asn1_nested_boundary_openssl__supp_005__valid_prefix_truncated_tail_one_byte
  family: asn1_nested_boundary
  target_library: openssl
  candidate_type: full_consumption_gap_candidate
  observed_condition: accepted_true_and_full_consumption_false
  local_triage_performed: false
  external_validation_status: pending
  assigned_to: teammate
  claim_policy:
    confirmed_vulnerability: false
    cve: false
    exploitable: false
summary:
  total_candidates: 3
  pending_external_validation: 3
```
