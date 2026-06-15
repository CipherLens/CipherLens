# Oracle Expectation Plan

```yaml
schema: oracle_expectation_plan_v1
families:
- family: pkcs_container_parsing
  target_library: openssl
  primary_oracles:
  - parser_reject_accept
  secondary_oracles:
  - return_code_semantics
  - full_consumption
  - cleanup_required
  expected_result_labels:
  - api_misuse_false_positive
  - migrated_safe
  - needs_triage
  - semantic_divergence_candidate
  oracle_interpretation_rules:
  - rule: parser accept/reject divergence
    meaning: candidate behavioral divergence only
    false_positive_risk: API-level permissiveness or input construction mismatch
  - rule: return-code divergence
    meaning: semantic_divergence_candidate
    false_positive_risk: different library error taxonomy
  - rule: crash signal
    meaning: requires reproduction and sanitizer evidence before vulnerability claim
    false_positive_risk: harness misuse or invalid API setup
  - rule: API misuse
    meaning: downgrade to api_misuse_false_positive
    false_positive_risk: adapter did not preserve target preconditions
  candidate_label_policy:
    do_not_claim_confirmed_vulnerability: true
    semantic_divergence_requires_triage: true
    crash_requires_reproduction: true
- family: asn1_nested_boundary
  target_library: openssl
  primary_oracles:
  - parser_reject_accept
  secondary_oracles:
  - full_consumption
  - return_code_semantics
  expected_result_labels:
  - migrated_safe
  - needs_triage
  - semantic_divergence_candidate
  oracle_interpretation_rules:
  - rule: parser accept/reject divergence
    meaning: candidate behavioral divergence only
    false_positive_risk: API-level permissiveness or input construction mismatch
  - rule: return-code divergence
    meaning: semantic_divergence_candidate
    false_positive_risk: different library error taxonomy
  - rule: crash signal
    meaning: requires reproduction and sanitizer evidence before vulnerability claim
    false_positive_risk: harness misuse or invalid API setup
  - rule: API misuse
    meaning: downgrade to api_misuse_false_positive
    false_positive_risk: adapter did not preserve target preconditions
  candidate_label_policy:
    do_not_claim_confirmed_vulnerability: true
    semantic_divergence_requires_triage: true
    crash_requires_reproduction: true
```
