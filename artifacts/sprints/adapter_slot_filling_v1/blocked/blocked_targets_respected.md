# Blocked Targets Respected

```yaml
schema: blocked_targets_respected_v1
generated_at: '2026-06-11T14:04:52+00:00'
respected: true
pkcs_container_parsing_mbedtls: not requested for slot filling; blocked/no_direct_counterpart
  records preserved
weak_evidence_mappings: not promoted to confirmed equivalence; forbidden APIs rejected
needs_manual_review_mappings: asn1_nested_boundary.mbedtls written as blocked_by_mapping_gate
  placeholder
blocked_records_seen:
- family: pkcs_container_parsing
  target_library: openssl
  blocked_reason: weak_evidence
  blocked_apis:
  - d2i_PKCS7
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - do_not_generate_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: asn1_nested_boundary
  target_library: openssl
  blocked_reason: needs_manual_review
  blocked_apis:
  - d2i_X509
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - manual_review_before_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: asn1_nested_boundary
  target_library: mbedtls
  blocked_reason: needs_manual_review
  blocked_apis:
  - mbedtls_x509_crt_parse_der
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - manual_review_before_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
```
