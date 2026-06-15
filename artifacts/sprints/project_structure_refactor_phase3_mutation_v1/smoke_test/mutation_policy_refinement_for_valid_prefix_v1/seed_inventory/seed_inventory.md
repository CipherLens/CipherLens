# Seed Inventory

```yaml
schema: valid_prefix_seed_inventory_v1
generated_at: '2026-06-12T08:08:52+00:00'
families:
- family: pkcs_container_parsing
  available_seed_sources:
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__expected_return_flip__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__invalid_container_structure__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__malformed_length__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__nested_length_mismatch__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__pem_der_format_toggle__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__pkcs_container_parsing__openssl__trailing_garbage__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__pkcs_container_parsing__openssl__expected_return_flip__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__pkcs_container_parsing__openssl__invalid_container_structure__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__pkcs_container_parsing__openssl__malformed_length__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__pkcs_container_parsing__openssl__nested_length_mismatch__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__pkcs_container_parsing__openssl__pem_der_format_toggle__case_001/input_corpus/input.bin
    source_type: bin
    likely_valid: unknown
    notes: candidate PKCS-like seed source found on disk; validity not proven in this planning step
  valid_prefix_seed_available: false
  near_valid_seed_available: true
  trailing_only_possible: false
  limitations:
  - 'pending_valid_seed: PKCS-like .p12/.p7b or rendered .bin sources need validation before render_allowed
    supplemental cases'
  - do not fabricate valid PKCS12/PKCS7 bytes in this planning step
- family: asn1_nested_boundary
  available_seed_sources:
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__expected_return_flip__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__long_length__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__nested_depth_variation__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__nested_length_mismatch__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__seed_preserving_baseline__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__short_length__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/oracle_instrumentation_enrichment_v1/instrumented_cases/rendered_cases/render__asn1_nested_boundary__openssl__trailing_garbage__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__asn1_nested_boundary__openssl__expected_return_flip__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__asn1_nested_boundary__openssl__long_length__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__asn1_nested_boundary__openssl__nested_depth_variation__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__asn1_nested_boundary__openssl__nested_length_mismatch__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  - path: artifacts/sprints/render_cases_v1/rendered_cases/render__asn1_nested_boundary__openssl__seed_preserving_baseline__case_001/input_corpus/input.der
    source_type: der
    likely_valid: true
    notes: usable as ASN.1/DER valid-prefix or near-valid seed candidate; downstream render must preserve
      byte/length pairing
  valid_prefix_seed_available: true
  near_valid_seed_available: true
  trailing_only_possible: true
  limitations:
  - render must preserve outer DER object validity for accepted-path probes
  - certificate-like seeds may be app-level valid but still need per-API acceptance checks later
summary:
  pkcs_seed_available: false
  asn1_seed_available: true
  families_without_valid_seed:
  - pkcs_container_parsing
```
