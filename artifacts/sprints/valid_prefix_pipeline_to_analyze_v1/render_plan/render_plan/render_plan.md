# Render Plan Valid Prefix

```yaml
schema: render_plan_valid_prefix_v1
generated_at: '2026-06-12T04:13:07+00:00'
render_jobs:
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__001
  supplemental_case_id: asn1_nested_boundary_openssl__supp_001__valid_der_plus_trailing_garbage
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: valid_object_plus_trailing_garbage
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: valid_control
    mutation_value_strategy: reuse_valid_der_seed_prefix
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: high
  - slot_name: TRAILING_GARBAGE
    mutation_type: boundary
    mutation_value_strategy: append_00_after_valid_object
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: high
  render_allowed: true
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__002
  supplemental_case_id: asn1_nested_boundary_openssl__supp_002__valid_prefix_trailing_only_ff00
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: valid_prefix_trailing_only
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: valid_control
    mutation_value_strategy: preserve_seed_exact
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: high
  - slot_name: TRAILING_GARBAGE
    mutation_type: boundary
    mutation_value_strategy: append_ff00_after_valid_object
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: high
  render_allowed: true
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__003
  supplemental_case_id: asn1_nested_boundary_openssl__supp_003__outer_sequence_inner_length_plus_one
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: preserve_outer_container_mutate_inner
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: valid_control
    mutation_value_strategy: preserve_outer_sequence_seed
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  - slot_name: ASN1_NESTED_LENGTH
    mutation_type: boundary
    mutation_value_strategy: small_delta_plus_one_inner_only
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  render_allowed: true
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__004
  supplemental_case_id: asn1_nested_boundary_openssl__supp_004__outer_sequence_inner_length_minus_one
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: near_valid_small_length_delta
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: valid_control
    mutation_value_strategy: preserve_outer_sequence_seed
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  - slot_name: ASN1_NESTED_LENGTH
    mutation_type: boundary
    mutation_value_strategy: small_delta_minus_one_inner_only
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  render_allowed: true
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__005
  supplemental_case_id: asn1_nested_boundary_openssl__supp_005__valid_prefix_truncated_tail_one_byte
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: valid_prefix_trailing_only
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: boundary
    mutation_value_strategy: preserve_valid_prefix_truncate_tail_one_byte
    preserves_valid_prefix: true
    preserves_outer_container: false
    expected_accept_path_probability: medium
  render_allowed: true
- render_job_id: render_valid_prefix__asn1_nested_boundary__openssl__006
  supplemental_case_id: asn1_nested_boundary_openssl__supp_006__nested_depth_near_valid
  family: asn1_nested_boundary
  target_library: openssl
  refinement_strategy: preserve_outer_container_mutate_inner
  mutation_assignments:
  - slot_name: DER_BYTES
    mutation_type: valid_control
    mutation_value_strategy: preserve_seed_exact
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  - slot_name: NESTED_DEPTH
    mutation_type: boundary
    mutation_value_strategy: increase_depth_by_one_only
    preserves_valid_prefix: true
    preserves_outer_container: true
    expected_accept_path_probability: medium
  render_allowed: true
summary:
  total_render_jobs: 6
  family: asn1_nested_boundary
  target_library: openssl
  pkcs_jobs: 0
  mbedtls_jobs: 0
  harness_generated: false
```
