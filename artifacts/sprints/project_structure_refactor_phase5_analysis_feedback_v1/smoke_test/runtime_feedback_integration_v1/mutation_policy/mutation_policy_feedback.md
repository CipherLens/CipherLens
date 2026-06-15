# Mutation Policy Feedback

```yaml
schema: mutation_policy_feedback_v1
generated_at: '2026-06-12T09:39:18+00:00'
families:
- family: asn1_nested_boundary
  target_library: openssl
  effective_strategies:
  - valid_object_plus_trailing_garbage
  - valid_prefix_trailing_only
  ineffective_or_too_strong_strategies:
  - malformed_length
  - nested_length_mismatch_strong
  recommended_policy_update:
    increase_weight:
    - valid_prefix_trailing_only
    - valid_object_plus_trailing_garbage
    - near_valid_small_length_delta
    decrease_weight:
    - malformed_length_strong
    add_strategy:
    - accepted_path_full_consumption_probe
  confidence: medium
- family: pkcs_container_parsing
  target_library: openssl
  status: pending_valid_seed
  recommended_policy_update:
  - valid_seed_discovery_pkcs_v1
notes:
- original malformed matrix produced all reject observations and insufficient accept-path coverage
- valid-prefix supplemental cases improved accepted-path coverage
- PKCS lacks verified valid seed and should not be judged as mutation ineffective yet
```
