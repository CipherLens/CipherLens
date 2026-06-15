# Route Decision Schema

Route decision chooses the least unsafe next action for each family. A route can be blocked even when a family looks interesting.

```yaml
schema_version: 1
routes:
  A_recipe_slot_cross_library_migration:
    required:
    - strong_api_mapping
    - stable_oracle
    - comparable_source_target_behavior
    - adapter_validate_passed
    glm_allowed: true
    glm_role: strict_recipe_slot_filling_only
    auto_render_allowed_if:
    - evidence_gate_medium_or_strong
    - a_path_gate_passed
    - adapter_recipe_exists
    example_family: mac_lifecycle
  B_controlled_family_mutation:
    required:
    - stable_single_library_api_group
    - clear_state_or_parameter_mutation_points
    - normal_control_available
    - analyzer_label_defined
    glm_allowed: false_or_optional_for_plan_summary
    auto_render_allowed_if:
    - normal_control_defined
    - mutation_matrix_reviewed
    - stop_conditions_absent
    example_family: secure_heap_state_lifecycle or cipher_aead_lifecycle
  C_app_level_validation_gap:
    required:
    - app_or_cli_path
    - observable_success_or_failure
    - malformed_vs_control_input
    - user_visible_effect
    glm_allowed: false
    auto_render_allowed_if:
    - app_path_available
    - control_input_available
    - malformed_only_reject_available
    example_family: der_full_consumption
  D_crash_sanitizer_evidence_audit:
    required:
    - historical_crash_or_sanitizer_seed
    - input_or_reconstruction_path
    - minimal_reproducer_feasibility
    glm_allowed: false
    auto_render_allowed_if:
    - real_seed_available
    - sanitizer_or_gdb_environment_available
    example_family: asn1_nested_boundary before seed_missing block
  D_then_A:
    required:
    - D_path_seed_candidate
    - potential_cross_library_mapping
    - A_path_deferred_until_reproduction
    glm_allowed: only_after_D_path_reproduction_and_A_gate
    auto_render_allowed_if:
    - strict_reproduction_success
    - a_path_gate_passed
    example_family: asn1_nested_boundary if real seed is recovered later
route_selection_order:
- block_conditions
- D_seed_reality
- C_app_visibility
- A_mapping_and_oracle
- B_mutation_controls
```
