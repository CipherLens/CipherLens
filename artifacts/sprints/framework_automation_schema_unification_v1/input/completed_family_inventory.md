# Completed Family Inventory

This inventory normalizes the representative exploration lines into scheduler-facing fields. No new family experiment, render, compile, run, GLM call, or vulnerability claim was performed in this sprint.

| family | execution_path | outcome | claim_level | evidence_strength |
| --- | --- | --- | --- | --- |
| mac_lifecycle | A_recipe_slot_cross_library_migration | migrated_safe | needs_triage | medium_to_strong |
| der_full_consumption | C_app_level_validation_gap | app_level_validation_gap_candidate | semantic_divergence_candidate | strong_for_behavior_medium_for_security_claim |
| secure_heap_state_lifecycle | B_controlled_family_mutation | validated_new_state_candidate | validated_new_state_candidate | strong_for_current_version_reproducer_limited_for_upstream_claim |
| cipher_aead_lifecycle | B_controlled_family_mutation | negative_feedback | no_claim | strong_negative_feedback_for_gcm_medium_for_remaining_non_gcm_spaces |
| asn1_nested_boundary | blocked_seed_missing | blocked_seed_missing | no_claim | medium_metadata_but_insufficient_for_reproduction |

## Lessons
- `mac_lifecycle`: A-path can be automated when source/target API mapping, cleanup mapping, and oracle comparability are explicit.; GLM is acceptable only as strict recipe-slot filler after recipe and allowed slots exist.; Generic analyzers must keep semantic divergence as triage unless cross-library oracle evidence is strong.
- `der_full_consumption`: Low-level prefix-parse behavior is expected for many d2i APIs; app-level acceptance of malformed trailing data is a separate route.; A valid-control plus malformed-only reject plus valid-prefix-with-malformed-tail accept pattern is a useful C-path gate.; This route should emit minimal reproducer/upstream-inquiry handoff rather than direct vulnerability claim.
- `secure_heap_state_lifecycle`: State-machine mutation needs normal controls, explicit precondition notes, and external validation handoff.; A current-version robustness candidate is not automatically a confirmed vulnerability.; Once minimal reproducer and gdb evidence exist, scheduler should move the family to external validation instead of keeping it top exploratory priority.
- `cipher_aead_lifecycle`: Cross-library semantic checks are essential before promoting permissive behavior.; Legal GCM semantics such as empty plaintext or truncated allowed tags must demote candidates.; No A-path or GLM should be used when the mapping/oracle is still mutation-local and candidate semantics may be legal.
- `asn1_nested_boundary`: Placeholder input must block D-path reproduction and crash claims.; Missing seed should prevent A-path escalation even if issue metadata looks promising.; Seed enrichment can record related vectors, but high-uncertainty reconstruction should not be treated as strict reproduction.
