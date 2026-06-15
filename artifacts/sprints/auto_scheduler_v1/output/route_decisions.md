# Route Decisions

| family | recommended_route | evidence_gate | a_path_gate | glm_allowed | auto_render_allowed | auto_run_allowed | next_task_name |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x509_parsing | C_app_level_validation_gap | True | False | False | False | False | x509_parsing_triage_v1 |
| evp_pkey_context_lifecycle | B_controlled_family_mutation | False | False | False | False | False | evp_pkey_context_lifecycle_triage_v1 |
| der_full_consumption | C_app_level_validation_gap | True | False | False | False | False | der_full_consumption_minimal_reproducer_or_upstream_inquiry |
| bignum_serialization_boundary | needs_more_evidence | True | False | False | False | False | bignum_serialization_boundary_evidence_triage_v1 |
| secure_heap_state_lifecycle | external_validation | True | False | False | False | False | secure_heap_state_lifecycle_external_validation_track |
| bignum_arithmetic_precondition | needs_more_evidence | True | False | False | False | False | bignum_arithmetic_precondition_evidence_triage_v1 |
| mac_lifecycle | A_recipe_slot_cross_library_migration | True | True | True | False | False | mac_lifecycle_documentation_and_caller_impact_triage |
| pkey_verify_semantic | closed_negative_feedback | True | False | False | False | False | pkey_verify_semantic_closed_negative_feedback |
| ossl_store_decoder_boundary | C_app_level_validation_gap | False | False | False | False | False | ossl_store_decoder_boundary_triage_v1 |
| provider_fetch_lifecycle | B_controlled_family_mutation | False | False | False | False | False | provider_fetch_lifecycle_triage_v1 |
| cipher_aead_lifecycle | closed_negative_feedback | False | False | False | False | False | cipher_aead_lifecycle_closed_negative_feedback |
| asn1_nested_boundary | blocked | False | False | False | False | False | asn1_nested_boundary_seed_recovery_or_blocked_review |
