# Family Scores

| family | final_score | recommended_route | recommended_next_task | explanation |
| --- | --- | --- | --- | --- |
| x509_parsing | 15 | C_app_level_validation_gap | x509_parsing_triage_v1 | Status: ready_for_triage. |
| evp_pkey_context_lifecycle | 15 | B_controlled_family_mutation | evp_pkey_context_lifecycle_triage_v1 | Status: ready_for_triage. |
| der_full_consumption | 15 | C_app_level_validation_gap | der_full_consumption_minimal_reproducer_or_upstream_inquiry | Strong app-level behavior candidate; next step is minimal reproducer/upstream inquiry, not repeat C-path. |
| bignum_serialization_boundary | 14 | needs_more_evidence | bignum_serialization_boundary_evidence_triage_v1 | Status: ready_for_triage. |
| secure_heap_state_lifecycle | 13 | external_validation | secure_heap_state_lifecycle_external_validation_track | Strong current-version signal, but moved to external validation rather than main exploration. |
| bignum_arithmetic_precondition | 13 | needs_more_evidence | bignum_arithmetic_precondition_evidence_triage_v1 | Status: ready_for_triage. |
| mac_lifecycle | 12 | A_recipe_slot_cross_library_migration | mac_lifecycle_documentation_and_caller_impact_triage | Successful A-path template; keep for triage/documentation rather than immediate new run. |
| pkey_verify_semantic | 11 | closed_negative_feedback | pkey_verify_semantic_closed_negative_feedback | Status: closed_negative_feedback. |
| ossl_store_decoder_boundary | 11 | C_app_level_validation_gap | ossl_store_decoder_boundary_triage_v1 | Candidate family with limited prior artifacts; scheduler may triage before render/run. |
| provider_fetch_lifecycle | 10 | B_controlled_family_mutation | provider_fetch_lifecycle_triage_v1 | Candidate family with limited prior artifacts; scheduler may triage before render/run. |
| cipher_aead_lifecycle | 8 | closed_negative_feedback | cipher_aead_lifecycle_closed_negative_feedback | GCM candidates are closed as negative feedback; only non-GCM spaces remain later. |
| asn1_nested_boundary | -2 | blocked | asn1_nested_boundary_seed_recovery_or_blocked_review | Blocked because real seed is missing and placeholder-only evidence cannot support D-path. |
