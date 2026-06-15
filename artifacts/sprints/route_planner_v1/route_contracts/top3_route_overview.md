# Top-3 Route Overview

top3:
- rank: 1
  family: x509_parsing
  recommended_route: C_app_level_validation_gap
  final_score: 15
  reason: 'Status: ready_for_triage.'
- rank: 2
  family: evp_pkey_context_lifecycle
  recommended_route: B_controlled_family_mutation
  final_score: 15
  reason: 'Status: ready_for_triage.'
- rank: 3
  family: der_full_consumption
  recommended_route: C_app_level_validation_gap
  final_score: 15
  reason: Strong app-level behavior candidate; next step is minimal reproducer/upstream
    inquiry, not repeat C-path.
why_top2_not_first: evp_pkey_context_lifecycle has weak evidence gate in scheduler
  output; it should wait for evidence strengthening.
why_top3_der_not_directly_continue: der_full_consumption already has strong C-path
  signal and should proceed via minimal reproducer/upstream inquiry, not repeat the
  completed discovery path.
fallback_if_x509_blocked: evp_pkey_context_lifecycle_evidence_strengthening_v1 before
  any render/run; if its evidence remains weak, use der_full_consumption minimal reproducer/upstream
  inquiry track.
