# x509_parsing Gate Decision

evidence_gate:
  passed: true
  reason: Medium scheduler evidence is enough for triage, not for render/run.
  strength: medium
route_gate:
  selected_route: C_app_level_validation_gap
  reason: Use C-path only as a triage hypothesis because x509 has app-visible wrong-result
    cases; D-path and A/B alternatives remain unresolved.
  alternatives:
    D_crash_sanitizer_evidence_audit: Use only for seeds with real crash/sanitizer
      input and reproducibility path.
    A_recipe_slot_cross_library_migration: Blocked until source/target API mapping
      and oracle comparability are explicit.
    B_controlled_family_mutation: Possible later for verifier/state machine behavior
      after controls exist.
a_path_gate:
  passed: false
  reason: No validated cross-library recipe-slot mapping or comparable oracle yet.
glm_gate:
  glm_allowed: false
  reason: GLM is disallowed because A-path gate is false.
  allowed_role: none
  forbidden_role:
  - free_form_c_generation
  - API_contract_guessing
  - vulnerability_claim
  - sanitizer_interpretation
execution_gate:
  auto_triage_allowed: true
  auto_render_allowed: false
  auto_run_allowed: false
  reason: Planner can authorize only evidence collection and route disambiguation
    in the next sprint.
