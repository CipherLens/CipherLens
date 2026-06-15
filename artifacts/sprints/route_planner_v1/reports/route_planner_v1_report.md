# route_planner_v1 Report

- Top-1 family: `x509_parsing`
- Route: `C_app_level_validation_gap`
- Route confidence: `medium`
- Auto triage: `true`
- Auto render/run: `false` / `false`
- GLM allowed: `false`
- Pattern Bank modified: `false`
- Vulnerability found: `false`

## Route Ambiguity

- C_app_level_validation_gap is plausible because several x509 seeds are app-visible wrong-result/wrong-output cases.
- D_crash_sanitizer_evidence_audit remains plausible for seeds such as CSR/ASN.1 NULL dereference reports.
- A-path is premature until seed inventory, API grouping, and oracle comparability are explicit.
- B-path is possible later for verifier/state-machine style mutations, but controls are not defined yet.
