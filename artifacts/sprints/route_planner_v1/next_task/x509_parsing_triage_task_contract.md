# x509_parsing_triage_v1 Task Contract

next_task_name: x509_parsing_triage_v1
family: x509_parsing
task_type: auto_triage_contract
goal: Decide whether x509_parsing should follow C, D, A, or B route using seed inventory,
  API grouping, and oracle abstraction.
allowed_actions:
  collect_seed_inventory: true
  read_existing_artifacts: true
  collect_api_evidence: true
  define_oracle_candidates: true
  render_cases: false
  compile_run: false
  glm: false
required_steps:
- Collect x509_parsing historical seeds from Pattern Bank and knowledge_raw.
- Separate x509_parsing from der_full_consumption and asn1_nested_boundary.
- Map OpenSSL app-level x509/verify/crl/req/decoder/d2i APIs.
- Abstract oracle candidates for wrong-result, wrong-output, safe rejection, and crash-audit
  seeds.
- Choose final route among C/D/A/B or block.
- Do not render/run and do not use GLM in triage.
- Emit whether gated_auto_triage_v1 can continue.
route_questions:
- Which seeds have real inputs?
- Which seeds are app-level behavior vs parser boundary vs crash audit?
- Which app or API paths expose observable behavior?
- Which controls are required before any mutation/render?
handoff_to: gated_auto_triage_v1 if seed inventory and route disambiguation are sufficient
source_route_contract: x509_parsing
