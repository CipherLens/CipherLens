# auto_scheduler_v1 Design

`auto_scheduler_v1` is a read-only planner. It should rank families, choose routes, apply gates, and decide whether GLM or auto render/run is allowed. It should not render, compile, run, or claim vulnerabilities.

```yaml
schema_version: 1
component: auto_scheduler_v1
inputs:
- artifacts/pattern_bank/unified_pattern_bank.yaml
- artifacts/pattern_bank/scheduler_seed.yaml
- artifacts/feedback/*.jsonl
- knowledge_raw/poc_patterns/*.md
outputs:
- family_rerank
- route_decision
- evidence_gate_result
- next_task_recommendation
- glm_allowed
- auto_render_run_allowed
pseudo_code:
- load_pattern_bank()
- load_scheduler_seed()
- load_feedback()
- 'for family in families:'
- '  profile = build_family_profile(family)'
- '  evidence = score_evidence(profile)'
- '  route = decide_route(profile, evidence)'
- '  gate = apply_gates(route, evidence)'
- '  score = scheduler_score(profile, evidence, feedback)'
- rank()
- emit_next_task()
decision_policy:
  default_next_task: auto_scheduler_v1
  do_not_auto_render_if:
  - evidence_gate_insufficient
  - route_blocked
  - normal_control_missing
  - glm_gate_failed
  glm_allowed_only_for:
  - A_recipe_slot_cross_library_migration with a_path_gate_passed
```
