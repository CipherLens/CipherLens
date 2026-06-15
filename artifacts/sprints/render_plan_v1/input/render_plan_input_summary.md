# render_plan_v1 Input Summary

- generated_at: `2026-06-11T15:53:58+00:00`
- mutation_cases: `14`
- render_candidates: `14`
- render_ready_adapters: `['asn1_nested_boundary_openssl', 'pkcs_container_parsing_openssl']`
- blocked_adapters: `['asn1_nested_boundary_mbedtls']`
- scope: plan only; no C render, compile, run, or LLM call.

## Inputs

- artifacts/sprints/family_adapter_mutation_planner_v1/mutation_case_matrix/mutation_case_matrix.yaml
- artifacts/sprints/family_adapter_mutation_planner_v1/render_candidate_plan/render_candidate_plan.yaml
- artifacts/sprints/family_adapter_mutation_planner_v1/oracle_expectation_plan/oracle_expectation_plan.yaml
- artifacts/sprints/adapter_slot_filling_regression_fixup_v1/validation/adapter_validate_results.yaml
- artifacts/sprints/adapter_slot_filling_regression_fixup_v1/validation/render_readiness_summary.yaml
- adapter_recipes/wolfssl_family
- normalized_templates/wolfssl_family
