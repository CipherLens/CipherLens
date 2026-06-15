# render_cases_v1 Input Summary

- consumes: `render_plan_v1`
- generates C harness: `true`
- compile/run/analyze: `false`
- target scope: `OpenSSL only`
- blocked mbedTLS adapter rendered: `false`
- GLM called: `false`

## Inputs

- artifacts/sprints/render_plan_v1/render_plan/render_plan.yaml
- artifacts/sprints/render_plan_v1/case_manifest/case_manifest.yaml
- artifacts/sprints/family_adapter_mutation_planner_v1/mutation_case_matrix/mutation_case_matrix.yaml
- artifacts/sprints/family_adapter_mutation_planner_v1/oracle_expectation_plan/oracle_expectation_plan.yaml
- adapter_recipes/wolfssl_family
- normalized_templates/wolfssl_family
