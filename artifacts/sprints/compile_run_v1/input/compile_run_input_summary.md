# compile_run_v1 Input Summary

- consumes: `compile_plan_v1`
- real compile: `true`
- real run: `true`
- OpenSSL: ASan/UBSan install
- analyze/triage: `false`
- GLM: `false`
- modifies harness/template/adapter: `false`

## Inputs

- artifacts/sprints/compile_plan_v1/compile_plan/compile_plan.yaml
- artifacts/sprints/compile_plan_v1/compile_manifest/compile_manifest.yaml
- artifacts/sprints/render_cases_v1/case_index/rendered_case_index.yaml
- /home/wen/work/install-openssl-3.5.5-asan
