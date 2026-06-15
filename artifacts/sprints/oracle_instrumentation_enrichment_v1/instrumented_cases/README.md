# render_cases_v1

This sprint renders the 14 OpenSSL cases from render_plan_v1 into C harnesses and metadata.
It does not compile, run, analyze, rebuild RAG, or call GLM/LLM.

## Outputs

- rendered_cases/<render_job_id>/harness.c
- rendered_cases/<render_job_id>/input_corpus/
- rendered_cases/<render_job_id>/build_metadata.yaml
- rendered_cases/<render_job_id>/oracle_metadata.yaml
- rendered_cases/<render_job_id>/case_metadata.yaml
- rendered_cases/<render_job_id>/render_trace.yaml
- case_index/rendered_case_index.yaml
