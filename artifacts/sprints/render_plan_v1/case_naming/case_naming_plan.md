# Case Naming Plan

- case_id_format: `<family>__<target_library>__<mutation_strategy>__case_<NNN>`
- render_job_id_format: `render__<family>__<target_library>__<mutation_strategy>__case_<NNN>`
- output_dir_format: `artifacts/sprints/render_cases_v1/rendered_cases/<family>/<target_library>/<render_job_id>`
- collision_policy: `deterministic; fail preflight if target output directory already exists`

## Examples

- pkcs_container_parsing__openssl__seed_preserving_baseline__case_001
- pkcs_container_parsing__openssl__trailing_garbage__case_001
- pkcs_container_parsing__openssl__malformed_length__case_001
