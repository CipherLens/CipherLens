# Render Plan

- schema: `render_plan_v1`
- total_render_jobs: `14`
- pkcs jobs: `7`
- asn1 jobs: `7`
- execution: `{'render_c': False, 'compile': False, 'run': False, 'llm_call': False, 'plan_only': True}`

| render_job_id | family | target_library | mutation_strategy | expected_result_label |
|---|---|---|---|---|
| render__pkcs_container_parsing__openssl__seed_preserving_baseline__case_001 | pkcs_container_parsing | openssl | seed_preserving_baseline | migrated_safe |
| render__pkcs_container_parsing__openssl__trailing_garbage__case_001 | pkcs_container_parsing | openssl | trailing_garbage | semantic_divergence_candidate |
| render__pkcs_container_parsing__openssl__malformed_length__case_001 | pkcs_container_parsing | openssl | malformed_length | needs_triage |
| render__pkcs_container_parsing__openssl__nested_length_mismatch__case_001 | pkcs_container_parsing | openssl | nested_length_mismatch | semantic_divergence_candidate |
| render__pkcs_container_parsing__openssl__invalid_container_structure__case_001 | pkcs_container_parsing | openssl | invalid_container_structure | migrated_safe |
| render__pkcs_container_parsing__openssl__pem_der_format_toggle__case_001 | pkcs_container_parsing | openssl | pem_der_format_toggle | api_misuse_false_positive |
| render__pkcs_container_parsing__openssl__expected_return_flip__case_001 | pkcs_container_parsing | openssl | expected_return_flip | needs_triage |
| render__asn1_nested_boundary__openssl__seed_preserving_baseline__case_001 | asn1_nested_boundary | openssl | seed_preserving_baseline | migrated_safe |
| render__asn1_nested_boundary__openssl__trailing_garbage__case_001 | asn1_nested_boundary | openssl | trailing_garbage | semantic_divergence_candidate |
| render__asn1_nested_boundary__openssl__short_length__case_001 | asn1_nested_boundary | openssl | short_length | migrated_safe |
| render__asn1_nested_boundary__openssl__long_length__case_001 | asn1_nested_boundary | openssl | long_length | needs_triage |
| render__asn1_nested_boundary__openssl__nested_length_mismatch__case_001 | asn1_nested_boundary | openssl | nested_length_mismatch | semantic_divergence_candidate |
| render__asn1_nested_boundary__openssl__nested_depth_variation__case_001 | asn1_nested_boundary | openssl | nested_depth_variation | needs_triage |
| render__asn1_nested_boundary__openssl__expected_return_flip__case_001 | asn1_nested_boundary | openssl | expected_return_flip | needs_triage |
