# Cipher AEAD Lifecycle Mutation Analysis

## Summary

- total_cases: 12
- raw_status_counts: `{'run_ok': 12}`
- classification_counts: `{'normal_control_ok': 2, 'expected_reject': 7, 'semantic_divergence_candidate': 2, 'permissive_behavior': 1}`
- normal_controls_passed: True
- high_value_candidates: 3

## Cases

| case_id | case_name | type | status | exit | classification | observed |
|---|---|---|---|---:|---|---|
| aead_000_normal_encrypt_gcm | normal_encrypt_control | safety_control | run_ok | 0 | normal_control_ok | normal_control_completed |
| aead_001_normal_decrypt_gcm | normal_decrypt_control | safety_control | run_ok | 0 | normal_control_ok | normal_control_completed |
| aead_004_repeated_final_gcm_encrypt | repeated_final | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_005_update_after_final_gcm_encrypt | update_after_final | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_006_final_without_update_gcm_encrypt | final_without_update | mutation_case | run_ok | 0 | semantic_divergence_candidate | mutation_allowed_but_may_match_documented_low_level_semantics |
| aead_007_get_tag_before_final_gcm_encrypt | get_tag_before_final | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_009_set_tag_after_final_gcm_decrypt | set_tag_after_final | mutation_case | run_ok | 0 | permissive_behavior | mutation_allowed_by_api |
| aead_010_aad_after_data_update_gcm_encrypt | aad_after_data_update | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_011_decrypt_without_set_tag_gcm | decrypt_without_set_tag | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_012_wrong_tag_length_gcm_decrypt | wrong_tag_length | mutation_case | run_ok | 0 | semantic_divergence_candidate | mutation_allowed_but_may_match_documented_low_level_semantics |
| aead_013_ctx_reuse_after_final_gcm_encrypt | ctx_reuse_after_final | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |
| aead_014_cleanup_then_update_gcm | cleanup_then_update | mutation_case | run_ok | 0 | expected_reject | mutation_rejected_by_api |

## Interpretation

这些标签只表示 harness 观察到的 API 状态机行为；`permissive_behavior` 和 `semantic_divergence_candidate` 都不是漏洞确认。需要跨库对照、文档语义核查和更强 oracle 之后，才能决定是否进入更深层的模式迁移或版本复现。
