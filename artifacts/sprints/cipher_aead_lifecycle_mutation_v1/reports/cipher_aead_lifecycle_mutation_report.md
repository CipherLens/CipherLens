# Cipher AEAD Lifecycle Mutation Report

## Scope

- family: `cipher_aead_lifecycle`
- target library: `openssl`
- target API group: `EVP AEAD/GCM`
- selected cases: 12 from the 24-case draft
- algorithm priority: `aes-128-gcm`
- full 24-case run: no

## Results

- total_cases: 12
- raw_status_counts: `{'run_ok': 12}`
- classification_counts: `{'expected_reject': 7, 'normal_control_ok': 2, 'permissive_behavior': 1, 'semantic_divergence_candidate': 2}`
- normal_controls_passed: True
- high_value_candidates: 3

## High Value Triage Candidates

- `aead_006_final_without_update_gcm_encrypt` `final_without_update`: `semantic_divergence_candidate`; observed `mutation_allowed_but_may_match_documented_low_level_semantics`
- `aead_009_set_tag_after_final_gcm_decrypt` `set_tag_after_final`: `permissive_behavior`; observed `mutation_allowed_by_api`
- `aead_012_wrong_tag_length_gcm_decrypt` `wrong_tag_length`: `semantic_divergence_candidate`; observed `mutation_allowed_but_may_match_documented_low_level_semantics`

## Interpretation

本轮没有 crash/sanitizer 证据，也没有确认漏洞结论。`expected_reject` 表示 OpenSSL 对该状态序列给出了拒绝；`permissive_behavior` 和 `semantic_divergence_candidate` 只表示值得做 API 文档核查和跨库对比。

## Next Steps

1. 将 3 个 high-value triage candidate 映射到 Botan / mbedTLS AEAD lifecycle 对应 API。
2. 区分 GCM 合法低层语义和真正状态机不一致行为，避免把正常允许行为误报为漏洞。
3. 等跨库对照稳定后，再沉淀 family-level recipe / mutation slot。
