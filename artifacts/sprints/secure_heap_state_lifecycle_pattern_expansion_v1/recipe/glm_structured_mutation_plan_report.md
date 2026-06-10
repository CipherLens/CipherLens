# GLM Structured Mutation Plan

`glm_status: not_used`

本轮没有使用 GLM。原因是当前已有的 `adapter_filler` 主要服务 A-path recipe-slot adapter 生成，而本轮是 B-path same-family state expansion。为了避免把 A-path adapter 机制硬套到 secure heap lifecycle family，本轮直接使用结构化 `mutation_plan.yaml` 和 `render_matrix.yaml`。

边界保持不变：GLM 即使用于本 family，也只能填写 `api_group_selection`、`state_sequence_selection`、`expected_controls`、`oracle_mapping`、`novelty_labels`，不能生成 `init_block`、`trigger_block`、`cleanup_block` 或任何 free-form C。
