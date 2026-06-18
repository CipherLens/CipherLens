# Central Oracle Dispatcher

`central_oracle_dispatcher` 不是新的 fuzz 模块，也不负责生成输入、编译 harness 或扩大 campaign 规模。它的职责是把不同 campaign 的原始运行结果转换为统一 oracle result schema，并用保守规则决定结果属于 baseline、observation、candidate event 还是需要人工复核的 semantic/API contract gap。

输入侧，dispatcher 接收统一字段，例如 source campaign、oracle type、target、input id、raw exit code、stdout/stderr 摘要、sanitizer/timeout 信号、expected/observed/control behavior 和 evidence files。输出侧，它固定给出 oracle type、classification、candidate level、confidence、evidence、overclaim guard 和下一步 triage action。

candidate queue 的入口只接受保守标签：`candidate_event`、`semantic_gap_candidate`、`robustness_candidate`、`API_contract_gap_candidate`。`normal reject`、`unsupported API`、`invalid contract` 和普通跨库语义差异不会直接进入 candidate queue。所有 candidate 标签都只是 triage 入口，不是最终安全结论。
