# Full Mainline GLM Oracle Campaign v1

本轮跑的是一个 bounded mainline campaign：从现有 PoC/pattern bank 与 mainline RAG/API-card 证据中选择 4 个 family，经由 GLM 生成新的 adapter recipe / slot binding 摘要，再把小规模 case/raw result 接入 oracle dispatcher。

GLM 实际参与了 adapter recipe 与 slot binding 阶段：request_count=4，success_count=4，fallback_count=0。本轮没有把 fallback 静默写成 GLM 成功，也没有保存 API key。

本轮生成 adapter recipe 4 份、slot binding 4 份，case/raw result 33 条。compile/run 层采用已有 ready mainline artifact 的小规模摘要作为可复现输入，没有新建长期 compiled_cases，也没有运行大规模 fuzz。

oracle dispatcher 对 raw result 做保守分类：candidate_event=0，semantic_gap_candidate=1，robustness_candidate=0，semantic_observation=2，safe_reject=27，unsupported=3。

新的 candidate/observation 都只是 triage 入口。candidate queue 不等同于安全结论；normal reject、unsupported、invalid contract 和普通 semantic difference 不升级为漏洞结论。
