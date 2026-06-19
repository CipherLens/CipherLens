# Mainline Current Architecture

当前 HEAD: `2b1ad42 Add oracle v1 taxonomy dispatcher and adapters`。

本轮整理后，oracle v1 已通过 `analysis/oracle_pipeline_integration.py` 接入主线入口。该入口读取 dispatcher schema、dispatch rules、bulk adapter registry，以及 batch connector 生成的 unified ledger / candidate queue / semantic observation queue / safe reject baseline。

主线流程保持为：campaign 产生 raw result -> adapter registry 归一化输入 -> central dispatcher 分类 -> batch connector 写入 unified oracle ledger -> integration 层暴露 candidate_queue、semantic_observation_queue、safe_reject_baseline。

`candidate_queue` 只表示后续 triage 队列，不表示漏洞确认。当前清理没有运行 fuzz、render、compile、target run，也没有修改 OpenSSL / wolfSSL build。
