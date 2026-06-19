# Full Mainline Pipeline Integration v1

当前主线被整理为一条从真实历史 PoC / 漏洞模式到 oracle 分类的闭环。历史 PoC、issue、pattern bank 提供漏洞模式来源；normalized template 与 migration candidate 层把模式抽象为可迁移的 API / 参数 / 触发路径；RAG 与 API Cards 提供目标库 API 约束、能力矩阵和证据；GLM 只辅助 API 映射、参数绑定和 slot binding，失败时使用本地 fallback 与人工可审计规则。

adapter recipe 将模式落到具体密码库 API，case generation 生成受控 case manifest，compile / run 只产生 raw result 与 summary。raw result 进入 oracle bulk adapter，central dispatcher 依据 taxonomy 与 decision rules 统一分类，最终写入 unified ledger、candidate queue、semantic observation queue 和 safe reject baseline。

本系统不是单纯 PoC 复现，而是“真实漏洞模式驱动的跨库变异测试与 oracle 分类闭环”。`candidate_queue` 只是后续 triage 队列，不等同于已确认安全问题；normal reject、semantic difference、unsupported API 和 invalid contract 都必须保守分类。
