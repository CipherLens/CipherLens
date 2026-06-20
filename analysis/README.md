# analysis/ Directory Guide

`analysis/` 现在包含主线入口、GLM/RAG 管线、oracle 管线、campaign runner、诊断脚本和历史辅助脚本。为了避免后续维护混乱，Codex 不应随意在 `analysis/` 根目录创建一次性临时脚本。

## 当前主线入口

- `analysis/full_mainline_pipeline_integration.py`: 只读索引完整主线，从 Pattern/RAG/GLM/adapter/case/compile-run 到 oracle ledger/queue。
- `analysis/full_mainline_glm_oracle_campaign.py`: 一键主线 smoke runner，支持 `--probe-mode live` 和 `--probe-mode existing`。
- `analysis/glm_live_probe.py`: 最小 GLM live probe，不记录真实 key。
- `analysis/oracle_pipeline_integration.py`: oracle v1 后半段接入入口。
- `analysis/central_oracle_dispatcher.py`: oracle 分类 dispatcher。

## 核心脚本类别

- `mainline_entrypoints`: 当前主线入口。
- `glm_rag_pipeline`: GLM/RAG/API-card/slot-filling 相关能力。
- `oracle_pipeline`: oracle taxonomy、adapter、dispatcher、ledger/queue 相关能力。
- `campaign_runners`: 历史 campaign、replay、compile/run 管线脚本。
- `cat_inspired_legacy`: CAT-inspired 历史脚本，保留但不作为当前主线入口。
- `diagnostics_and_triage`: 诊断、triage、候选审核脚本。
- `utility_or_archive`: 记录、调度、状态、注册表等辅助或历史脚本。

## 临时脚本规则

不要在 `analysis/` 根目录写 `tmp_*.py`、`debug_*.py`、`test_probe_*.py` 或 `*_scratch.py`。临时 helper 应放在：

```text
artifacts/cross_library/mainline/<task_name>/scratch/
```

任务结束后删除临时 helper，只保留可复现的 manifest、quality report、summary 和必要证据。不要把 API key、`.env`、二进制、`work/` 或 `compiled_cases/` 放进主线提交。

## Cleanup policy

1. `analysis/` 根目录只放可复用脚本和主线入口。
2. 临时调试脚本不要放 `analysis/`，应放 `artifacts/cross_library/mainline/<task>/scratch/`。
3. 一次性运行结果、日志、二进制、中间 YAML 不应放 `analysis/`。
4. 删除 tracked 历史脚本前必须人工确认。
5. Wycheproof 种子不放 `analysis/`，后续从 `knowledge_raw/wycheproof_vectors/` 接入。

## Recommended one-click usage

用户本地 WSL 真实联网运行：

```bash
PYTHONPATH=. python3 analysis/full_mainline_glm_oracle_campaign.py   --repo-root .   --out-dir artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1   --targets mbedtls-3.6.4-asan,mbedtls-4.1.0-asan,botan-3.10.0-asan   --families pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption   --seed-source mixed   --execution-mode syntax_only   --oracle-mode dispatch   --max-families 5   --max-cases 60   --max-compile-jobs 80   --probe-mode live
```

Codex 环境如果不能联网，推荐读取已有 live probe artifact：

```bash
PYTHONPATH=. python3 analysis/full_mainline_glm_oracle_campaign.py   --repo-root .   --out-dir artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1   --targets mbedtls-3.6.4-asan,mbedtls-4.1.0-asan,botan-3.10.0-asan   --families pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption   --seed-source mixed   --execution-mode syntax_only   --oracle-mode dispatch   --max-families 5   --max-cases 60   --max-compile-jobs 80   --probe-mode existing
```

Wycheproof seed bridge is planned for the next stage and is not enabled in this runner version.
