# Mainline Entrypoint Report

当前 `analysis/*.py` 数量：69。

主线入口已记录到 `analysis/mainline_entrypoints.yaml`，目录使用规则已记录到 `analysis/README.md`。当前主线入口包括 `full_mainline_pipeline_integration.py`、`full_mainline_glm_oracle_campaign.py`、`glm_live_probe.py`、`oracle_pipeline_integration.py` 和 `central_oracle_dispatcher.py`。

后续 Codex 不应在 `analysis/` 根目录创建一次性 helper；临时脚本应放入任务输出目录的 `scratch/` 下，并在任务结束后清理。
