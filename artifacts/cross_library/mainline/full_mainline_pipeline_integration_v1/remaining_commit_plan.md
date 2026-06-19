# Remaining Commit Plan

不要使用 `git add -A`。建议下一步只做精确提交，范围可以限定为：

- analysis/oracle_pipeline_integration.py
- analysis/full_mainline_pipeline_integration.py
- artifacts/cross_library/mainline/oracle_pipeline_integration_v1/
- artifacts/cross_library/mainline/mainline_oracle_integration_cleanup_v1/
- artifacts/cross_library/mainline/post_cleanup_mainline_smoke_v1/
- artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/

不要提交 `compiled_cases/`、`work/`、`*.bin`、`*.so`、`*.a`、大型 `*.log`、seed_enrichment 历史产物或旧 campaign 临时产物。
