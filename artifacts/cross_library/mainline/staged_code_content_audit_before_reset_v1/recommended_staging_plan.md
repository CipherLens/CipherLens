# Recommended Staging Plan

当前暂存区不建议直接 commit。建议先清空暂存区后按清单重建：

```bash
git restore --staged .
```

然后只显式添加 keep 清单中的路径，例如：

```bash
# mainline scripts / docs
git add analysis/README.md analysis/mainline_entrypoints.yaml analysis/script_inventory.yaml
git add analysis/full_mainline_glm_oracle_campaign.py analysis/glm_connectivity_diagnose.py

# selected mainline artifacts
git add artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1/
git add artifacts/cross_library/mainline/safe_all_branch_cleanup_commit_push_v1/
git add artifacts/cross_library/mainline/analysis_dead_code_audit_cleanup_before_push_v1/
```

不要使用 `git add -A` 直接提交当前暂存区；当前暂存区包含大量历史 campaign/replay/research/data 产物。
