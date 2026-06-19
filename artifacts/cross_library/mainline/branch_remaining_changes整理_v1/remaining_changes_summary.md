# Remaining Changes Summary

当前 HEAD: `2b1ad42`。最近提交中 oracle v1 已经在 `2b1ad42` 提交并推送，本轮只整理剩余 modified / untracked 文件，不执行 `git add`、`git commit` 或 `git push`。

当前工作区仍然长期不干净，剩余变更横跨 `analysis/`、`artifacts/cross_library/mainline/`、`artifacts/cross_library/`、历史 `campaigns/`、`sprints/`、`work/`、二进制和日志输出。不能直接使用 `git add -A`，因为这样会把大量缓存、编译产物、历史实验输出和来源不明确的中间产物一起带入提交。

建议后续只按 `should_commit_list.md` 中的显式路径分主题提交；`maybe_commit_need_user_confirm.md` 中的内容需要用户确认主题和范围；`do_not_commit_list.yaml` 中的内容默认不提交。

## 分类计数

- 未提交文件总数: 2309
- 建议提交: 65
- 需要用户确认: 483
- 不建议提交: 1761
- 大文件风险: 1355
