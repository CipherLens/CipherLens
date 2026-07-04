# tools/mainline

Thin user/team CLI wrappers for the current mainline.

- `run_one_click_glm_oracle_campaign.py` delegates to `analysis/full_mainline_glm_oracle_campaign.py`, the unique core automation entrypoint.
- `run_multi_target_family_campaign.py` is an optional bounded multi-target wrapper. It must not claim runtime behavior when execution falls back to syntax-only.

Do not add new runner scripts to `analysis/` or to the `tools/` root. New wrappers belong in this directory; temporary helper scripts belong under `artifacts/cross_library/mainline/<task>/scratch/`.

## Framework References

Use these reports before changing the mainline script set:

```text
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/framework_tree.md
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/automation_involved_files.yaml
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/dependency_closure_explanation.md
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/next_delete_review_table.md
```

`dependency_closure_count` only captures strong AST/dynamic dependencies of `analysis/full_mainline_glm_oracle_campaign.py`; it is not the full list of protected mainline modules.
