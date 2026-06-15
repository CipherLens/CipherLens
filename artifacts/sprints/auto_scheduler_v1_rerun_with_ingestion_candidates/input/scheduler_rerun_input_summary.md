# scheduler rerun input summary

- 本轮新增输入来自 `ingestion_review_and_import_v1`。
- 只使用 `high_confidence_import_candidate` 和 `medium_confidence_staging`。
- `blocked` / `needs_manual_review` 不进入主调度。
- 本轮是 staging-only rerun，不写正式 Pattern Bank。

| metric | value |
| --- | --- |
| input_source | ingestion_review_and_import_v1 plus existing auto_scheduler_v1 outputs |
| base_scheduler_dir | artifacts/sprints/auto_scheduler_v1 |
| reviewed_candidates | 50 |
| eligible | 40 |
| excluded | 10 |
| feedback_files | 16 |
| feedback_rows | 238 |
