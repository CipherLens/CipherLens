# Oracle v1 Push Checklist

只建议显式添加以下 oracle v1 相关文件。不要使用 `git add -A`，不要提交历史脏文件。

## 建议提交文件

- `analysis/crypto_library_oracle_taxonomy.py`
- `analysis/parser_full_consumption_oracle.py`
- `analysis/central_oracle_dispatcher.py`
- `analysis/crypto_oracle_bulk_adapter_registry.py`
- `analysis/batch_connect_existing_oracle_results.py`
- `analysis/pkey_sign_verify_lifecycle_oracle.py`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/adapter_dispatch_report.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/candidate_queue.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/classification_statistics.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/quality_report.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/resume_progress_snippet.md`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/safe_reject_baseline.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/semantic_observation_queue.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/unified_oracle_ledger.yaml`
- `artifacts/cross_library/mainline/batch_connect_existing_oracle_results_v1/unsupported_or_missing_report.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/dispatch_rules.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/dispatched_parser_results.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/dispatcher_design.md`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/dispatcher_input_schema.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/dispatcher_output_schema.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/integration_plan.yaml`
- `artifacts/cross_library/mainline/central_oracle_dispatcher_v1/quality_report.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/next_campaign_plan.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/oracle_decision_rules.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/oracle_gap_analysis.md`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/oracle_result_schema.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/oracle_taxonomy.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/quality_report.yaml`
- `artifacts/cross_library/mainline/crypto_library_oracle_taxonomy_v1/reclassified_existing_results.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/adapter_input_contracts.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/adapter_output_examples.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/adapter_registry.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/bulk_dispatch_mapping.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/crypto_oracle_common_patterns.md`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/existing_campaign_adapter_report.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/next_bulk_campaign_plan.yaml`
- `artifacts/cross_library/mainline/crypto_oracle_bulk_adapter_registry_v1/quality_report.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/app_vs_low_level_analysis.md`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/case_matrix.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/classification_summary.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/negative_control_report.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/oracle_results.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/quality_report.yaml`
- `artifacts/cross_library/mainline/parser_full_consumption_oracle_v2/resume_progress_snippet.md`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/candidate_queue_delta.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/case_matrix.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/classification_statistics.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/cross_library_consistency_report.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/dispatcher_inputs.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/negative_control_report.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/oracle_results.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/quality_report.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/raw_run_summary.yaml`
- `artifacts/cross_library/mainline/pkey_sign_verify_lifecycle_oracle_v1/resume_progress_snippet.md`

## 建议提交命令形态

使用 `git add <explicit file>` 逐项添加，提交前再次运行 `git diff --cached --name-only | sort` 复核。
