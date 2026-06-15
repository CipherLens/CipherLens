# project_structure_refactor_phase2_analyzer_v1 Report

```yaml
schema: project_structure_refactor_phase2_analyzer_v1_report
generated_at: '2026-06-12T07:44:40+00:00'
analyze_poc:
  original_function: lightweight C PoC structure extractor for includes, macros, function
    calls, API calls, trigger call, library guess, and simple oracle helper names
  valuable_logic:
  - include extraction
  - macro extraction
  - lightweight function call extraction
  - library guess from includes/API names
  - trigger call heuristic
  - simple canary/fixed-ret oracle helper detection
  superseded_by_family_level_chain:
  - template/mask metadata now carries source/target family information
  - oracle-aware analysis consumes compile/run/oracle-event YAML instead of raw PoC
    C files
  - family_result_adapter reuses runner.analyze_results classify_record for raw verdicts
  - oracle_event_parser parses explicit ORACLE_EVENT records
  - new semantic_labels/candidate_labels modules hold family-level labels
  dependency_check:
    imports: 0
    import_refs_sample: []
    cli_refs: 0
    active_doc_refs: 0
    active_doc_refs_sample: []
    active_pipeline_refs: 0
    active_pipeline_refs_sample: []
    artifact_refs: 127
    artifact_refs_note: historical sprint artifact references only; not active pipeline
      entrypoints
  deleted: true
  delete_reason: superseded_by_family_level_analyzer
refactor_result:
  schema: analyzer_refactor_phase2_summary_v1
  generated_at: '2026-06-12T07:44:40+00:00'
  new_core_modules:
  - analyzer/oracle_aware_analyzer.py
  - analyzer/semantic_labels.py
  - analyzer/candidate_labels.py
  tools_wrappers_updated:
  - tools/analyze_results_v1.py
  - tools/analyze_results_oracle_aware_v1.py
  tools_wrappers_preserved: true
  cli_backward_compatible: true
  oracle_parser_reused: true
  family_result_adapter_reused: true
  analyze_poc_deleted: true
  delete_decision:
    file: analyzer/analyze_poc.py
    delete_allowed: true
    deleted: true
    reason: superseded_by_family_level_analyzer
    generated_at: '2026-06-12T07:43:15+00:00'
    dependency_check:
      imports: 0
      cli_refs: 0
      active_doc_refs: 0
      active_pipeline_refs: 0
    migrated_or_recorded_logic:
    - PoC C source extraction logic recorded in this review; not needed by current
      runtime/oracle-aware analyzer path
    - family-level semantic labels migrated to analyzer/semantic_labels.py
    - candidate labels migrated to analyzer/candidate_labels.py
    - oracle-aware case/family analysis migrated to analyzer/oracle_aware_analyzer.py
  smoke_test:
    executed: true
    input: artifacts/sprints/compile_run_oracle_instrumented_v1/ + artifacts/sprints/analyze_results_oracle_aware_v1/
    cases_analyzed: 14
    accepted_true: 0
    full_consumption_gap_candidate: 0
    original_cases_analyzed: 14
    original_accepted_true: 0
    original_full_consumption_gap_candidate: 0
    consistent_with_original: true
  next_task: project_structure_refactor_phase3_mutation_or_analysis_v1
quality_checks:
  schema: analyzer_refactor_quality_checks_v1
  generated_at: '2026-06-12T07:44:40+00:00'
  core_modules_created: true
  tools_wrappers_preserved: true
  analyze_poc_reviewed: true
  analyze_poc_deleted: true
  only_allowed_file_deleted: true
  files_deleted:
  - analyzer/analyze_poc.py
  cli_backward_compatible: true
  smoke_test_executed: true
  smoke_test_pass: true
  render_executed: false
  compile_executed: false
  run_executed: false
  feedback_written: false
  adapter_recipes_modified: false
  normalized_templates_modified: false
  knowledge_modified: false
  glm_called: false
  git_add_commit_push: false
  quality_status: pass
next_task: project_structure_refactor_phase3_mutation_or_analysis_v1
notes:
- No render/compile/run was executed; smoke test was offline analyzer rerun only.
- No feedback, adapter_recipes, normalized_templates, knowledge, Pattern Bank, or
  scheduler files were modified by this task.
- No vulnerability claim is made.
```
