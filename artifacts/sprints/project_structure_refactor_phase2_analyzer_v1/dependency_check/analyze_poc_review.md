# analyze_poc Review

```yaml
schema: analyze_poc_review_v1
generated_at: '2026-06-12T07:42:56+00:00'
file: analyzer/analyze_poc.py
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
delete_allowed: true
delete_reason: superseded_by_family_level_analyzer
migrated_or_recorded_logic:
- PoC C source extraction logic recorded in this review; not needed by current runtime/oracle-aware
  analyzer path
- family-level semantic labels migrated to analyzer/semantic_labels.py
- candidate labels migrated to analyzer/candidate_labels.py
- oracle-aware case/family analysis migrated to analyzer/oracle_aware_analyzer.py
```
