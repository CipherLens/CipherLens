# Artifact Map

## Pattern Bank

`artifacts/pattern_bank/` is a generated but important knowledge layer. Commit the YAML and README snapshots when they reflect a reviewed milestone.

## RAG Sources

`knowledge_raw/poc_patterns/` is input knowledge. It should be committed, but it must stay consistent with `unified_pattern_bank.yaml`.

## Feedback

`artifacts/feedback/` stores verdict feedback and mutation scores. It is useful evidence and should be committed at milestones, preferably with run provenance.

## Execution Plan

`artifacts/execution_plan/` is report/output from scheduler routing. Commit with the scheduler seed and candidate queue.

## A-path

`artifacts/migrations/mac_lifecycle_glm_full_a_path/` is the completed full A-path representative. Commit reports, result JSON, summaries, and source templates. Logs can be committed if small, but build binaries should not.

## C-path

`artifacts/sprints/der_full_consumption_v2/` is the DER app-level validation-gap representative. Commit summary reports, manifests, and representative rendered cases; avoid bulky or reproducible logs.

## D/B-path

`artifacts/sprints/secure_heap_state_lifecycle_v1/` is seed validation and robustness qualification. Commit final reports, version provenance, novelty assessment, and compact results. Treat binaries and repeated debug logs as `.gitignore` candidates.

## Framework Alignment and RAG Validation

`artifacts/framework_alignment_audit/` and `artifacts/rag_rebuild_validation/` should be committed as framework-milestone evidence. Logs are useful for traceability but can be split or ignored if they become noisy.
