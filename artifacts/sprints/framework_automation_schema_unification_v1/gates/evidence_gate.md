# Evidence Gate

The evidence gate exists because RAG can be imprecise, LLMs can invent structure, and cross-library APIs are often not equivalent. The gate converts uncertainty into explicit block/demote decisions.

```yaml
schema_version: 1
evidence_gate:
  rag_source_priority:
  - official_doc
  - source_code
  - official_test
  - issue_metadata
  - sanitizer_log
  - prior_artifact
  - third_party_or_unknown
  evidence_strength:
    strong:
      requirements:
      - official_doc_or_source_code
      - reproducible_behavior_or_existing_result
    medium:
      requirements:
      - prior_artifact
      - partial_doc_or_test_evidence
    weak:
      requirements:
      - metadata_only
      - ambiguous_rag_result
    insufficient:
      requirements:
      - placeholder_only
      - missing_seed
      - mapping_gap_without_oracle
  gate_rules:
  - if: seed_missing
    then: no_D_path_reproduction
  - if: placeholder_only
    then: no_crash_claim
  - if: mapping_gap
    then: no_A_path
  - if: rag_evidence_weak
    then: no_auto_render
  - if: normal_control_missing
    then: no_mutation_claim
  - if: legal_semantics_evidence_strong
    then: write_negative_feedback
  rag_inaccuracy_controls:
  - require source path and layer metadata
  - prefer official/source/test evidence
  - treat metadata-only as weak unless paired with reproduction
  - emit missing evidence reasons
  llm_hallucination_controls:
  - LLM cannot invent API contracts
  - LLM cannot generate free-form C
  - LLM output must be slot_bindings validated against recipe
  cross_library_equivalence_controls:
  - score vulnerability_path separately
  - require oracle comparability
  - demote mapping_gap to no_A_path or needs_triage
```
