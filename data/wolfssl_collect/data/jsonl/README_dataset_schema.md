# wolfSSL Dataset Schema

## Pattern Prompt JSONL

Path:

- data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl

Expected rows:

- 10

Main fields:

- sample_id
- library
- task_type
- pattern_id
- related_pocs
- prompt
- recipe
- poc_metadata

## Code Localization JSONL

Path:

- data/jsonl/wolfssl_code_localization_eval_v1.jsonl

Expected rows:

- 10

Main fields:

- sample_id
- library
- task_type
- pattern_id
- vulnerable_code
- fixed_code
- masked_code
- ground_truth
- ground_truth_answer
- recipe

## PoC Metadata

Each PoC directory contains:

- metadata.json

Important fields:

- poc_id
- issue_or_cve
- title
- bug_class
- input_type
- input_provenance
- quality_level
- vulnerable_version_verified
- fixed_version_verified
- current_version_verified
- strict_reproduction
- crash_signal
- fixed_behavior
- current_behavior
- reproduction_summary

## Pattern Recipe

Path:

- inventory/wolfssl_pattern_recipes.json

Important fields:

- pattern_id
- name
- related_pocs
- bug_class
- trigger_surface
- input_type
- quality_level
- bug_mechanism
- recipe_slots
- mutation_strategy
- oracle
- rag_keywords
- dataset_tags

## Quality Level

Accepted Q1 level:

- Q1_strict_reproduction_candidate

A Q1 sample has:

- vulnerable-version sanitizer/crash oracle
- fixed-version safe behavior
- current-version safe behavior
- documented reproduction route
- mapped vulnerability pattern
