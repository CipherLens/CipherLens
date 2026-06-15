# wolfSSL Pattern Prompt Evaluation Dataset v1

## Dataset File

- File: data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl
- Format: JSON Lines
- Total samples: 4
- Library: wolfSSL
- Task type: vulnerability_pattern_search

## Purpose

This dataset converts manually validated wolfSSL vulnerability patterns into LLM/RAG-ready evaluation samples.

Each sample contains:

- a natural-language vulnerability pattern prompt
- the corresponding machine-readable recipe
- PoC metadata
- an expected output schema for suspicious code-region reports

The dataset is intended for:

- LLM/RAG vulnerability pattern search
- AST masking experiment input generation
- structured mutation planning
- fuzz seed selection
- cross-library vulnerability pattern migration

## Source Materials

This dataset is derived from:

- inventory/wolfssl_poc_inventory.csv
- inventory/wolfssl_poc_inventory.md
- inventory/wolfssl_pattern_summary.md
- inventory/wolfssl_pattern_recipes.json
- prompts/pattern_*.md
- WOLFSSL-POC-0001 to WOLFSSL-POC-0004 metadata files

## Samples

| Sample ID | Pattern ID | Related PoC | Trigger Surface |
|---|---|---|---|
| wolfssl_pattern_01 | Pattern-01 | WOLFSSL-POC-0001 | x509_name_parser |
| wolfssl_pattern_02 | Pattern-02 | WOLFSSL-POC-0002 | openssl_compat_x509_text_extraction |
| wolfssl_pattern_03 | Pattern-03 | WOLFSSL-POC-0003 | x509_time_setter_getter_api |
| wolfssl_pattern_04 | Pattern-04 | WOLFSSL-POC-0004 | x509_authority_key_identifier_reencode |

## JSONL Schema

Each line is a JSON object with the following fields:

- sample_id: unique sample identifier
- library: source library name
- task_type: task type label
- pattern_id: pattern identifier
- related_pocs: related PoC IDs
- prompt: full LLM/RAG prompt text
- recipe: machine-readable vulnerability pattern recipe
- poc_metadata: selected metadata from the corresponding PoC
- expected_output_schema: expected format for model output

## Quality Guarantees

All four samples are based on Q1 strict reproduction candidates.

Each related PoC has:

- vulnerable-version reproduction
- fixed-release validation
- current-version validation
- sanitizer crash or safe-rejection evidence

## Intended Evaluation Use

A model receives the prompt and source code context, then reports suspicious code regions that match the vulnerability pattern.

Expected model output should include:

- function name
- file path
- relevant variables
- guard condition
- copy or write operation
- destination capacity
- matched recipe slots
- why the code matches the pattern
- suggested mutation or test input shape

## Limitations

This JSONL does not yet include source code snippets, masked code, ground-truth vulnerable lines, or model answers.

It is a pattern-prompt dataset, not a full code-localization benchmark.

A future version can extend each sample with:

- vulnerable source code snippets
- fixed source code snippets
- masked AST regions
- ground-truth vulnerable operations
- expected answer text
