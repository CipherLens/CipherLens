# wolfSSL Code Localization Evaluation Dataset v1

## Dataset File

- File: data/jsonl/wolfssl_code_localization_eval_v1.jsonl
- Format: JSON Lines
- Total samples: 4
- Library: wolfSSL
- Task type: vulnerability_code_localization

## Purpose

This dataset extends the wolfSSL vulnerability pattern prompt dataset with source-code localization information.

Each sample contains:

- vulnerability pattern prompt
- machine-readable recipe
- PoC metadata
- vulnerable source code snippet
- fixed source code snippet
- masked vulnerable code
- ground-truth localization metadata
- ground-truth natural-language answer
- expected model output schema

The dataset is intended for:

- AST masking experiments
- RAG-assisted vulnerability localization
- LLM code-region localization evaluation
- recipe-slot based vulnerability search
- structured mutation planning

## Source Samples

| Sample ID | Pattern ID | Related PoC | Ground Truth Function | Ground Truth File |
|---|---|---|---|---|
| wolfssl_pattern_01 | Pattern-01 | WOLFSSL-POC-0001 | GetName | wolfcrypt/src/asn.c |
| wolfssl_pattern_02 | Pattern-02 | WOLFSSL-POC-0002 | wolfSSL_X509_NAME_get_text_by_NID | src/ssl.c |
| wolfssl_pattern_03 | Pattern-03 | WOLFSSL-POC-0003 | wolfSSL_X509_set_notAfter | src/x509.c |
| wolfssl_pattern_04 | Pattern-04 | WOLFSSL-POC-0004 | CertFromX509 | src/x509.c |

## JSONL Fields

Each line contains one JSON object with:

- sample_id
- library
- task_type
- pattern_id
- related_pocs
- prompt
- recipe
- poc_metadata
- expected_output_schema
- source_context
- vulnerable_code
- fixed_code
- masked_code
- ground_truth
- ground_truth_answer

## Code Fields

### vulnerable_code

The source snippet extracted from the vulnerable version.

### fixed_code

The corresponding source snippet extracted from the fixed version.

### masked_code

The vulnerable snippet with key vulnerable operations masked. This field is intended for AST masking or fill-in-the-vulnerability experiments.

### ground_truth

Structured localization metadata, including:

- file
- function
- vulnerable_operation
- guard_condition
- destination_capacity
- matched_recipe_slots

### ground_truth_answer

A natural-language answer explaining why the code region matches the vulnerability pattern.

## Quality Guarantees

All samples are derived from Q1 strict reproduction candidates.

Each related PoC has:

- vulnerable-version reproduction
- fixed-release validation
- current-version validation
- sanitizer crash or safe-rejection evidence

## Current Limitations

This dataset currently contains wolfSSL-only samples.

It does not yet include:

- full source files
- AST node spans
- token-level masks
- model output baselines
- cross-library target code

## Recommended Next Extensions

Future versions can add:

- AST node ranges
- exact vulnerable line ranges
- before/after patch diff
- model baseline outputs
- cross-library candidate snippets from OpenSSL, mbedTLS, Botan, or LibreSSL
