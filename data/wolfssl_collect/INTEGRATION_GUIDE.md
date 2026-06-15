# wolfSSL PoC Dataset Integration Guide

## Summary

This directory contains the collected wolfSSL PoC dataset.

Current status:

- Q1 strict reproduction PoCs: 10
- Vulnerability patterns: 10
- Pattern prompt eval rows: 10
- Code localization eval rows: 10
- Rejected candidates: 1

## Recommended Entry Points

- README.md
- inventory/wolfssl_poc_inventory.md
- inventory/wolfssl_pattern_summary.md
- inventory/wolfssl_final_status.md
- inventory/wolfssl_artifact_manifest.txt
- data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl
- data/jsonl/wolfssl_code_localization_eval_v1.jsonl

## Validation

Run this command before integration:

./scripts/validate_wolfssl_dataset.sh

Expected result:

- pattern prompt JSONL rows: 10
- validated_samples: 10
- validation_status: OK
- wolfSSL dataset validation passed

## Integration Notes

PoC source files are stored under each WOLFSSL-POC-XXXX/poc directory.

The dataset can support:

- PoC reproduction
- vulnerability pattern extraction
- RAG retrieval experiments
- AST masking experiments
- code localization evaluation

Do not commit local build directories or compiled ASan binaries.
