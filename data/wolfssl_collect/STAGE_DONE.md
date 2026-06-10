# wolfSSL Collection Stage Done

## Stage Summary

The wolfSSL PoC collection and dataset construction stage has been completed for WOLFSSL-POC-0001 to WOLFSSL-POC-0004.

## Completed Outputs

- Q1 PoC inventory
- Vulnerability pattern summary
- Machine-readable pattern recipes
- Recipe search tool
- Pattern prompts
- Prompt index
- Pattern prompt JSONL dataset
- Code localization JSONL dataset
- Dataset README files
- JSONL validation script
- Artifact manifest

## Core Dataset Files

- inventory/wolfssl_poc_inventory.md
- inventory/wolfssl_pattern_summary.md
- inventory/wolfssl_pattern_recipes.json
- prompts/prompt_index.md
- data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl
- data/jsonl/wolfssl_code_localization_eval_v1.jsonl
- inventory/wolfssl_artifact_manifest.txt

## Validation Status

- Total PoCs: 4
- Q1 strict reproduction candidates: 4
- Vulnerable-version verified: 4
- Fixed-version verified: 4
- Current-version verified: 4
- Code localization JSONL validated samples: 4
- Code localization JSONL validation status: OK

## Current Dataset Scope

- Library: wolfSSL
- Focus: X.509 / ASN.1 / OpenSSL compatibility API / memory safety
- Patterns:
  - Pattern-01: X.509 name field repetition / loc array overflow
  - Pattern-02: X.509 text field fixed-size buffer off-by-one
  - Pattern-03: ASN1_TIME length trust boundary error
  - Pattern-04: AuthorityKeyIdentifier subfield/full-extension length confusion

## Recommended Next Step

Copy this collection into the main CryptoPoc project dataset area, then start the first model/RAG experiment using:

- data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl
- data/jsonl/wolfssl_code_localization_eval_v1.jsonl

