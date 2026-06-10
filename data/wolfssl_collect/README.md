# wolfSSL Vulnerability PoC and Pattern Dataset

## Overview

This repository contains a curated wolfSSL vulnerability reproduction and pattern-analysis dataset.

Current dataset status:

- Q1 strict reproduction PoCs: 10
- Vulnerability patterns: 10
- Pattern prompt evaluation samples: 10
- Code localization evaluation samples: 10
- Rejected candidates: 1

## Purpose

This dataset is designed for:

- vulnerability pattern extraction
- LLM/RAG vulnerability search
- code localization evaluation
- AST masking experiments
- sanitizer-oracle reproduction validation
- structured vulnerability recipe construction

## Dataset Scope

| Area | Samples |
|---|---|
| X.509 / ASN.1 parsing | WOLFSSL-POC-0001, 0002, 0003, 0004 |
| DTLS 1.3 serialization | WOLFSSL-POC-0005 |
| PKCS7 / CMS | WOLFSSL-POC-0006, 0007 |
| TLS 1.3 PQC cleanup | WOLFSSL-POC-0008 |
| SSL_SESSION deserialization | WOLFSSL-POC-0009 |
| ALPN / NPN parsing | WOLFSSL-POC-0010 |

## Main Artifacts

| Path | Description |
|---|---|
| inventory/wolfssl_poc_inventory.md | Human-readable PoC inventory |
| inventory/wolfssl_poc_inventory.csv | Machine-readable PoC inventory |
| inventory/wolfssl_rejected_candidates.md | Rejected candidate records |
| inventory/wolfssl_pattern_summary.md | Human-readable pattern summary |
| inventory/wolfssl_pattern_recipes.json | Machine-readable pattern recipes |
| prompts/prompt_index.md | Pattern prompt index |
| data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl | Pattern prompt evaluation dataset |
| data/jsonl/wolfssl_code_localization_eval_v1.jsonl | Code localization evaluation dataset |
| inventory/wolfssl_artifact_manifest.txt | Artifact manifest |

## Quality Definition

A PoC is marked as Q1_strict_reproduction_candidate only when:

1. The vulnerable version is verified with a sanitizer-visible crash or equivalent memory-safety oracle.
2. The fixed version safely rejects or handles the same input.
3. The current version behaves safely.
4. The input provenance and reproduction route are documented.
5. The PoC is mapped to a structured vulnerability pattern.

## Directory Layout

Each PoC directory follows this structure:

- metadata.json
- poc/
- inputs/
- logs/
- notes/
- sources/

## Final Milestone

The dataset has reached the planned 10-PoC milestone.

Next stage:

- dataset schema documentation
- statistics summary
- validation script
- final artifact manifest check
