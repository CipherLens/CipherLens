# OpenSSL PoC Artifacts

This directory contains standardized OpenSSL PoC artifacts used by CipherLens.

## Structure

- `poc_artifacts/issue_<id>/metadata.json`: standardized metadata
- `poc_artifacts/issue_<id>/poc.c`: C harness
- `poc_artifacts/issue_<id>/run.sh`: build and validation script
- `poc_artifacts/issue_<id>/inputs/`: placeholder or recovered input files
- `artifact_summary.csv`: tabular summary of selected artifacts
- `artifact_validation_results.jsonl`: validation records in JSONL format

## Artifact Classes

- `A_ast_ready`: C PoC directly extracted from issue evidence
- `B2_cli_to_c_candidate`: C harness translated from OpenSSL CLI PoC
- `C_rag_seed_to_c_candidate`: C harness generated from semantic issue seed

These harnesses validate API paths and artifact structure. Unless explicitly marked otherwise, they should not be interpreted as strict vulnerability reproductions.
