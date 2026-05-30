# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE`
- Source API: `mbedtls_pk_parse_key`
- Source library: `mbedtls`
- Harness family: `der_pointer_consumption`

## Target API

- Target library: `openssl`
- Target API: `d2i_PrivateKey`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a pointer-consumption semantic oracle for DER parsing.

Bug candidate behavior:

- target decoder returns success;
- `consumed_len < der_len`, meaning the first DER object was decoded while trailing garbage remained unconsumed.

Safe behavior:

- target decoder rejects the trailing-garbage input; or
- target decoder succeeds and `consumed_len == der_len`.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
