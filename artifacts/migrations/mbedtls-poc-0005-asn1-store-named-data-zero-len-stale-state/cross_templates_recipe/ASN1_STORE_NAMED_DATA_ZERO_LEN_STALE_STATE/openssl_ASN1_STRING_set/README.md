# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `ASN1_STORE_NAMED_DATA_ZERO_LEN_STALE_STATE`
- Source API: `mbedtls_asn1_store_named_data`
- Source library: `mbedtls`
- Harness family: `object_state_lifecycle`

## Target API

- Target library: `openssl`
- Target API: `ASN1_STRING_set`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a memory-safety oracle inherited from the source PoC pattern. The target API is executed with a caller-provided output buffer followed by a canary region.

Bug candidate behavior:

- canary corruption;
- sanitizer crash;
- out-of-bounds write signal.

Safe behavior:

- canary region remains intact;
- no sanitizer crash is observed.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
