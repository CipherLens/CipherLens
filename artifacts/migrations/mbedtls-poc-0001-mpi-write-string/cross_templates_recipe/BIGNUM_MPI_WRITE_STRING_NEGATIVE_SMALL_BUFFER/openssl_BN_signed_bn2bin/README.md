# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER`
- Source API: `mbedtls_mpi_write_string`
- Source library: `mbedtls`
- Harness family: `buffer_canary_boundary`

## Target API

- Target library: `openssl`
- Target API: `BN_signed_bn2bin`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a bignum serialization buffer-boundary oracle.

Bug candidate behavior:

- target serialization overwrites the canary after the caller-provided output buffer;
- sanitizer output reports a memory-safety failure.

Safe behavior:

- target serialization rejects a too-small output buffer and the canary remains intact.

Triage behavior:

- target serialization succeeds into the caller-provided buffer and the canary remains intact. This is a normal serialization path that does not reproduce the original mbedTLS bug by itself.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
