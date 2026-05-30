# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `CIPHER_PKCS_PADDING_INVALID_OUTLEN_UNDERFLOW`
- Source API: `mbedtls_cipher_finish`
- Source library: `mbedtls`
- Harness family: `return_code_outlen_semantic`

## Target API

- Target library: `openssl`
- Target API: `EVP_DecryptFinal_ex`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a return-code plus output-length semantic oracle for invalid padding finalization.

Bug candidate behavior:

- target finalization API reports invalid padding failure;
- the caller-visible final output length is non-zero after that failure.

Safe behavior:

- target finalization API reports invalid padding failure;
- the caller-visible final output length remains zero.

Unexpected success is treated as a triage result because the input is constructed to contain invalid padding.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
