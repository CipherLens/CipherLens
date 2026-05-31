# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `PSA_AEAD_INVALID_SHORTENED_TAG_SETUP`
- Source API: `psa_aead_decrypt_setup`
- Source library: `mbedtls`
- Harness family: `invalid_parameter_setup_oracle`

## Target API

- Target library: `openssl`
- Target API: `EVP_CIPHER_CTX_ctrl`
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
