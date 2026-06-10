# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE`
- Source API: `None`
- Source library: `None`
- Harness family: `object_state_lifecycle`

## Target API

- Target library: `mbedtls`
- Target API: `psa_mac_sign_setup`
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

## AST Mask Selection

- Selected units: `8`
- Selection source: `normalized_templates/openssl/evp_mac_get_size_uninit_lifecycle/selected_mask_units.yaml`
- Trace fields are written to `template_meta.yaml` and `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_mbedtls.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
- `ast_mask_report.yaml`
- `selected_mask_units.yaml`
