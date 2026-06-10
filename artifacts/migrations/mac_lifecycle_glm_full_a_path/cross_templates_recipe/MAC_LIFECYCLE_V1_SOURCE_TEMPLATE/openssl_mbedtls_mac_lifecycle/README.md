# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `MAC_LIFECYCLE_V1_SOURCE_TEMPLATE`
- Source API: `None`
- Source library: `None`
- Harness family: `mac_lifecycle`

## Target API

- Target library: `cross_library`
- Target API: `mac_lifecycle_pair`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a MAC lifecycle state-transition semantic oracle.

Safe behavior:

- normal init/update/final completes successfully;
- repeated final, update-after-final, or abort-then-update is rejected without crash.

Triage behavior:

- a library accepts a terminal-state reuse sequence. This is recorded as semantic divergence or API-specific permissive behavior, not a confirmed vulnerability.

Bug candidate behavior requires explicit crash/sanitizer evidence or unsafe output-state evidence.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## AST Mask Selection

- Selected units: `6`
- Selection source: `artifacts/sprints/mac_lifecycle_family_v1/mask/selected_mask_units.yaml`
- Trace fields are written to `template_meta.yaml` and `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_cross_library.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
- `ast_mask_report.yaml`
- `selected_mask_units.yaml`
