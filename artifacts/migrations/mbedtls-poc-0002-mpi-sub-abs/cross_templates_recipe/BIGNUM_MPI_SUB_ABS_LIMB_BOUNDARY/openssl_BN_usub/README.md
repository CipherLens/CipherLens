# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY`
- Source API: `mbedtls_mpi_sub_abs`
- Source library: `mbedtls`
- Harness family: `bignum_arithmetic_semantic`

## Target API

- Target library: `openssl`
- Target API: `BN_usub`
- LLM status: `ok`
- Adapter mode: `recipe slot bindings`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses a bignum arithmetic semantic projection oracle.

This is not a full memory-boundary migration of the original mbedTLS limb-storage bug. OpenSSL 3.x BIGNUM storage is opaque through the public API, so the direct canary-after-limbs oracle is intentionally not modeled here.

Safe behavior:

- for `lhs < rhs`, the target rejects or avoids producing a result for unsigned subtraction.

Triage behavior:

- for `lhs < rhs`, the target produces a result; this is a semantic-projection mismatch and requires review, not an automatic memory-corruption bug.

Normal behavior:

- for `lhs >= rhs`, unsigned subtraction is treated as the ordinary non-vulnerable arithmetic path.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
