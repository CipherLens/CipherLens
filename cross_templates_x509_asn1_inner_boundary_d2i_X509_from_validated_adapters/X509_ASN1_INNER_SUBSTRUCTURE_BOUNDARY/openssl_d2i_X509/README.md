# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY`
- Source API: `mbedtls_x509_crt_parse_der`
- Source library: `mbedtls`
- Harness family: `x509_asn1_inner_boundary`

## Target API

- Target library: `openssl`
- Target API: `d2i_X509`
- LLM status: `fallback`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

The migrated harness uses an X.509 / ASN.1 inner-boundary semantic oracle.

Bug candidate behavior:

- `d2i_X509()` returns a non-NULL X509 object;
- the harness maps this to `ret == 0`, meaning the target accepted malformed inner-boundary DER.

Safe behavior:

- `d2i_X509()` returns NULL;
- the harness maps this to `ret != 0`, meaning the target rejected the malformed DER.

The harness also records `consumed_len` for pointer-consumption analysis, but it does not require OpenSSL to reproduce mbedTLS numeric error codes.


## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_openssl.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
