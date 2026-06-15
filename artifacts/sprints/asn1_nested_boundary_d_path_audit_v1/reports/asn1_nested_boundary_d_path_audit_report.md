# ASN.1 Nested Boundary D-Path Audit Report

## Why This Family

`asn1_nested_boundary` was selected because AEAD-GCM closed as negative feedback, while ASN.1/X.509 has reusable historical seeds and a clearer malformed nested-object oracle.

## Difference From DER Full-Consumption

- DER full-consumption: valid top-level DER object plus trailing garbage after the object.
- ASN.1 nested boundary: malformed child object, inner length/end-pointer mismatch, optional field problems, or nested substructure parsing inside the object.

## Seeds Found

- `MBEDTLS-POC-0017`
- `OPENSSL-ISSUE-30581`
- `OPENSSL-ISSUE-9043`

## MBEDTLS-POC-0017 Evidence

Current migration result is safe/safe: 16 `safe_reject_behavior` cases and 8 `migrated_safe` pairs for OpenSSL `d2i_X509`.

## OPENSSL-ISSUE-30581 Evidence

Local artifact is available and metadata reports `CLI+INPUT_SEED+CLI+SANITIZER_LOG`, component `PKCS12/ASN1`, trigger `NULL_DEREFERENCE_CRASH`, affected version `OpenSSL 4.1.0-dev`. However, the local artifact notes placeholder input was used and strict reproduction is not established.

## API Mapping

OpenSSL: `d2i_X509`, `d2i_X509_bio`, `X509_new`, `X509_free`, `ASN1_item_d2i`, `OSSL_DECODER`, `X509_verify_cert`, `d2i_PKCS12_fp`, `PKCS12_parse`.

mbedTLS: `mbedtls_x509_crt_parse`, `mbedtls_x509_crt_parse_der`, `mbedtls_x509_crt_free`.

## Oracle

Use safe rejection, full nested-content consumption when the malformed content belongs to the object, no-crash, cross-library semantic divergence, and app-level validation gap only when behavior reaches CLI/app level.

## A-Path / GLM

- Enter A-path now: no.
- GLM used now: no.
- Confirmed vulnerability: no.
- Continue family: yes, via D-path minimal reproducer.

## Next Task

`asn1_nested_boundary_minimal_reproducer_v1`
