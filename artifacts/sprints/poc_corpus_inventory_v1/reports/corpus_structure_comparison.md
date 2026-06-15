# Corpus structure comparison

## mbedtls

nested core10/MBEDTLS-POC-XXXX artifacts with metadata.json, README.md, poc/ and evidence files

## wolfssl

WOLFSSL-POC-XXXX evidence bundles with inputs/logs/sources/scripts/notes and richer reproduction metadata

## openssl

flat issue_XXXXX artifacts with metadata.json, README.md, poc.c, run.sh and optional inputs

## Ingestion fallback requirements

- ID normalization from MBEDTLS-POC-XXXX, WOLFSSL-POC-XXXX, and issue_XXXXX/issue_number.
- Metadata key fallback across mbedTLS traceability/classification, wolfSSL harness/oracle fields, and OpenSSL issue artifact fields.
- PoC source detection must accept poc.c, poc/ directories, scripts/run.sh, and input-only evidence bundles.
- Do not infer vulnerability confirmation from corpus metadata; preserve strict_reproduction/local_test_result as evidence fields only.
