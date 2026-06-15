# historical_poc_ingestion_v1 input config

| library | root |
| --- | --- |
| mbedtls | data/pocs |
| wolfssl | data/wolfssl_collect |
| openssl | datasets/openssl/poc_artifacts |

## Rules

- Use status=ready_for_ingestion artifacts first.
- Preserve metadata_summary and artifact_files verbatim.
- Do not execute run.sh or compile poc.c during ingestion.
- Route metadata_only/missing_metadata/needs_manual_review to manual triage.
