# Migration Artifact Index

New migration outputs should be placed under:

```text
artifacts/migrations/<artifact_slug>/
```

Recommended subdirectories:

```text
adapters/
adapters_validated/
cross_templates/
rendered_cases/
results/
logs/
```

## Current Slug Mapping

| PoC ID | artifact_slug | status | notes |
| --- | --- | --- | --- |
| `MBEDTLS-POC-0001` | `mbedtls-poc-0001-mpi-write-string` | `complete_runnable` in legacy layout | New artifact root has placeholders only. Legacy result: `migrated_safe`. |
| `MBEDTLS-POC-0002` | `mbedtls-poc-0002-mpi-sub-abs` | `evidence_only` | Candidates and evidence exist, but no adapter/validated adapter was found. |
| `MBEDTLS-POC-0004` | `mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow` | `migrated_safe` | Uses recipe/slot-filling layout for `EVP_DecryptFinal_ex`. |
| `MBEDTLS-POC-0017` | `mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509` | `migrated_safe` | Re-run under new artifact layout on 2026-05-29. |
| `MBEDTLS-POC-0020` | `mbedtls-poc-0020-rsa-der-trailing-garbage` | `migrated_bug_candidate` | Re-run under new artifact layout on 2026-05-29. |

## Status Meanings

- `complete_runnable`: normalized template, candidates/evidence, adapter or validated adapter, cross template, rendered cases, and results are present somewhere in the repository.
- `evidence_only`: candidates and RAG evidence are present, but adapter generation/validation is not complete.
- `migrated_safe`: source and target both show safe behavior for the rendered cases.
- `migrated_bug_candidate`: source safe behavior and target bug-like semantic behavior were observed.

## Current Result Files

| PoC ID | result path | migration summary |
| --- | --- | --- |
| `MBEDTLS-POC-0001` | `runner/results/run_cross_mpi_write_string.summary.json` | `runner/results/run_cross_mpi_write_string.migration_summary.json` |
| `MBEDTLS-POC-0002` | not available | not available |
| `MBEDTLS-POC-0004` | `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/results/run_recipe.summary.json` | `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/results/run_recipe.migration_summary.json` |
| `MBEDTLS-POC-0017` | `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/results/run.summary.json` | `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/results/run.migration_summary.json` |
| `MBEDTLS-POC-0020` | `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/results/run.summary.json` | `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/results/run.migration_summary.json` |
