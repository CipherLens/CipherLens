# Migration Artifacts Index

This index tracks migration artifacts using the newer `artifacts/migrations/<artifact_slug>/` layout. Legacy root-level outputs are still present and were not deleted.

| PoC ID | artifact_slug | harness_family | target API | status | result path | migration verdict | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MBEDTLS-POC-0001` | `mbedtls-poc-0001-mpi-write-string` | legacy bignum / buffer boundary | `BN_bn2binpad`, `BN_signed_bn2bin` | legacy complete, artifact placeholder only | `runner/results/run_cross_mpi_write_string.summary.json` | `{'migrated_safe': 32}` | New artifact root prepared; legacy outputs remain in root-level directories. |
| `MBEDTLS-POC-0002` | `mbedtls-poc-0002-mpi-sub-abs` | not recorded in template meta | not available | `evidence_only` | not available | not available | Needs adapter generation/validation. |
| `MBEDTLS-POC-0004` | `mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow` | `return_code_outlen_semantic` | `EVP_DecryptFinal_ex` | `migrated_safe` | `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/results/run_recipe.summary.json` | `{'migrated_safe': 4}` | Recipe/slot-filling reference case. |
| `MBEDTLS-POC-0017` | `mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509` | `x509_asn1_inner_boundary` | `d2i_X509` | `migrated_safe` | `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/results/run.summary.json` | `{'migrated_safe': 8}` | Re-run under new artifact layout. |
| `MBEDTLS-POC-0020` | `mbedtls-poc-0020-rsa-der-trailing-garbage` | `der_pointer_consumption` | `d2i_PrivateKey`, `d2i_RSAPrivateKey`, `d2i_RSA_PUBKEY` | `migrated_bug_candidate` | `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/results/run.summary.json` | `{'migrated_bug_candidate': 18, 'migration_needs_triage': 9}` | Semantic DER trailing-garbage pointer-consumption candidate; not a crash. |

## Latest Artifact Results

```text
MBEDTLS-POC-0004:
  verdict_counts: {'safe_reject_behavior': 8}
  migration_verdict_counts: {'migrated_safe': 4}

MBEDTLS-POC-0017:
  verdict_counts: {'safe_reject_behavior': 16}
  migration_verdict_counts: {'migrated_safe': 8}

MBEDTLS-POC-0020:
  verdict_counts: {'safe_reject_behavior': 27, 'bug_candidate': 18, 'normal_behavior_needs_triage': 9}
  migration_verdict_counts: {'migrated_bug_candidate': 18, 'migration_needs_triage': 9}
```
