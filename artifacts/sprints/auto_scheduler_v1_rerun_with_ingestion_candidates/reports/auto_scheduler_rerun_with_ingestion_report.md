# auto_scheduler_v1 rerun with ingestion candidates

| metric | value |
| --- | --- |
| generated_at | 2026-06-11T00:48:18.115019+00:00 |
| reviewed_candidates_read | 50 |
| eligible_count | 40 |
| excluded_count | 10 |
| bignum_concentration_affects_sorting | True |
| wolfssl_pushes_new_family | True |
| next_task_name | manual_review_family_corrections_v1 |
| rag_recommended_task | rag_enrichment_from_ingestion_v1 |
| scheduler_seed_modified | False |
| pattern_bank_modified | False |
| knowledge_raw_modified | False |
| run_poc | False |
| glm | False |
| render | False |
| confirmed_vulnerability | False |
| candidate_only | True |

## top PoC candidates

| rank | poc_id | family | score |
| --- | --- | --- | --- |
| 1 | WOLFSSL-POC-0007 | pkcs_container_parsing | 30 |
| 2 | WOLFSSL-POC-0006 | pkcs_container_parsing | 28 |
| 3 | WOLFSSL-POC-0004 | tls_protocol_state_lifecycle | 28 |

## top families

| rank | family | max_score | avg_score |
| --- | --- | --- | --- |
| 1 | pkcs_container_parsing | 30 | 29.0 |
| 2 | x509_parsing | 28 | 28.0 |
| 3 | tls_protocol_state_lifecycle | 28 | 25.0 |
