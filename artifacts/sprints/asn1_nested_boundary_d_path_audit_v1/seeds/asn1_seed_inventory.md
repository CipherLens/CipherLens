# ASN.1 Seed Inventory

## MBEDTLS-POC-0017

- source: `data/pocs/core10/MBEDTLS-POC-0017 and normalized_templates/x509/x509_asn1_inner_boundary`
- library: `mbedtls`
- component: X509/ASN1
- boundary_type: `inner_asn1_boundary`
- evidence_quality: `medium`
- recommended_next: `D_then_A`
- oracle_hint: historical buggy ret=-9186 vs fixed ret=-9184; current migration results are safe_reject_behavior/migrated_safe

## OPENSSL-ISSUE-30581

- source: `datasets/openssl/poc_artifacts/issue_30581`
- library: `openssl`
- component: PKCS12/ASN1
- boundary_type: `malformed_child_object`
- evidence_quality: `strong`
- recommended_next: `D_audit_only`
- oracle_hint: CLI+INPUT_SEED+CLI+SANITIZER_LOG metadata; local C harness uses d2i_PKCS12_fp / PKCS12_parse path but strict reproduction missing original input

## OPENSSL-ISSUE-9043

- source: `knowledge_raw/poc_patterns/openssl_issue_patterns.md`
- library: `openssl`
- component: X509/CSR/ASN1
- boundary_type: `malformed_child_object`
- evidence_quality: `medium`
- recommended_next: `needs_more_evidence`
- oracle_hint: crash_or_sanitizer candidate reference; needs source artifact audit
