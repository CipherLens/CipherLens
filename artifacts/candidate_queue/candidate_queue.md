# Candidate Queue

Generated from `artifacts/pattern_bank/unified_pattern_bank.yaml` with separated readiness and severity scoring.

## Summary

- total_candidates: `42`
- top_readiness_family: `{'family': 'der_full_consumption', 'score': 1.0, 'count': 1}`
- top_severity_family: `{'family': 'memory_length_boundary', 'score': 0.75, 'count': 2}`
- top_combined_family: `{'family': 'asn1_nested_boundary', 'score': 0.7546, 'count': 7}`

## app_level_semantic_candidates

- `der_full_consumption:MBEDTLS-POC-0020` readiness=1.00 severity=0.25 combined=0.66 action=`run_der_full_consumption_v2`

## lifecycle_semantic_divergence_candidates

- `cipher_aead_lifecycle:MBEDTLS-POC-0004` readiness=0.75 severity=0.70 combined=0.73 action=`queue_for_family_triage`
- `mac_lifecycle:OPENSSL-ISSUE-22842` readiness=0.80 severity=0.55 combined=0.69 action=`audit_lifecycle_semantic_divergence`
- `cipher_aead_lifecycle:MBEDTLS-POC-0028` readiness=0.75 severity=0.45 combined=0.61 action=`manual_unexpected_success_audit`
- `cipher_aead_lifecycle:OPENSSL-ISSUE-17715` readiness=0.50 severity=0.55 combined=0.52 action=`manual_crash_repro_audit`
- `api_state_machine:OPENSSL-ISSUE-18659` readiness=0.50 severity=0.55 combined=0.52 action=`manual_crash_repro_audit`
- `api_state_machine:OPENSSL-ISSUE-2630` readiness=0.50 severity=0.55 combined=0.52 action=`manual_crash_repro_audit`
- `api_state_machine:OPENSSL-ISSUE-29645` readiness=0.50 severity=0.55 combined=0.52 action=`manual_crash_repro_audit`
- `cipher_aead_lifecycle:OPENSSL-ISSUE-8980` readiness=0.50 severity=0.55 combined=0.52 action=`manual_crash_repro_audit`
- `api_state_machine:MBEDTLS-POC-0005` readiness=0.50 severity=0.15 combined=0.34 action=`queue_for_family_triage`

## crash_or_sanitizer_candidates

- `asn1_nested_boundary:OPENSSL-ISSUE-16196` readiness=0.80 severity=0.75 combined=0.78 action=`manual_crash_repro_audit`
- `asn1_nested_boundary:OPENSSL-ISSUE-18168` readiness=0.80 severity=0.75 combined=0.78 action=`manual_crash_repro_audit`
- `asn1_nested_boundary:OPENSSL-ISSUE-26106` readiness=0.80 severity=0.75 combined=0.78 action=`manual_crash_repro_audit`
- `asn1_nested_boundary:OPENSSL-ISSUE-28669` readiness=0.80 severity=0.75 combined=0.78 action=`manual_crash_repro_audit`
- `asn1_nested_boundary:OPENSSL-ISSUE-30581` readiness=0.80 severity=0.75 combined=0.78 action=`manual_crash_repro_audit`
- `memory_length_boundary:MBEDTLS-POC-0001` readiness=0.65 severity=0.75 combined=0.69 action=`manual_crash_repro_audit`
- `memory_length_boundary:MBEDTLS-POC-0011` readiness=0.65 severity=0.75 combined=0.69 action=`manual_crash_repro_audit`
- `pkey_verify_semantic:MBEDTLS-POC-0003` readiness=0.90 severity=0.40 combined=0.68 action=`manual_crash_repro_audit`
- `pkey_verify_semantic:OPENSSL-ISSUE-15899` readiness=0.90 severity=0.40 combined=0.68 action=`manual_crash_repro_audit`
- `pkey_verify_semantic:OPENSSL-ISSUE-19524` readiness=0.90 severity=0.40 combined=0.68 action=`manual_crash_repro_audit`

## unexpected_success_candidates

- none

## stable_safe_negative_baselines

- `pkey_verify_semantic:PKEY_VERIFY_FAMILY_V0` readiness=1.00 severity=0.00 combined=0.55 action=`keep_as_stable_safe_negative_baseline`
- `pkey_verify_semantic:PKEY_VERIFY_FAMILY_V1` readiness=1.00 severity=0.00 combined=0.55 action=`keep_as_stable_safe_negative_baseline`

## projection_or_expected_behavior

- `bn_mpi_arithmetic:MBEDTLS-POC-0002` readiness=0.00 severity=0.00 combined=0.00 action=`document_projection_limitation`

## general_candidates

- `asn1_nested_boundary:OPENSSL-ISSUE-27572` readiness=1.00 severity=0.55 combined=0.80 action=`queue_for_family_triage`
- `pkey_verify_semantic:OPENSSL-ISSUE-22388` readiness=1.00 severity=0.20 combined=0.64 action=`queue_for_family_triage`
- `pkey_verify_semantic:OPENSSL-ISSUE-30291` readiness=1.00 severity=0.20 combined=0.64 action=`queue_for_family_triage`
- `pkey_verify_semantic:OPENSSL-ISSUE-30432` readiness=1.00 severity=0.20 combined=0.64 action=`queue_for_family_triage`
- `pkey_verify_semantic:OPENSSL-ISSUE-8435` readiness=1.00 severity=0.20 combined=0.64 action=`queue_for_family_triage`
- `asn1_nested_boundary:MBEDTLS-POC-0017` readiness=0.80 severity=0.35 combined=0.60 action=`queue_for_family_triage`
- `x509_parsing:MBEDTLS-POC-0027` readiness=0.75 severity=0.20 combined=0.50 action=`queue_for_family_triage`
- `x509_parsing:OPENSSL-ISSUE-11567` readiness=0.75 severity=0.20 combined=0.50 action=`queue_for_family_triage`
- `x509_parsing:OPENSSL-ISSUE-11772` readiness=0.75 severity=0.20 combined=0.50 action=`queue_for_family_triage`
- `x509_parsing:OPENSSL-ISSUE-14457` readiness=0.75 severity=0.20 combined=0.50 action=`queue_for_family_triage`
