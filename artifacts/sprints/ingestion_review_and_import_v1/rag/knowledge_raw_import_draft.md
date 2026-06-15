# Ingested PoC Pattern Candidates

## mbedtls
- `MBEDTLS-POC-0001`: family=`bignum_serialization_boundary`, oracle=`buffer_canary_boundary`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0002`: family=`bignum_arithmetic_precondition`, oracle=`buffer_canary_boundary`, import_status=`blocked`
- `MBEDTLS-POC-0003`: family=`cipher_padding_output_length`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0004`: family=`cipher_padding_output_length`, oracle=`return_code_outlen_semantic`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0005`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0011`: family=`tls_protocol_state_lifecycle`, oracle=`pointer_consumption_semantic_oracle`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0017`: family=`tls_protocol_state_lifecycle`, oracle=`pointer_consumption_semantic_oracle`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0020`: family=`tls_protocol_state_lifecycle`, oracle=`pointer_consumption_semantic_oracle`, import_status=`medium_confidence_staging`
- `MBEDTLS-POC-0028`: family=`cipher_aead_lifecycle`, oracle=`buffer_canary_boundary`, import_status=`needs_manual_review`

## wolfssl
- `WOLFSSL-POC-0001`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`blocked`
- `WOLFSSL-POC-0002`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0003`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0004`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0005`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0005`: family=`x509_parsing`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0006`: family=`pkcs_container_parsing`, oracle=`pointer_consumption_semantic_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0007`: family=`pkcs_container_parsing`, oracle=`buffer_canary_boundary`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0008`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0009`: family=`tls_protocol_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `WOLFSSL-POC-0010`: family=`tls_protocol_state_lifecycle`, oracle=`return_code_outlen_semantic`, import_status=`medium_confidence_staging`

## openssl
- `OPENSSL-ISSUE-11567`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-11772`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-13860`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-14457`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-14675`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-15899`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-16196`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-17715`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-18168`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-18659`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`medium_confidence_staging`
- `OPENSSL-ISSUE-19524`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-21935`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-22388`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-22842`: family=`mac_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-23325`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-26106`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-2630`: family=`secure_heap_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-27572`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-28669`: family=`secure_heap_state_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-29418`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-29574`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-29645`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-30291`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-30432`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-30581`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-30889`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`blocked`
- `OPENSSL-ISSUE-6788`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-8435`: family=`bignum_serialization_boundary`, oracle=`pointer_consumption_semantic_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-8980`: family=`cipher_aead_lifecycle`, oracle=`crash_sanitizer_oracle`, import_status=`high_confidence_import_candidate`
- `OPENSSL-ISSUE-9043`: family=`bignum_serialization_boundary`, oracle=`crash_sanitizer_oracle`, import_status=`blocked`
