# eligible ingestion candidates

| poc_id | library | family | confidence | import_status |
| --- | --- | --- | --- | --- |
| MBEDTLS-POC-0001 | mbedtls | bignum_serialization_boundary | medium | medium_confidence_staging |
| MBEDTLS-POC-0003 | mbedtls | cipher_padding_output_length | medium | medium_confidence_staging |
| MBEDTLS-POC-0004 | mbedtls | cipher_padding_output_length | medium | medium_confidence_staging |
| MBEDTLS-POC-0005 | mbedtls | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| MBEDTLS-POC-0011 | mbedtls | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| MBEDTLS-POC-0017 | mbedtls | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| MBEDTLS-POC-0020 | mbedtls | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| OPENSSL-ISSUE-13860 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-14457 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-15899 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-16196 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-18168 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-18659 | openssl | bignum_serialization_boundary | medium | medium_confidence_staging |
| OPENSSL-ISSUE-19524 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-21935 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-22388 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-22842 | openssl | mac_lifecycle | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-23325 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-26106 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-2630 | openssl | secure_heap_state_lifecycle | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-27572 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-28669 | openssl | secure_heap_state_lifecycle | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-29574 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-29645 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-30291 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-30432 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-30581 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-6788 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-8435 | openssl | bignum_serialization_boundary | high | high_confidence_import_candidate |
| OPENSSL-ISSUE-8980 | openssl | cipher_aead_lifecycle | high | high_confidence_import_candidate |
| WOLFSSL-POC-0002 | wolfssl | bignum_serialization_boundary | medium | medium_confidence_staging |
| WOLFSSL-POC-0003 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| WOLFSSL-POC-0004 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| WOLFSSL-POC-0005 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| WOLFSSL-POC-0005 | wolfssl | x509_parsing | medium | medium_confidence_staging |
| WOLFSSL-POC-0006 | wolfssl | pkcs_container_parsing | medium | medium_confidence_staging |
| WOLFSSL-POC-0007 | wolfssl | pkcs_container_parsing | medium | medium_confidence_staging |
| WOLFSSL-POC-0008 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| WOLFSSL-POC-0009 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |
| WOLFSSL-POC-0010 | wolfssl | tls_protocol_state_lifecycle | medium | medium_confidence_staging |

## excluded

| poc_id | library | reason |
| --- | --- | --- |
| MBEDTLS-POC-0002 | mbedtls | excluded import_status=blocked, quality_confidence=blocked |
| MBEDTLS-POC-0028 | mbedtls | excluded import_status=needs_manual_review, quality_confidence=low |
| OPENSSL-ISSUE-11567 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-11772 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-14675 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-17715 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-29418 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-30889 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| OPENSSL-ISSUE-9043 | openssl | excluded import_status=blocked, quality_confidence=blocked |
| WOLFSSL-POC-0001 | wolfssl | excluded import_status=blocked, quality_confidence=blocked |
