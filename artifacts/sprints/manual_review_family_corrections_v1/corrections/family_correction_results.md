# family correction results

| metric | value |
| --- | --- |
| total_reviewed | 36 |
| changed | 27 |
| unchanged | 23 |
| needs_review | 2 |
| bignum_before | 28 |
| bignum_after | 4 |
| pkcs_container_after | 8 |
| x509_after | 15 |
| tls_after | 13 |

## items

| poc_id | library | original | corrected | confidence | reason |
| --- | --- | --- | --- | --- | --- |
| MBEDTLS-POC-0001 | mbedtls | bignum_serialization_boundary | bignum_serialization_boundary | high | API/component evidence contains BN/BIGNUM/MPI terms |
| MBEDTLS-POC-0002 | mbedtls | bignum_arithmetic_precondition | bignum_arithmetic_precondition | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0003 | mbedtls | cipher_padding_output_length | cipher_padding_output_length | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0004 | mbedtls | cipher_padding_output_length | cipher_padding_output_length | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0005 | mbedtls | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0011 | mbedtls | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0017 | mbedtls | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0020 | mbedtls | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| MBEDTLS-POC-0028 | mbedtls | cipher_aead_lifecycle | cipher_aead_lifecycle | medium | not in targeted correction set; preserved original staging family |
| OPENSSL-ISSUE-11567 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-11772 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-13860 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-14457 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-14675 | openssl | bignum_serialization_boundary | x509_parsing | medium | API/component evidence contains X509/certificate/verify terms |
| OPENSSL-ISSUE-15899 | openssl | bignum_serialization_boundary | bignum_serialization_boundary | high | API/component evidence contains BN/BIGNUM/MPI terms |
| OPENSSL-ISSUE-16196 | openssl | bignum_serialization_boundary | bignum_serialization_boundary | high | API/component evidence contains BN/BIGNUM/MPI terms |
| OPENSSL-ISSUE-17715 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-18168 | openssl | bignum_serialization_boundary | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| OPENSSL-ISSUE-18659 | openssl | bignum_serialization_boundary | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| OPENSSL-ISSUE-19524 | openssl | bignum_serialization_boundary | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| OPENSSL-ISSUE-21935 | openssl | bignum_serialization_boundary | bignum_serialization_boundary | high | API/component evidence contains BN/BIGNUM/MPI terms |
| OPENSSL-ISSUE-22388 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-22842 | openssl | mac_lifecycle | mac_lifecycle | medium | not in targeted correction set; preserved original staging family |
| OPENSSL-ISSUE-23325 | openssl | bignum_serialization_boundary | x509_parsing | medium | API/component evidence contains X509/certificate/verify terms |
| OPENSSL-ISSUE-26106 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-2630 | openssl | secure_heap_state_lifecycle | secure_heap_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| OPENSSL-ISSUE-27572 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-28669 | openssl | secure_heap_state_lifecycle | secure_heap_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| OPENSSL-ISSUE-29418 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-29574 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| OPENSSL-ISSUE-29645 | openssl | bignum_serialization_boundary | needs_review | needs_review | insufficient evidence to keep or correct original family=bignum_serialization_boundary |
| OPENSSL-ISSUE-30291 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-30432 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-30581 | openssl | bignum_serialization_boundary | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| OPENSSL-ISSUE-30889 | openssl | bignum_serialization_boundary | needs_review | needs_review | insufficient evidence to keep or correct original family=bignum_serialization_boundary |
| OPENSSL-ISSUE-6788 | openssl | bignum_serialization_boundary | x509_parsing | medium | API/component evidence contains X509/certificate/verify terms |
| OPENSSL-ISSUE-8435 | openssl | bignum_serialization_boundary | x509_parsing | medium | API/component evidence contains X509/certificate/verify terms |
| OPENSSL-ISSUE-8980 | openssl | cipher_aead_lifecycle | cipher_aead_lifecycle | medium | not in targeted correction set; preserved original staging family |
| OPENSSL-ISSUE-9043 | openssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| WOLFSSL-POC-0001 | wolfssl | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| WOLFSSL-POC-0002 | wolfssl | bignum_serialization_boundary | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| WOLFSSL-POC-0003 | wolfssl | tls_protocol_state_lifecycle | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| WOLFSSL-POC-0004 | wolfssl | tls_protocol_state_lifecycle | asn1_nested_boundary | medium | certificate/ASN.1 evidence suggests nested parser boundary |
| WOLFSSL-POC-0005 | wolfssl | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| WOLFSSL-POC-0005 | wolfssl | x509_parsing | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| WOLFSSL-POC-0006 | wolfssl | pkcs_container_parsing | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| WOLFSSL-POC-0007 | wolfssl | pkcs_container_parsing | pkcs_container_parsing | high | API/component evidence contains PKCS/CMS/OID container terms |
| WOLFSSL-POC-0008 | wolfssl | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
| WOLFSSL-POC-0009 | wolfssl | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | medium | not in targeted correction set; preserved original staging family |
| WOLFSSL-POC-0010 | wolfssl | tls_protocol_state_lifecycle | tls_protocol_state_lifecycle | high | API/component evidence contains TLS/DTLS state terms |
