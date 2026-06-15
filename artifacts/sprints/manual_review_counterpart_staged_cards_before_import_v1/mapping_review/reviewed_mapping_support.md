| wolfssl_api | target_library | target_api | status | mapping_confidence_reviewed |
| --- | --- | --- | --- | --- |
| wc_InitDecodedCert | mbedtls | mbedtls_x509_crt_parse_der | import_ready_candidate_mapping | high |
| wc_PKCS12_parse | mbedtls |  | no_direct_counterpart | none |
| wc_PKCS7_DecodeSignedData | mbedtls |  | no_direct_counterpart | none |
| wc_PKCS7_VerifySignedData | mbedtls |  | no_direct_counterpart | none |
| wc_ParseCert | mbedtls | mbedtls_x509_crt_parse_der | import_ready_candidate_mapping | high |
| wolfSSL_CTX_new | mbedtls | mbedtls_ssl_config_init | import_ready_candidate_mapping | high |
| wolfSSL_Free | mbedtls | mbedtls_free | import_ready_candidate_mapping | high |
| wolfSSL_Malloc | mbedtls | mbedtls_calloc | needs_manual_review | low |
| wolfSSL_SetAllocators | mbedtls | mbedtls_platform_set_calloc_free | needs_manual_review | not_found_in_source |
| wolfSSL_X509_free | mbedtls | mbedtls_x509_crt_free | import_ready_candidate_mapping | high |
| wolfSSL_X509_load_certificate_file | mbedtls | mbedtls_x509_crt_parse_file | weak_evidence | low |
| wolfSSL_X509_verify | mbedtls | mbedtls_x509_crt_verify | weak_evidence | low |
| wolfSSL_accept | mbedtls | mbedtls_ssl_handshake | import_ready_candidate_mapping | high |
| wolfSSL_connect | mbedtls | mbedtls_ssl_handshake | import_ready_candidate_mapping | high |
| wolfSSL_free | mbedtls | mbedtls_ssl_free | import_ready_candidate_mapping | high |
| wolfSSL_new | mbedtls | mbedtls_ssl_init | import_ready_candidate_mapping | high |
| wolfSSL_read | mbedtls | mbedtls_ssl_read | import_ready_candidate_mapping | high |
| wolfSSL_write | mbedtls | mbedtls_ssl_write | import_ready_candidate_mapping | high |
| wc_InitDecodedCert | openssl | ASN1_item_d2i | import_ready_candidate_mapping | high |
| wc_PKCS12_parse | openssl | PKCS12_parse | import_ready_candidate_mapping | high |
| wc_PKCS7_DecodeSignedData | openssl | d2i_PKCS7 | needs_manual_review | low |
| wc_PKCS7_VerifySignedData | openssl | PKCS7_verify | import_ready_candidate_mapping | high |
| wc_ParseCert | openssl | d2i_X509 | needs_manual_review | low |
| wolfSSL_CTX_new | openssl | SSL_CTX_new | import_ready_candidate_mapping | high |
| wolfSSL_Free | openssl | OPENSSL_free | weak_evidence | low |
| wolfSSL_Malloc | openssl | OPENSSL_malloc | weak_evidence | low |
| wolfSSL_SetAllocators | openssl | CRYPTO_set_mem_functions | weak_evidence | low |
| wolfSSL_X509_free | openssl | X509_free | needs_manual_review | low |
| wolfSSL_X509_load_certificate_file | openssl | PEM_read_X509 | weak_evidence | low |
| wolfSSL_X509_verify | openssl | X509_verify | weak_evidence | low |
| wolfSSL_accept | openssl | SSL_accept | import_ready_candidate_mapping | high |
| wolfSSL_connect | openssl | SSL_connect | import_ready_candidate_mapping | high |
| wolfSSL_free | openssl | SSL_free | import_ready_candidate_mapping | high |
| wolfSSL_new | openssl | SSL_new | import_ready_candidate_mapping | high |
| wolfSSL_read | openssl | SSL_read | import_ready_candidate_mapping | high |
| wolfSSL_write | openssl | SSL_write | import_ready_candidate_mapping | high |
