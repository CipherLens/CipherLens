| source_api | target_library | target_api | support_status_after_staging |
| --- | --- | --- | --- |
| wc_InitDecodedCert | mbedtls | mbedtls_x509_crt_parse_der | ready_for_import |
| wc_PKCS12_parse | mbedtls |  | no_direct_counterpart |
| wc_PKCS7_DecodeSignedData | mbedtls |  | no_direct_counterpart |
| wc_PKCS7_VerifySignedData | mbedtls |  | no_direct_counterpart |
| wc_ParseCert | mbedtls | mbedtls_x509_crt_parse_der | ready_for_import |
| wolfSSL_CTX_new | mbedtls | mbedtls_ssl_config_init | ready_for_import |
| wolfSSL_Free | mbedtls | mbedtls_free | needs_manual_review |
| wolfSSL_Malloc | mbedtls | mbedtls_calloc | needs_manual_review |
| wolfSSL_SetAllocators | mbedtls | mbedtls_platform_set_calloc_free | needs_manual_review |
| wolfSSL_X509_free | mbedtls | mbedtls_x509_crt_free | ready_for_import |
| wolfSSL_X509_load_certificate_file | mbedtls | mbedtls_x509_crt_parse_file | weak_evidence |
| wolfSSL_X509_verify | mbedtls | mbedtls_x509_crt_verify | weak_evidence |
| wolfSSL_accept | mbedtls | mbedtls_ssl_handshake | ready_for_import |
| wolfSSL_connect | mbedtls | mbedtls_ssl_handshake | ready_for_import |
| wolfSSL_free | mbedtls | mbedtls_ssl_free | ready_for_import |
| wolfSSL_new | mbedtls | mbedtls_ssl_init | ready_for_import |
| wolfSSL_read | mbedtls | mbedtls_ssl_read | ready_for_import |
| wolfSSL_write | mbedtls | mbedtls_ssl_write | ready_for_import |
| wc_InitDecodedCert | openssl | ASN1_item_d2i | ready_for_import |
| wc_PKCS12_parse | openssl | PKCS12_parse | ready_for_import |
| wc_PKCS7_DecodeSignedData | openssl | d2i_PKCS7 | needs_manual_review |
| wc_PKCS7_VerifySignedData | openssl | PKCS7_verify | ready_for_import |
| wc_ParseCert | openssl | d2i_X509 | ready_for_import |
| wolfSSL_CTX_new | openssl | SSL_CTX_new | ready_for_import |
| wolfSSL_Free | openssl | OPENSSL_free | weak_evidence |
| wolfSSL_Malloc | openssl | OPENSSL_malloc | weak_evidence |
| wolfSSL_SetAllocators | openssl | CRYPTO_set_mem_functions | weak_evidence |
| wolfSSL_X509_free | openssl | X509_free | ready_for_import |
| wolfSSL_X509_load_certificate_file | openssl | PEM_read_X509 | weak_evidence |
| wolfSSL_X509_verify | openssl | X509_verify | weak_evidence |
| wolfSSL_accept | openssl | SSL_accept | ready_for_import |
| wolfSSL_connect | openssl | SSL_connect | ready_for_import |
| wolfSSL_free | openssl | SSL_free | ready_for_import |
| wolfSSL_new | openssl | SSL_new | ready_for_import |
| wolfSSL_read | openssl | SSL_read | ready_for_import |
| wolfSSL_write | openssl | SSL_write | ready_for_import |
