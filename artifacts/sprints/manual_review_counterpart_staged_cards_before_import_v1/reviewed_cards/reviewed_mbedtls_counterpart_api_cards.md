| api | source_api | family | review.reviewed_confidence | review.import_recommendation |
| --- | --- | --- | --- | --- |
|  | wc_PKCS12_parse | pkcs_container_parsing | not_found | skip_no_direct_counterpart |
|  | wc_PKCS7_Free | pkcs_container_parsing | not_found | skip_no_direct_counterpart |
|  | wc_PKCS7_Init | pkcs_container_parsing | not_found | skip_no_direct_counterpart |
|  | wc_PKCS7_VerifySignedData | pkcs_container_parsing | not_found | skip_no_direct_counterpart |
| mbedtls_calloc |  | secure_heap_state_lifecycle | low | skip_manual_review |
| mbedtls_free |  | secure_heap_state_lifecycle | high | import_now |
| mbedtls_platform_set_calloc_free |  | secure_heap_state_lifecycle | not_found_in_source | skip_not_found |
| mbedtls_ssl_config_free |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_config_init |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_free |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_handshake |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_init |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_read |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_setup |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_ssl_write |  | tls_protocol_state_lifecycle | high | import_now |
| mbedtls_x509_crt_free |  | x509_parsing | high | import_now |
| mbedtls_x509_crt_init |  | x509_parsing | high | import_now |
| mbedtls_x509_crt_parse |  | x509_parsing | high | import_now |
| mbedtls_x509_crt_parse_der |  | x509_parsing | high | import_now |
