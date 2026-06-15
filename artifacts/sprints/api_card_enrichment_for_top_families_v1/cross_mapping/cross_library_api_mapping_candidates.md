# Cross-Library API Mapping Candidates

- total: `18`

- `asn1_nested_boundary` `wc_InitDecodedCert` -> OpenSSL `ASN1_item_d2i`, mbedTLS `mbedtls_x509_crt_parse_der` (medium)
- `asn1_nested_boundary` `wc_ParseCert` -> OpenSSL `d2i_X509`, mbedTLS `mbedtls_x509_crt_parse_der` (medium)
- `pkcs_container_parsing` `wc_PKCS12_parse` -> OpenSSL `PKCS12_parse`, mbedTLS `` (medium)
- `pkcs_container_parsing` `wc_PKCS7_DecodeSignedData` -> OpenSSL `d2i_PKCS7`, mbedTLS `` (low)
- `pkcs_container_parsing` `wc_PKCS7_VerifySignedData` -> OpenSSL `PKCS7_verify`, mbedTLS `` (medium)
- `secure_heap_state_lifecycle` `wolfSSL_Free` -> OpenSSL `OPENSSL_free`, mbedTLS `mbedtls_free` (medium)
- `secure_heap_state_lifecycle` `wolfSSL_Malloc` -> OpenSSL `OPENSSL_malloc`, mbedTLS `mbedtls_calloc` (medium)
- `secure_heap_state_lifecycle` `wolfSSL_SetAllocators` -> OpenSSL `CRYPTO_set_mem_functions`, mbedTLS `mbedtls_platform_set_calloc_free` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_CTX_new` -> OpenSSL `SSL_CTX_new`, mbedTLS `mbedtls_ssl_config_init` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_accept` -> OpenSSL `SSL_accept`, mbedTLS `mbedtls_ssl_handshake` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_connect` -> OpenSSL `SSL_connect`, mbedTLS `mbedtls_ssl_handshake` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_free` -> OpenSSL `SSL_free`, mbedTLS `mbedtls_ssl_free` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_new` -> OpenSSL `SSL_new`, mbedTLS `mbedtls_ssl_init` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_read` -> OpenSSL `SSL_read`, mbedTLS `mbedtls_ssl_read` (medium)
- `tls_protocol_state_lifecycle` `wolfSSL_write` -> OpenSSL `SSL_write`, mbedTLS `mbedtls_ssl_write` (medium)
- `x509_parsing` `wolfSSL_X509_free` -> OpenSSL `X509_free`, mbedTLS `mbedtls_x509_crt_free` (medium)
- `x509_parsing` `wolfSSL_X509_load_certificate_file` -> OpenSSL `PEM_read_X509`, mbedTLS `mbedtls_x509_crt_parse_file` (medium)
- `x509_parsing` `wolfSSL_X509_verify` -> OpenSSL `X509_verify`, mbedTLS `mbedtls_x509_crt_verify` (medium)
