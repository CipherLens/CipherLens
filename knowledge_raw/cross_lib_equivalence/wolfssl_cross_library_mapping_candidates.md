# wolfSSL cross-library mapping candidates

- `wc_InitDecodedCert -> ASN1_item_d2i / mbedtls_x509_crt_parse_der`
- `wc_ParseCert -> d2i_X509 / mbedtls_x509_crt_parse_der`
- `wc_PKCS12_parse -> PKCS12_parse / `
- `wc_PKCS7_DecodeSignedData -> d2i_PKCS7 / `
- `wc_PKCS7_VerifySignedData -> PKCS7_verify / `
- `wolfSSL_Free -> OPENSSL_free / mbedtls_free`
- `wolfSSL_Malloc -> OPENSSL_malloc / mbedtls_calloc`
- `wolfSSL_SetAllocators -> CRYPTO_set_mem_functions / mbedtls_platform_set_calloc_free`
- `wolfSSL_CTX_new -> SSL_CTX_new / mbedtls_ssl_config_init`
- `wolfSSL_accept -> SSL_accept / mbedtls_ssl_handshake`
- `wolfSSL_connect -> SSL_connect / mbedtls_ssl_handshake`
- `wolfSSL_free -> SSL_free / mbedtls_ssl_free`
- `wolfSSL_new -> SSL_new / mbedtls_ssl_init`
- `wolfSSL_read -> SSL_read / mbedtls_ssl_read`
- `wolfSSL_write -> SSL_write / mbedtls_ssl_write`
- `wolfSSL_X509_free -> X509_free / mbedtls_x509_crt_free`
- `wolfSSL_X509_load_certificate_file -> PEM_read_X509 / mbedtls_x509_crt_parse_file`
- `wolfSSL_X509_verify -> X509_verify / mbedtls_x509_crt_verify`
