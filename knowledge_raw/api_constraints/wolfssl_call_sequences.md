# wolfSSL call sequences

- `wolfssl_decodedcert_parse_free_004:wc_InitDecodedCert -> wc_ParseCert -> wc_FreeDecodedCert`
- `wolfssl_pkcs7_init_decode_free_005:wc_PKCS7_Init -> wc_PKCS7_Free`
- `wolfssl_pkcs7_init_verify_free_006:wc_PKCS7_Init -> wc_PKCS7_Free`
- `wolfssl_tls_accept_lifecycle_002:wolfSSL_CTX_new -> wolfSSL_new -> wolfSSL_read -> wolfSSL_write -> wolfSSL_free -> wolfSSL_CTX_free`
- `wolfssl_tls_lifecycle_001:wolfSSL_CTX_new -> wolfSSL_new -> wolfSSL_connect -> wolfSSL_read -> wolfSSL_write -> wolfSSL_free -> wolfSSL_CTX_free`
- `wolfssl_x509_load_inspect_free_003:wolfSSL_X509_load_certificate_file -> wolfSSL_X509_get_subject_name -> wolfSSL_X509_free`
