# wolfSSL Call Sequence Candidates

- total: `6`

- `wolfssl_decodedcert_parse_free_004` `examples/ocsp_responder/ocsp_responder.c`: wc_InitDecodedCert -> wc_ParseCert -> wc_FreeDecodedCert
- `wolfssl_pkcs7_init_decode_free_005` `tests/api.c`: wc_PKCS7_Init -> wc_PKCS7_Free
- `wolfssl_pkcs7_init_verify_free_006` `tests/api.c`: wc_PKCS7_Init -> wc_PKCS7_Free
- `wolfssl_tls_accept_lifecycle_002` `examples/async/async_client.c`: wolfSSL_CTX_new -> wolfSSL_new -> wolfSSL_read -> wolfSSL_write -> wolfSSL_free -> wolfSSL_CTX_free
- `wolfssl_tls_lifecycle_001` `examples/async/async_client.c`: wolfSSL_CTX_new -> wolfSSL_new -> wolfSSL_connect -> wolfSSL_read -> wolfSSL_write -> wolfSSL_free -> wolfSSL_CTX_free
- `wolfssl_x509_load_inspect_free_003` `tests/api.c`: wolfSSL_X509_load_certificate_file -> wolfSSL_X509_get_subject_name -> wolfSSL_X509_free
