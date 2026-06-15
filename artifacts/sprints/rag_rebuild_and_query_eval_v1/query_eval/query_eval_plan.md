# Query Eval Plan

- `q1_tls_ctx_lifecycle`: wolfSSL_CTX_new wolfSSL_CTX_free TLS context lifecycle
- `q2_tls_session_lifecycle`: wolfSSL_new wolfSSL_free wolfSSL_connect wolfSSL_read wolfSSL_write
- `q3_x509_load_free`: wolfSSL_X509_load_certificate_file wolfSSL_X509_free certificate lifecycle
- `q4_decodedcert_parse_free`: wc_InitDecodedCert wc_ParseCert wc_FreeDecodedCert ASN.1 parse free
- `q5_pkcs7_verify_cleanup`: wc_PKCS7_Init wc_PKCS7_VerifySignedData wc_PKCS7_Free cleanup
- `q6_cross_mapping_pkcs7`: wolfSSL OpenSSL PKCS7 cross library mapping VerifySignedData d2i_PKCS7
- `q7_false_positive_risk`: wolfSSL API constraints false positive misuse cleanup required
