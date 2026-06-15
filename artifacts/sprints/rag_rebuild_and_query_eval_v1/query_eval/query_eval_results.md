# Query Eval Results

- `q1_tls_ctx_lifecycle` success=`True` found=['wolfSSL_CTX_new', 'wolfSSL_CTX_free', 'tls_protocol_state_lifecycle'] missing=[]
- `q2_tls_session_lifecycle` success=`True` found=['wolfSSL_new', 'wolfSSL_free', 'wolfSSL_connect'] missing=[]
- `q3_x509_load_free` success=`True` found=['wolfSSL_X509_load_certificate_file', 'wolfSSL_X509_free', 'x509_parsing'] missing=[]
- `q4_decodedcert_parse_free` success=`True` found=['wc_InitDecodedCert', 'wc_ParseCert', 'wc_FreeDecodedCert'] missing=[]
- `q5_pkcs7_verify_cleanup` success=`True` found=['wc_PKCS7_Init', 'wc_PKCS7_VerifySignedData', 'wc_PKCS7_Free'] missing=[]
- `q6_cross_mapping_pkcs7` success=`True` found=['wc_PKCS7_VerifySignedData', 'PKCS7', 'OpenSSL'] missing=[]
- `q7_false_positive_risk` success=`False` found=['cleanup_required'] missing=['false_positive_risk']
