# blocked slot filling targets

- pkcs_container_parsing -> mbedtls: no_direct_counterpart (wc_PKCS12_parse)
- pkcs_container_parsing -> mbedtls: no_direct_counterpart (wc_PKCS7_DecodeSignedData)
- pkcs_container_parsing -> openssl: weak_evidence (d2i_PKCS7)
- pkcs_container_parsing -> mbedtls: no_direct_counterpart (wc_PKCS7_VerifySignedData)
- asn1_nested_boundary -> mbedtls: needs_manual_review (mbedtls_x509_crt_parse_der)
- asn1_nested_boundary -> openssl: needs_manual_review (d2i_X509)
- x509_parsing -> mbedtls: needs_manual_review (mbedtls_x509_crt_parse_der)
