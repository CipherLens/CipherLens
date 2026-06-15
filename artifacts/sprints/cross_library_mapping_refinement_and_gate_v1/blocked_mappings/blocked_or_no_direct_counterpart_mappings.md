| family | wolfssl_api | target_library | target_api | reason | recommendation |
| --- | --- | --- | --- | --- | --- |
| asn1_nested_boundary | wc_ParseCert | mbedtls | mbedtls_x509_crt_parse_der | needs_manual_review | manual_review_before_adapter |
| asn1_nested_boundary | wc_ParseCert | openssl | d2i_X509 | needs_manual_review | manual_review_before_adapter |
| pkcs_container_parsing | wc_PKCS12_parse | mbedtls |  | no_direct_counterpart | needs_new_target_strategy |
| pkcs_container_parsing | wc_PKCS7_DecodeSignedData | mbedtls |  | no_direct_counterpart | needs_new_target_strategy |
| pkcs_container_parsing | wc_PKCS7_DecodeSignedData | openssl | d2i_PKCS7 | weak_evidence | manual_review_before_adapter |
| pkcs_container_parsing | wc_PKCS7_VerifySignedData | mbedtls |  | no_direct_counterpart | needs_new_target_strategy |
| x509_parsing | wc_ParseCert | mbedtls | mbedtls_x509_crt_parse_der | needs_manual_review | manual_review_before_adapter |
