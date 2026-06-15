# wolfSSL cross-library mapping candidates

- `asn1_nested_boundary:wc_InitDecodedCert:semantic_related:medium:candidate_only`
- `asn1_nested_boundary:wc_ParseCert:parser_equivalent:medium:candidate_only`
- `pkcs_container_parsing:wc_PKCS12_parse:parser_equivalent:medium:candidate_only`
- `pkcs_container_parsing:wc_PKCS7_DecodeSignedData:parser_equivalent:low:candidate_only`
- `pkcs_container_parsing:wc_PKCS7_VerifySignedData:parser_equivalent:medium:candidate_only`
- `secure_heap_state_lifecycle:wolfSSL_Free:cleanup_equivalent:medium:candidate_only`
- `secure_heap_state_lifecycle:wolfSSL_Malloc:semantic_related:medium:candidate_only`
- `secure_heap_state_lifecycle:wolfSSL_SetAllocators:semantic_related:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_CTX_new:lifecycle_equivalent:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_accept:semantic_related:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_connect:semantic_related:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_free:cleanup_equivalent:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_new:lifecycle_equivalent:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_read:semantic_related:medium:candidate_only`
- `tls_protocol_state_lifecycle:wolfSSL_write:semantic_related:medium:candidate_only`
- `x509_parsing:wolfSSL_X509_free:cleanup_equivalent:medium:candidate_only`
- `x509_parsing:wolfSSL_X509_load_certificate_file:parser_equivalent:medium:candidate_only`
- `x509_parsing:wolfSSL_X509_verify:semantic_related:medium:candidate_only`
