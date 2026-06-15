# adapter slot binding validation rules

## Global Rules
- no_full_c_generation
- no_blocked_target_api
- no_confirmed_equivalence_claim
- all_required_bindings_present
- cleanup_mapping_required
- oracle_mapping_required
- mapping_gate_status_recorded
- candidate_mapping_must_remain_candidate

## Adapter-Specific Rules
- asn1_nested_boundary.mbedtls.family_adapter_recipe_v1: allowed=['mbedtls_x509_crt_parse_der'], forbidden=['mbedtls_x509_crt_parse_der']
- asn1_nested_boundary.openssl.family_adapter_recipe_v1: allowed=['ASN1_item_d2i'], forbidden=['d2i_X509']
- pkcs_container_parsing.openssl.family_adapter_recipe_v1: allowed=['PKCS12_parse', 'PKCS7_verify'], forbidden=['d2i_PKCS7']
