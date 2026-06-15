# Report

```yaml
mapping_inventory_summary:
  total_mappings: 38
  by_target_library:
    mbedtls: 20
    openssl: 18
  by_family:
    asn1_nested_boundary: 4
    pkcs_container_parsing: 6
    secure_heap_state_lifecycle: 6
    tls_protocol_state_lifecycle: 14
    x509_parsing: 8
  with_source_card: 38
  with_target_card: 23
  with_constraints: 36
  no_direct_counterpart: 3
  weak_evidence: 15
mappings:
- mapping_id: map_001
  family: asn1_nested_boundary
  wolfssl_api: wc_InitDecodedCert
  target_library: mbedtls
  target_api: mbedtls_x509_crt_parse_der
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - wc_InitDecodedCert
    - asn1_nested_boundary
  notes: &id001
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_002
  family: asn1_nested_boundary
  wolfssl_api: wc_InitDecodedCert
  target_library: openssl
  target_api: ASN1_item_d2i
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - wc_InitDecodedCert
    - asn1_nested_boundary
  notes: *id001
  source_confidence: high
- mapping_id: map_003
  family: asn1_nested_boundary
  wolfssl_api: wc_ParseCert
  target_library: mbedtls
  target_api: mbedtls_x509_crt_parse_der
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - asn1_nested_boundary
  notes: &id002
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_004
  family: asn1_nested_boundary
  wolfssl_api: wc_ParseCert
  target_library: openssl
  target_api: d2i_X509
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - d2i_X509
    - asn1_nested_boundary
  notes: *id002
  source_confidence: medium
- mapping_id: map_005
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS12_parse
  target_library: mbedtls
  target_api: ''
  mapping_type: parser_equivalent
  original_status: no_direct_counterpart
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits:
    - q5_pkcs12_wolfssl_openssl
    missing_terms:
    - pkcs_container_parsing
  notes: &id003
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_006
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS12_parse
  target_library: openssl
  target_api: PKCS12_parse
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q5_pkcs12_wolfssl_openssl
    missing_terms:
    - pkcs_container_parsing
  notes: *id003
  source_confidence: high
- mapping_id: map_007
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS7_DecodeSignedData
  target_library: mbedtls
  target_api: ''
  mapping_type: parser_equivalent
  original_status: no_direct_counterpart
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: false
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wc_PKCS7_DecodeSignedData
    - pkcs_container_parsing
  notes: &id004
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: low
- mapping_id: map_008
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS7_DecodeSignedData
  target_library: openssl
  target_api: d2i_PKCS7
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: false
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wc_PKCS7_DecodeSignedData
    - d2i_PKCS7
    - pkcs_container_parsing
  notes: *id004
  source_confidence: low
- mapping_id: map_009
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS7_VerifySignedData
  target_library: mbedtls
  target_api: ''
  mapping_type: parser_equivalent
  original_status: no_direct_counterpart
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits:
    - q4_pkcs7_wolfssl_openssl
    missing_terms:
    - pkcs_container_parsing
  notes: &id005
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_010
  family: pkcs_container_parsing
  wolfssl_api: wc_PKCS7_VerifySignedData
  target_library: openssl
  target_api: PKCS7_verify
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q4_pkcs7_wolfssl_openssl
    - q8_candidate_labels
    missing_terms:
    - pkcs_container_parsing
  notes: *id005
  source_confidence: high
- mapping_id: map_011
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_Free
  target_library: mbedtls
  target_api: mbedtls_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q6_secure_heap_allocator
    missing_terms:
    - wolfSSL_Free
    - secure_heap_state_lifecycle
  notes: &id006
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_012
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_Free
  target_library: openssl
  target_api: OPENSSL_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_Free
    - OPENSSL_free
    - secure_heap_state_lifecycle
  notes: *id006
  source_confidence: medium
- mapping_id: map_013
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_Malloc
  target_library: mbedtls
  target_api: mbedtls_calloc
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_Malloc
    - mbedtls_calloc
    - secure_heap_state_lifecycle
  notes: &id007
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_014
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_Malloc
  target_library: openssl
  target_api: OPENSSL_malloc
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_Malloc
    - OPENSSL_malloc
    - secure_heap_state_lifecycle
  notes: *id007
  source_confidence: medium
- mapping_id: map_015
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_SetAllocators
  target_library: mbedtls
  target_api: mbedtls_platform_set_calloc_free
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_SetAllocators
    - mbedtls_platform_set_calloc_free
    - secure_heap_state_lifecycle
  notes: &id008
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_016
  family: secure_heap_state_lifecycle
  wolfssl_api: wolfSSL_SetAllocators
  target_library: openssl
  target_api: CRYPTO_set_mem_functions
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_SetAllocators
    - CRYPTO_set_mem_functions
    - secure_heap_state_lifecycle
  notes: *id008
  source_confidence: medium
- mapping_id: map_017
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_CTX_new
  target_library: mbedtls
  target_api: mbedtls_ssl_config_init
  mapping_type: lifecycle_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q1_tls_three_library_lifecycle
    missing_terms:
    - tls_protocol_state_lifecycle
  notes: &id009
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_018
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_CTX_new
  target_library: openssl
  target_api: SSL_CTX_new
  mapping_type: lifecycle_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q1_tls_three_library_lifecycle
    missing_terms:
    - tls_protocol_state_lifecycle
  notes: *id009
  source_confidence: high
- mapping_id: map_019
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_accept
  target_library: mbedtls
  target_api: mbedtls_ssl_handshake
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_accept
    - mbedtls_ssl_handshake
    - tls_protocol_state_lifecycle
  notes: &id010
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_020
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_accept
  target_library: openssl
  target_api: SSL_accept
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_accept
    - SSL_accept
    - tls_protocol_state_lifecycle
  notes: *id010
  source_confidence: high
- mapping_id: map_021
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_connect
  target_library: mbedtls
  target_api: mbedtls_ssl_handshake
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_connect
    - mbedtls_ssl_handshake
    - tls_protocol_state_lifecycle
  notes: &id011
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_022
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_connect
  target_library: openssl
  target_api: SSL_connect
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_connect
    - SSL_connect
    - tls_protocol_state_lifecycle
  notes: *id011
  source_confidence: high
- mapping_id: map_023
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_free
  target_library: mbedtls
  target_api: mbedtls_ssl_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q2_tls_session_mapping
    missing_terms:
    - wolfSSL_free
    - tls_protocol_state_lifecycle
  notes: &id012
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_024
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_free
  target_library: openssl
  target_api: SSL_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q2_tls_session_mapping
    missing_terms:
    - wolfSSL_free
    - tls_protocol_state_lifecycle
  notes: *id012
  source_confidence: high
- mapping_id: map_025
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_new
  target_library: mbedtls
  target_api: mbedtls_ssl_init
  mapping_type: lifecycle_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q1_tls_three_library_lifecycle
    - q2_tls_session_mapping
    missing_terms:
    - tls_protocol_state_lifecycle
  notes: &id013
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_026
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_new
  target_library: openssl
  target_api: SSL_new
  mapping_type: lifecycle_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q2_tls_session_mapping
    missing_terms:
    - tls_protocol_state_lifecycle
  notes: *id013
  source_confidence: high
- mapping_id: map_027
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_read
  target_library: mbedtls
  target_api: mbedtls_ssl_read
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_read
    - mbedtls_ssl_read
    - tls_protocol_state_lifecycle
  notes: &id014
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_028
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_read
  target_library: openssl
  target_api: SSL_read
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_read
    - SSL_read
    - tls_protocol_state_lifecycle
  notes: *id014
  source_confidence: high
- mapping_id: map_029
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_write
  target_library: mbedtls
  target_api: mbedtls_ssl_write
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_write
    - mbedtls_ssl_write
    - tls_protocol_state_lifecycle
  notes: &id015
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_030
  family: tls_protocol_state_lifecycle
  wolfssl_api: wolfSSL_write
  target_library: openssl
  target_api: SSL_write
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_write
    - SSL_write
    - tls_protocol_state_lifecycle
  notes: *id015
  source_confidence: high
- mapping_id: map_031
  family: x509_parsing
  wolfssl_api: wc_InitDecodedCert
  target_library: mbedtls
  target_api: mbedtls_x509_crt_parse_der
  mapping_type: candidate_counterpart
  original_status: import_ready_candidate_mapping
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - wc_InitDecodedCert
    - x509_parsing
  notes: candidate mapping only; not confirmed equivalence
  source_confidence: high
- mapping_id: map_032
  family: x509_parsing
  wolfssl_api: wc_ParseCert
  target_library: mbedtls
  target_api: mbedtls_x509_crt_parse_der
  mapping_type: candidate_counterpart
  original_status: import_ready_candidate_mapping
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits:
    - q3_x509_asn1_parse_mapping
    missing_terms:
    - x509_parsing
  notes: candidate mapping only; not confirmed equivalence
  source_confidence: high
- mapping_id: map_033
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_free
  target_library: mbedtls
  target_api: mbedtls_x509_crt_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/cross_library_counterpart_mapping_candidates.yaml
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: true
  source_constraint_exists: true
  target_constraint_exists: true
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_free
    - mbedtls_x509_crt_free
    - x509_parsing
  notes: &id016
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: high
- mapping_id: map_034
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_free
  target_library: openssl
  target_api: X509_free
  mapping_type: cleanup_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_free
    - X509_free
    - x509_parsing
  notes: *id016
  source_confidence: medium
- mapping_id: map_035
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_load_certificate_file
  target_library: mbedtls
  target_api: mbedtls_x509_crt_parse_file
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_load_certificate_file
    - mbedtls_x509_crt_parse_file
    - x509_parsing
  notes: &id017
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_036
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_load_certificate_file
  target_library: openssl
  target_api: PEM_read_X509
  mapping_type: parser_equivalent
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_load_certificate_file
    - PEM_read_X509
    - x509_parsing
  notes: *id017
  source_confidence: medium
- mapping_id: map_037
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_verify
  target_library: mbedtls
  target_api: mbedtls_x509_crt_verify
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_verify
    - mbedtls_x509_crt_verify
    - x509_parsing
  notes: &id018
  - Candidate mapping only; weak or medium evidence must pass candidate_mapper/RAG
    evidence gate.
  - Not confirmed equivalent; must pass candidate_mapper and RAG evidence gate.
  source_confidence: medium
- mapping_id: map_038
  family: x509_parsing
  wolfssl_api: wolfSSL_X509_verify
  target_library: openssl
  target_api: X509_verify
  mapping_type: semantic_related
  original_status: candidate_only
  source_files:
  - knowledge_raw/cross_lib_equivalence/wolfssl_cross_library_mapping_candidates.yaml
  source_card_exists: true
  target_card_exists: false
  source_constraint_exists: true
  target_constraint_exists: false
  query_eval_support:
    hits: []
    missing_terms:
    - wolfSSL_X509_verify
    - X509_verify
    - x509_parsing
  notes: *id018
  source_confidence: medium
```
