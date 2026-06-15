# Counterpart Enrichment Report

{
  "openssl": {
    "total": 24,
    "confidence_counts": {
      "medium": 23,
      "high": 1
    },
    "status_counts": {
      "staged_counterpart_card": 24
    },
    "families": [
      "asn1_nested_boundary",
      "pkcs_container_parsing",
      "secure_heap_state_lifecycle",
      "tls_protocol_state_lifecycle",
      "x509_parsing"
    ],
    "representative_apis": [
      "SSL_CTX_new",
      "SSL_CTX_free",
      "SSL_new",
      "SSL_free",
      "SSL_connect",
      "SSL_accept",
      "SSL_read",
      "SSL_write"
    ]
  },
  "mbedtls": {
    "total": 19,
    "confidence_counts": {
      "medium": 15,
      "not_found": 4
    },
    "status_counts": {
      "staged_counterpart_card": 15,
      "no_direct_counterpart": 4
    },
    "families": [
      "pkcs_container_parsing",
      "secure_heap_state_lifecycle",
      "tls_protocol_state_lifecycle",
      "x509_parsing"
    ],
    "representative_apis": [
      "mbedtls_ssl_config_init",
      "mbedtls_ssl_config_free",
      "mbedtls_ssl_init",
      "mbedtls_ssl_free",
      "mbedtls_ssl_setup",
      "mbedtls_ssl_handshake",
      "mbedtls_ssl_read",
      "mbedtls_ssl_write"
    ]
  },
  "constraints": {
    "openssl": 24,
    "mbedtls": 15
  },
  "call_sequences": {
    "openssl": 4,
    "mbedtls": 3
  },
  "mapping_support_counts": {
    "ready_for_import": 22,
    "no_direct_counterpart": 3,
    "needs_manual_review": 4,
    "weak_evidence": 7
  },
  "knowledge_raw_modified": false,
  "knowledge_base_modified": false,
  "rag_rebuild": false,
  "pattern_bank_modified": false,
  "scheduler_seed_modified": false,
  "poc_run": false,
  "compile_run": false,
  "glm": false,
  "render": false,
  "template_generated": false
}
