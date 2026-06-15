# Import Plan

{
  "recommended_next_task": "manual_review_then_import_counterpart_api_cards_to_knowledge_raw",
  "should_import_to_knowledge_raw_now": false,
  "reason": "This sprint produced staged drafts only; medium/low evidence cards should be reviewed before import.",
  "rebuild_required_after_import": true,
  "source_gap_summary": {
    "openssl_existing_cards": [
      "d2i_X509"
    ],
    "openssl_missing_api_cards": [
      "ASN1_item_d2i",
      "CRYPTO_secure_free",
      "CRYPTO_secure_malloc",
      "CRYPTO_secure_malloc_init",
      "OPENSSL_secure_free",
      "OPENSSL_secure_malloc",
      "PEM_read_bio_X509",
      "PKCS12_free",
      "PKCS12_parse",
      "PKCS7_free",
      "PKCS7_verify",
      "SSL_CTX_free",
      "SSL_CTX_new",
      "SSL_accept",
      "SSL_connect",
      "SSL_free",
      "SSL_new",
      "SSL_read",
      "SSL_write",
      "X509_free",
      "d2i_ASN1_SEQUENCE_ANY",
      "d2i_PKCS12",
      "d2i_PKCS7"
    ],
    "openssl_missing_constraints": [],
    "mbedtls_existing_cards": [],
    "mbedtls_missing_api_cards": [
      "mbedtls_calloc",
      "mbedtls_free",
      "mbedtls_platform_set_calloc_free",
      "mbedtls_ssl_config_free",
      "mbedtls_ssl_config_init",
      "mbedtls_ssl_free",
      "mbedtls_ssl_handshake",
      "mbedtls_ssl_init",
      "mbedtls_ssl_read",
      "mbedtls_ssl_setup",
      "mbedtls_ssl_write",
      "mbedtls_x509_crt_free",
      "mbedtls_x509_crt_init",
      "mbedtls_x509_crt_parse",
      "mbedtls_x509_crt_parse_der"
    ],
    "mbedtls_missing_constraints": [],
    "wolfssl_without_direct_mbedtls_counterpart": [
      "wc_PKCS12_parse",
      "wc_PKCS7_Free",
      "wc_PKCS7_Init",
      "wc_PKCS7_VerifySignedData"
    ],
    "weak_name_match_mappings": [],
    "families_needing_target_side_knowledge": [
      "tls_protocol_state_lifecycle",
      "pkcs_container_parsing",
      "secure_heap_state_lifecycle",
      "x509_parsing",
      "asn1_nested_boundary"
    ],
    "family_gap_counts": {
      "asn1_nested_boundary": {
        "no_gap": 1,
        "missing_api_card": 6
      },
      "pkcs_container_parsing": {
        "missing_api_card": 6,
        "no_direct_counterpart": 4
      },
      "secure_heap_state_lifecycle": {
        "missing_api_card": 10
      },
      "tls_protocol_state_lifecycle": {
        "missing_api_card": 16
      },
      "x509_parsing": {
        "missing_api_card": 9,
        "no_gap": 1
      }
    }
  },
  "source_enrichment_plan": {
    "enrichment_plan": {
      "recommended_next_task": "api_card_enrichment_for_cross_library_counterparts_v1",
      "priority_targets": [
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "PKCS12_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "PKCS12_parse",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "PKCS7_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "PKCS7_verify",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "d2i_PKCS12",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "pkcs_container_parsing",
          "api": "d2i_PKCS7",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "x509_parsing",
          "api": "ASN1_item_d2i",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "x509_parsing",
          "api": "PEM_read_bio_X509",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "x509_parsing",
          "api": "X509_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "x509_parsing",
          "api": "d2i_ASN1_SEQUENCE_ANY",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "asn1_nested_boundary",
          "api": "ASN1_item_d2i",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "asn1_nested_boundary",
          "api": "d2i_ASN1_SEQUENCE_ANY",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "x509_parsing",
          "api": "mbedtls_x509_crt_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "x509_parsing",
          "api": "mbedtls_x509_crt_init",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "x509_parsing",
          "api": "mbedtls_x509_crt_parse",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "x509_parsing",
          "api": "mbedtls_x509_crt_parse_der",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_config_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_config_init",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_handshake",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_init",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_read",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_setup",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "tls_protocol_state_lifecycle",
          "api": "mbedtls_ssl_write",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "secure_heap_state_lifecycle",
          "api": "CRYPTO_secure_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "secure_heap_state_lifecycle",
          "api": "CRYPTO_secure_malloc",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "secure_heap_state_lifecycle",
          "api": "CRYPTO_secure_malloc_init",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "secure_heap_state_lifecycle",
          "api": "OPENSSL_secure_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "secure_heap_state_lifecycle",
          "api": "OPENSSL_secure_malloc",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "secure_heap_state_lifecycle",
          "api": "mbedtls_calloc",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "secure_heap_state_lifecycle",
          "api": "mbedtls_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "secure_heap_state_lifecycle",
          "api": "mbedtls_platform_set_calloc_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "asn1_nested_boundary",
          "api": "mbedtls_x509_crt_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "asn1_nested_boundary",
          "api": "mbedtls_x509_crt_init",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "asn1_nested_boundary",
          "api": "mbedtls_x509_crt_parse",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "mbedtls",
          "family": "asn1_nested_boundary",
          "api": "mbedtls_x509_crt_parse_der",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_CTX_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_CTX_new",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_accept",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_connect",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_free",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_new",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_read",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        },
        {
          "target_library": "openssl",
          "family": "tls_protocol_state_lifecycle",
          "api": "SSL_write",
          "reason": "missing_api_card",
          "required_fields": [
            "signature",
            "parameter_semantics",
            "return_value_semantics",
            "state_preconditions",
            "cleanup",
            "oracle_observables"
          ]
        }
      ],
      "skip_or_low_priority": [
        {
          "api": "wc_PKCS12_parse",
          "reason": "mbedTLS direct PKCS7/PKCS12 counterpart not identified; do not force a weak mapping."
        },
        {
          "api": "wc_PKCS7_Free",
          "reason": "mbedTLS direct PKCS7/PKCS12 counterpart not identified; do not force a weak mapping."
        },
        {
          "api": "wc_PKCS7_Init",
          "reason": "mbedTLS direct PKCS7/PKCS12 counterpart not identified; do not force a weak mapping."
        },
        {
          "api": "wc_PKCS7_VerifySignedData",
          "reason": "mbedTLS direct PKCS7/PKCS12 counterpart not identified; do not force a weak mapping."
        }
      ]
    }
  }
}
