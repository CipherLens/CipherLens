# API Card Schema Summary

## Sampled Files
- `knowledge_base/api_cards/mbedtls/mbedtls_pk_verify.yaml`
- `knowledge_base/api_cards/mbedtls/psa_mac_sign_finish.yaml`
- `knowledge_base/api_cards/mbedtls/psa_verify_hash.yaml`
- `knowledge_base/api_cards/openssl/BN_bn2binpad.yaml`
- `knowledge_base/api_cards/openssl/BN_usub.yaml`
- `knowledge_base/api_cards/openssl/EVP_DigestVerify.yaml`
- `knowledge_base/api_cards/openssl/EVP_DigestVerifyInit.yaml`
- `knowledge_base/api_cards/openssl/EVP_MAC_CTX_get_mac_size.yaml`
- `knowledge_base/api_cards/openssl/EVP_MAC_final.yaml`
- `knowledge_base/api_cards/openssl/EVP_PKEY_CTX_set_rsa_padding.yaml`

## Observed API Card Fields
- `api`
- `family`
- `known_pitfalls`
- `library`
- `mutation_hints`
- `notes`
- `oracle_observables`
- `parameter_semantics`
- `related_apis`
- `return_value_semantics`
- `signature`
- `source_references`
- `state_preconditions`
- `unsupported_conditions`
- `valid_invalid_ranges`

## Canonical Staged Schema
- `api_name`
- `library`
- `family_relevance`
- `headers`
- `source_locations`
- `signature_candidates`
- `purpose`
- `preconditions`
- `postconditions`
- `lifecycle_constraints`
- `input_constraints`
- `ownership_and_lifetime`
- `return_value_semantics`
- `cleanup_requirements`
- `related_apis`
- `example_call_sequences`
- `poison_pitfalls`
- `evidence`
- `confidence`
- `notes`

Existing API cards use `api_card_v0`; staged drafts need manual normalization before import.
