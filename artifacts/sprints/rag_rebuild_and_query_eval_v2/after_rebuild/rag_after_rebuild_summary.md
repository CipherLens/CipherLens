# RAG After Rebuild Summary

```yaml
knowledge_base_files_after_count: 148
knowledge_base_files_before_count: 143
knowledge_base_size_after: "259M\tknowledge_base"
knowledge_base_modified: true
source_integration_modified_files:
- config/rag_config.yaml
- knowledge/rag_builder.py
knowledge_raw_scope: knowledge_raw contains previous counterpart imports plus existing
  prior dirty/untracked knowledge_raw files; this task did not add new knowledge_raw
  files.
large_file_note: knowledge_base/chroma is an index artifact; review before committing
  and usually avoid committing large/generated DB internals unless project policy
  requires artifact handoff.
rag_git_status_after:
- ' M config/rag_config.yaml'
- ' M knowledge/rag_builder.py'
- ' M knowledge/rag_query.py'
- ' M knowledge_base/api_cards/mbedtls/psa_mac_sign_finish.yaml'
- ' M knowledge_base/api_cards/mbedtls/psa_verify_hash.yaml'
- ' M knowledge_base/api_cards/openssl/EVP_DigestVerify.yaml'
- ' M knowledge_base/api_cards/openssl/EVP_MAC_CTX_get_mac_size.yaml'
- ' M knowledge_base/api_cards/openssl/EVP_MAC_final.yaml'
- ' M knowledge_base/api_cards/openssl/EVP_PKEY_verify.yaml'
- ' M knowledge_raw/poc_patterns/openssl_issue_patterns.md'
- ' M knowledge_raw/poc_patterns/unified_patterns.md'
- ?? knowledge/build_pattern_bank.py
- ?? knowledge_base/api_cards/mbedtls/mbedtls_pk_verify.yaml
- ?? knowledge_base/api_cards/openssl/EVP_DigestVerifyInit.yaml
- ?? knowledge_base/api_cards/openssl/EVP_PKEY_CTX_set_rsa_padding.yaml
- ?? knowledge_base/api_cards/openssl/EVP_PKEY_CTX_set_rsa_pss_saltlen.yaml
- ?? knowledge_raw/api_constraints/cross_library_counterpart_api_constraints.md
- ?? knowledge_raw/api_constraints/cross_library_counterpart_api_constraints.yaml
- ?? knowledge_raw/api_constraints/cross_library_counterpart_call_sequences.md
- ?? knowledge_raw/api_constraints/cross_library_counterpart_call_sequences.yaml
- ?? knowledge_raw/api_constraints/wolfssl_call_sequences.md
- ?? knowledge_raw/api_constraints/wolfssl_call_sequences.yaml
- ?? knowledge_raw/api_constraints/wolfssl_top_family_api_constraints.md
- ?? knowledge_raw/api_constraints/wolfssl_top_family_api_constraints.yaml
- ?? knowledge_raw/api_knowledge_cards/
- ?? knowledge_raw/cross_lib_equivalence/
```
