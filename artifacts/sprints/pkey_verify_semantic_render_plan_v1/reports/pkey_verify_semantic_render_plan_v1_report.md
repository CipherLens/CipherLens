# pkey_verify_semantic_render_plan_v1 Report

## Render Plan

- family: pkey_verify_semantic
- track: semantic
- target_library: openssl
- render_mode: semantic_harness
- case_count: 10
- quality_status: pass

## Baseline Gates

- rag_glm_baseline_loaded: True
- slot_bindings_schema_valid: True
- adapter_validate_passed: True
- mapping_gate_bypassed: False
- api_key_logged: False

## Semantic API

- algorithm: RSA
- digest: SHA256
- sign_api: EVP_DigestSignInit / EVP_DigestSignUpdate / EVP_DigestSignFinal
- verify_api: EVP_DigestVerifyInit / EVP_DigestVerifyUpdate / EVP_DigestVerifyFinal

## Policy

This sprint generated a render plan only. It did not render cases, compile,
run, write feedback, update pattern-bank, modify adapter recipes, modify
normalized templates, perform git operations, claim a CVE, claim exploitability,
or claim a confirmed vulnerability.
