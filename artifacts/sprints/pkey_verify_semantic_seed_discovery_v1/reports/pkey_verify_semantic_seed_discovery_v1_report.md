# pkey_verify_semantic_seed_discovery_v1 Report

## Seed Discovery

- family: pkey_verify_semantic
- track: semantic
- target_library: openssl
- seed_ready: True
- seed_count: 4

## Semantic Scope

- uses_der_parsing: False
- uses_trailing_garbage: False
- uses_full_consumption_oracle: False
- preferred_algorithm: RSA + SHA256

## Seeds

- pkey_verify_semantic_valid_sign_verify_control: accept
- pkey_verify_semantic_modified_signature_reject_control: reject
- pkey_verify_semantic_modified_message_reject_control: reject
- pkey_verify_semantic_wrong_key_reject_control: reject

## Policy

No tools script, family-specific seed discovery script, DER trailing-garbage seed,
full-consumption oracle, harness render, compile, run, feedback, pattern-bank,
adapter recipe, normalized template, API key logging, git operation, CVE,
exploitability, or confirmed vulnerability claim was produced.

## Quality

- quality_status: pass
