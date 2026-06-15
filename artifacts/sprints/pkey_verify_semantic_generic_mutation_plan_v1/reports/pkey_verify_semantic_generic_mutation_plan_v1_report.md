# pkey_verify_semantic_generic_mutation_plan_v1 Report

## Mutation Plan

- family: pkey_verify_semantic
- track: semantic
- target_library: openssl
- case_count: 10
- quality_status: pass

## Case Groups

- valid_accept_control: 1
- signature_corruption: 4
- message_mismatch: 4
- wrong_key: 1

## Deferred

- deferred_count: 2
- deferred_strategies: ['digest_mismatch_sha256_to_sha384_or_sha512', 'api_state_misuse_without_update_or_failed_init']

## Policy

No tools script, family-specific mutation script, DER trailing-garbage case,
full-consumption oracle, render, compile, run, feedback, pattern-bank, adapter
recipe, normalized template, API key logging, git operation, CVE,
exploitability, or confirmed vulnerability claim was produced.
