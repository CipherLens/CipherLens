# AEAD Lifecycle Pattern Abstraction

## Family

```text
cipher_aead_lifecycle
```

This sprint defines root-cause hypotheses, mutation points, and oracles. It does
not report a new vulnerability.

## Root Cause Hypotheses

- `terminal_state_reuse`
- `tag_order_mismatch`
- `aad_data_order_mismatch`
- `init_failure_followed_by_operation`
- `cleanup_free_followed_by_reuse`
- `mode_confusion_encrypt_decrypt`
- `invalid_tag_length_acceptance`
- `error_path_output_state_pollution`

## Mutation Points

- `operation_order`
- `tag_length`
- `tag_set_timing`
- `tag_get_timing`
- `aad_timing`
- `final_repetition`
- `ctx_reuse`
- `decrypt_verify_path`
- `cleanup_timing`
- `init_failure_path`

## Oracles

- `strict_bad_state_reject`: invalid lifecycle transition is rejected safely.
- `permissive_terminal_reuse`: an API succeeds after a terminal-looking state;
  classify as semantic divergence or allowed behavior pending contract review.
- `crash_or_sanitizer`: requires explicit `SIGSEGV`, ASAN, UBSAN, or Valgrind
  evidence.
- `unexpected_success`: invalid tag length or bad operation order succeeds.
- `semantic_divergence`: OpenSSL and mbedTLS differ on a comparable lifecycle
  sequence.
- `normal_defined_behavior`: expected control behavior.

## Claim Boundary

OpenSSL permissive behavior is not automatically a vulnerability. mbedTLS strict
rejection is not a vulnerability. Until contract, version, and caller-impact
evidence exists, classify findings as semantic divergence or robustness
candidates.
