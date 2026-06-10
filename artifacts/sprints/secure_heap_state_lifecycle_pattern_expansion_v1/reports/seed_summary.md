# Seed Summary

## Seed

`OPENSSL-ISSUE-28669` describes a secure heap lifecycle crash pattern around `CRYPTO_secure_used()`.

## Root Cause

The current working root cause is a possible NULL lock dereference in `CRYPTO_secure_used()` when the secure heap lock is not initialized, either before `CRYPTO_secure_malloc_init()` or after `CRYPTO_secure_malloc_done()`.

## Existing Crash Oracle

The existing crash oracle observes explicit crash evidence: `SIGSEGV`, exit code `139`, and historical local Valgrind `Invalid read` evidence. The previous sprint also used a signal handler that emitted `[CRASH] secure_heap_state_lifecycle`.

## Existing Controls

The prior sprint included initialized controls:

- `initialized_used`
- `initialized_check_then_used`
- `done_check_then_used_precondition_guard`

These controls showed defined behavior or a safe precondition guard.

## Current Version Conclusion

The current local OpenSSL version is `OpenSSL 3.5.5 27 Jan 2026`, with high-confidence local static linkage. The correct classification is:

```text
current_version_robustness_candidate_with_unknown_historical_overlap
```

## Claim Boundary

This cannot currently be called a confirmed vulnerability or CVE. The API contract for pre-init/post-done `CRYPTO_secure_used()` is ambiguous, and the local evidence does not establish historical affected/fixed version boundaries.

## Why Pattern Expansion

Stopping at the two seed cases would make this a historical reproducer. This sprint therefore expands the family to new APIs, new state combinations, and version-matrix planning while preserving the seed cases only as baselines.
