# Candidate Seed Summary

## Candidate

`secure_heap_exp_0003_new_state_init_failed_then_used`

## Source

The candidate comes from:

```text
artifacts/sprints/secure_heap_state_lifecycle_pattern_expansion_v1
```

## API And State

- API: `CRYPTO_secure_used`
- State sequence: `init_failed_then_query`
- Seed case: no

## Why It Is New

The original `OPENSSL-ISSUE-28669` seed baselines are:

- pre-init query
- post-done query

This candidate first makes `CRYPTO_secure_malloc_init()` fail, observes `init_ret=0`, and only then calls `CRYPTO_secure_used()`. That makes it a failed-init lifecycle state, not merely the original pre-init seed.

## Previous Crash Signal

The previous expansion run reported:

```text
exit_code: 139
signal: 11
verdict: crash_candidate
novelty_label: new_state_combination_candidate
```

## Validation Gaps

This sprint must verify whether the candidate remains stable in a minimal reproducer, whether the backtrace is the same `CRYPTO_secure_used` / NULL rwlock path, whether the initialized control exits normally, and whether the local API contract clearly allows or forbids query after failed init.
