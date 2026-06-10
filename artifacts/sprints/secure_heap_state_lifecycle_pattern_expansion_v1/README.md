# secure_heap_state_lifecycle_pattern_expansion_v1

This sprint expands `OPENSSL-ISSUE-28669` from seed validation into same-family secure heap lifecycle pattern testing.

## What This Is

- B-path same-family state expansion after prior D-path crash evidence audit.
- Structured template/mask/matrix rendering.
- OpenSSL-only secure heap API/state exploration.
- Novelty-aware analysis that separates seed reproductions from expansion candidates.

## What This Is Not

- Not a CVE claim.
- Not a confirmed vulnerability claim.
- Not an AFL++ fuzzing run.
- Not LLM-generated C.
- Not mbedTLS cross-library migration.

## Key Results

```text
total_cases: 19
run_ok: 16
run_nonzero: 3
crash_candidate: 3
non_novel_seed_reproduction: 2
new_state_combination_candidate: 1
harness_error: 0
```

The new candidate is:

```text
secure_heap_exp_0003_new_state_init_failed_then_used
```

It is a `new_state_combination_candidate` for `CRYPTO_secure_used` after failed init followed by query, with `SIGSEGV` / exit `139`.

## Important Boundary

The result remains:

```text
current_version_robustness_candidate
```

It is not a confirmed vulnerability or CVE because API contract and multi-version affected/fixed evidence are still incomplete.
