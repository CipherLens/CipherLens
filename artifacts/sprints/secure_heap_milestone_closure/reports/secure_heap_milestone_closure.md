# secure_heap_state_lifecycle Milestone Closure

## Summary

This milestone closes the current main-track work for `secure_heap_state_lifecycle`.
The family started from `OPENSSL-ISSUE-28669`, moved through seed validation and
same-family state expansion, and produced one validated non-seed state
combination candidate:

```text
secure_heap_exp_0003_new_state_init_failed_then_used
```

The current classification is:

```text
validated_new_state_candidate
current_version_robustness_candidate
```

This is not a confirmed vulnerability and not a CVE claim.

## Seed Issue

```text
OPENSSL-ISSUE-28669
family: secure_heap_state_lifecycle
api: CRYPTO_secure_used
```

The seed validation covered `pre_init_used_only` and `done_then_used` crash
candidates. Initialized controls returned normal behavior, and guarded checks
prevented the post-done `CRYPTO_secure_used()` call.

## Pattern Expansion

`secure_heap_state_lifecycle_pattern_expansion_v1` rendered 19 cases across
secure heap query, allocation, free, init, and done APIs.

```text
total_cases: 19
expansion_cases: 17
crash_candidate: 3
normal_defined_behavior: 16
new_state_combination_candidate: 1
```

The original two `CRYPTO_secure_used` crashes were retained as seed baselines.
The new non-seed candidate was:

```text
secure_heap_exp_0003_new_state_init_failed_then_used
```

## Validated New Candidate

The minimal reproducer for the new candidate makes:

```text
CRYPTO_secure_malloc_init(16,16)=0
CRYPTO_secure_used()
```

The result is stable `SIGSEGV` / exit `139`.

The initialized safe control makes:

```text
CRYPTO_secure_malloc_init(4096,32)=1
CRYPTO_secure_used()=0
exit 0
```

GDB shows the candidate reaches:

```text
pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

This is the same NULL rwlock path as the seed control, reached through a
different lifecycle state: failed init followed by query.

## Claim Boundary

Do not describe this result as:

```text
confirmed vulnerability
CVE
```

The correct current wording is:

```text
current-version robustness candidate with validated new state combination
```

## Remaining Gaps

- API contract manual confirmation.
- Multi-version matrix.
- ASAN/UBSAN or Valgrind validation.

## External Validation Track

ASAN/UBSAN rebuild should be performed separately by a teammate and should not
be mixed into the current main exploration workflow. The main scheduler should
move `secure_heap_state_lifecycle` out of immediate top-1 exploration unless the
explicit task is external validation.
