# Candidate Validation Report

## Candidate

```text
candidate_id: secure_heap_exp_0003_new_state_init_failed_then_used
api: CRYPTO_secure_used
state_sequence: init_failed_then_query
is_seed_case: false
```

## Validation Status

```text
validated_new_state_candidate
```

The minimal reproducer makes `CRYPTO_secure_malloc_init(16, 16)` fail with return value `0`, then calls `CRYPTO_secure_used()`. It exits with `139` / `SIGSEGV`.

The initialized safe control exits normally, proving the basic harness and linkage are sound.

## GDB Evidence

The candidate backtrace reaches:

```text
___pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

This is the same crash path as the pre-init seed control, but the lifecycle state is different: failed init followed by query.

## Claim Boundary

```text
can_claim_confirmed_vulnerability: false
can_claim_cve: false
```

The current classification is `current_version_robustness_candidate` and `new_state_combination_candidate`. API contract and multi-version evidence still need confirmation.
