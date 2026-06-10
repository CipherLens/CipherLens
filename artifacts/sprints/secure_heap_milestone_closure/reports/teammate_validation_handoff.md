# Teammate Validation Handoff

## Scope

This handoff is for independent validation of:

```text
secure_heap_exp_0003_new_state_init_failed_then_used
```

Current local evidence supports a robustness / hardening candidate only. Do not
call it a confirmed vulnerability or CVE without API contract and version-range
confirmation.

## Minimal Reproducer Path

```text
artifacts/sprints/secure_heap_init_failed_then_query_candidate_validation/minimal_reproducer/
```

Core cases:

- `init_failed_then_used.c`
- `pre_init_used_seed_control.c`
- `initialized_then_used_safe_control.c`

## Current Local Version

```text
OpenSSL 3.5.5 27 Jan 2026
```

## Observed Behavior

`init_failed_then_used`:

```text
CRYPTO_secure_malloc_init(16,16)=0
CRYPTO_secure_used()
SIGSEGV / exit 139
```

Safe control:

```text
CRYPTO_secure_malloc_init(4096,32)=1
CRYPTO_secure_used()=0
exit 0
```

## GDB Backtrace

```text
pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

## Evidence To Add

- ASAN build.
- UBSAN build.
- Valgrind, if available.
- OpenSSL 3.4.x / 3.5.x / 4.0-dev version matrix.
- API contract / upstream docs confirmation.

## Wording Boundary

Use:

```text
robustness candidate
hardening candidate
validated new state combination
```

Do not use:

```text
confirmed vulnerability
CVE
```
