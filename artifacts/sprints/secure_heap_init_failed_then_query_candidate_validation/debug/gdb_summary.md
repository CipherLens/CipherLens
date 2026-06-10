# GDB Summary

`gdb` is available. The first sandboxed run was blocked by `ptrace: Operation not permitted`; the approved escalated rerun succeeded.

## init_failed_then_used

Backtrace reaches:

```text
___pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

## pre_init_used_seed_control

The seed control reaches the same NULL rwlock path:

```text
___pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

## initialized_then_used_safe_control

The initialized control exits normally and does not crash.

## Interpretation

The new `init_failed_then_query` candidate follows the same `CRYPTO_secure_used` / NULL rwlock crash path as the seed control, but it is reached through a different lifecycle state: failed init followed by query.
