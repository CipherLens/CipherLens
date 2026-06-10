# gdb Summary

`gdb_available: true`

Two minimal crash reproducers were run under `gdb -q -batch`.

## pre_init_used_only

Observed:

```text
Program received signal SIGSEGV, Segmentation fault.
___pthread_rwlock_rdlock (rwlock=0x0)
#0  ___pthread_rwlock_rdlock (rwlock=0x0)
#1  CRYPTO_THREAD_read_lock (lock=0x0) at crypto/threads_pthread.c:631
#2  CRYPTO_secure_used () at crypto/mem_sec.c:265
#3  main ()
```

Interpretation: the crash is a NULL rwlock read path inside
`CRYPTO_secure_used()`, reached before secure heap initialization.

## done_then_used

Observed:

```text
Program received signal SIGSEGV, Segmentation fault.
___pthread_rwlock_rdlock (rwlock=0x0)
#0  ___pthread_rwlock_rdlock (rwlock=0x0)
#1  CRYPTO_THREAD_read_lock (lock=0x0) at crypto/threads_pthread.c:631
#2  CRYPTO_secure_used () at crypto/mem_sec.c:265
#3  main ()
```

Interpretation: after `CRYPTO_secure_malloc_done()` succeeds, the secure heap
lock has been freed and set to NULL. A direct `CRYPTO_secure_used()` call reaches
the same NULL rwlock read path.

## Qualification Impact

The backtrace supports implementation-level crash evidence. It does not by
itself settle whether the call violates a documented API precondition.
