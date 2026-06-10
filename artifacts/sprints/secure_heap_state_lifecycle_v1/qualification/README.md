# OPENSSL-ISSUE-28669 Vulnerability Qualification Sprint

## Why This Sprint

The previous `secure_heap_state_lifecycle_v1` sprint reproduced controlled crash
candidate behavior for `CRYPTO_secure_used()` before secure heap initialization
and after `CRYPTO_secure_malloc_done()`. This qualification sprint determines
whether the issue is closer to a confirmed vulnerability candidate, API
precondition misuse, historical regression, hardening issue, or insufficient
evidence.

## API Contract Conclusion

`contract_status: undocumented_or_ambiguous`

Local OpenSSL 3.5.5 documentation does not clearly state that
`CRYPTO_secure_used()` requires prior initialization or that post-done calls are
undefined. Source inspection shows `CRYPTO_secure_used()` passes
`sec_malloc_lock` to `CRYPTO_THREAD_read_lock()` without checking
`secure_mem_initialized`.

Manual documentation or maintainer confirmation is still needed.

## Minimal Reproducers

Generated under `minimal_reproducer/`:

- `pre_init_used_only.c`
- `done_then_used.c`
- `initialized_then_used_control.c`

Local run results:

```text
pre_init_used_only: SIGSEGV / exit 139
done_then_used: SIGSEGV / exit 139
initialized_then_used_control: exit 0
```

## Debug / Sanitizer Evidence

`gdb` is available. Backtraces for both crash cases show:

```text
pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
main()
```

Valgrind is not available in this environment. Historical local artifact
metadata reports Valgrind Invalid read. ASAN / UBSAN evidence is TODO because
the current OpenSSL build is not sanitizer-instrumented.

## Version Matrix

Only `openssl-3.5.5` is available under `${CLEAN_SOURCES_ROOT}`. It reproduces
both crash cases and the initialized control succeeds.

## Final Classification

```text
robustness_hardening_candidate
```

This is stronger than insufficient evidence and stronger than a simple
historical-only regression pattern, because the current local version reproduces
the crash and gdb shows an internal NULL lock path.

It is not yet a confirmed vulnerability because the API contract remains
ambiguous and needs manual confirmation.

## Upstream Suitability

Status:

```text
needs_doc_confirmation
```

A cautious upstream report can be drafted as a robustness / hardening question,
not as a CVE or confirmed vulnerability claim.

## Next Steps

1. Confirm intended contract for `CRYPTO_secure_used()` before init and after done.
2. Run a broader OpenSSL version matrix.
3. Rerun the minimal reproducers under Valgrind or ASAN/UBSAN.
