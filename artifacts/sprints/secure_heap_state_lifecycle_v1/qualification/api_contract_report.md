# API Contract Report

API: `CRYPTO_secure_used`

Contract status:

```text
undocumented_or_ambiguous
```

## Source Evidence

Local source version: `openssl-3.5.5`

`crypto/mem_sec.c` implements `CRYPTO_secure_used()` by calling:

```c
CRYPTO_THREAD_read_lock(sec_malloc_lock)
```

before reading `secure_mem_used`. There is no preceding
`secure_mem_initialized` guard in `CRYPTO_secure_used()`.

The same file shows `CRYPTO_secure_malloc_done()` frees `sec_malloc_lock` and
sets it to `NULL` after releasing the secure heap. It also shows
`CRYPTO_secure_allocated()` explicitly returning 0 when `secure_mem_initialized`
is false, which is a useful contrast: at least one query-like secure heap API is
guarded against uninitialized state.

## Documentation Evidence

`doc/man3/OPENSSL_secure_malloc.pod` says:

- `CRYPTO_secure_malloc_initialized()` indicates whether the secure heap has been initialized and is available.
- `CRYPTO_secure_malloc_done()` releases the heap and makes the memory unavailable.
- `CRYPTO_secure_used()` returns the number of bytes allocated in the secure heap.

The local manpage does not explicitly state that `CRYPTO_secure_used()` requires
prior `CRYPTO_secure_malloc_init()`, nor does it explicitly define pre-init or
post-done calls as undefined.

## Per-State Contract Status

- Never initialized: ambiguous; not documented as disallowed in the local manpage.
- Initialized: documented available state; current control returns defined behavior.
- Done: heap unavailable; post-done direct `CRYPTO_secure_used()` behavior is not explicitly documented.
- Done then check: `CRYPTO_secure_malloc_initialized()` returns false and prevents the direct call in the safe control.

## Qualification Impact

The crash does not currently fit a clean `api_precondition_misuse` label because
the local docs do not clearly require initialization before `CRYPTO_secure_used()`.
It also should not yet be called a confirmed vulnerability because the contract is
ambiguous and needs manual confirmation.

Current best contract conclusion:

```text
does_crash_violate_documented_contract: unknown
needs_manual_doc_confirmation: true
```
