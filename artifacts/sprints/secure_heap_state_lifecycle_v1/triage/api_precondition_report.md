# CRYPTO_secure_used API Precondition Report

## Local Source Reading

OpenSSL 3.5.5 `crypto/mem_sec.c` implements `CRYPTO_secure_used()` by calling `CRYPTO_THREAD_read_lock(sec_malloc_lock)` and then reading `secure_mem_used`. Unlike `CRYPTO_secure_allocated()`, it does not first check `secure_mem_initialized`.

The manpage `OPENSSL_secure_malloc.pod` says `CRYPTO_secure_used()` returns the number of bytes allocated in the secure heap. It does not clearly state what happens if the secure heap has not been initialized.

## Precondition Status

`precondition_status: needs_manual_doc_confirmation`

The source suggests a precondition or missing guard around `sec_malloc_lock`, but local documentation does not explicitly classify pre-init `CRYPTO_secure_used()` as allowed, safe, or undefined.

## Oracle

- Crash evidence: SIGSEGV, exit 139, Valgrind Invalid read, ASAN, UBSAN.
- Safe initialized control: `CRYPTO_secure_malloc_init()` followed by `CRYPTO_secure_used()` returns a defined value without crash.
- Precondition failure: no crash plus defined rejection/return is not a vulnerability.
- Ordinary nonzero exit alone is not crash evidence.
