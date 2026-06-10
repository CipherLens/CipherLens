# OPENSSL-ISSUE-28669 Evidence Audit

## Summary

- local artifact exists: `true`
- repro artifact: `datasets/openssl/poc_artifacts/issue_28669/poc.c`
- repro command style: generated C API PoC
- crash evidence in local metadata: `SIGSEGV`, `exit code 139`, `Valgrind Invalid read`
- ASAN / UBSAN evidence: not present in local artifact metadata
- ordinary nonzero only: `false`
- strict historical reproduction: `false`

## Local Evidence

The local PoC calls `CRYPTO_secure_used()` without first calling `CRYPTO_secure_malloc_init()`.

The local metadata records:

- tested library: `OpenSSL 3.0.13 / libcrypto.so.3`
- normal run: SIGSEGV with exit code 139
- Valgrind: Invalid read of size 4, one error context

This is useful crash-oracle seed evidence, but it is not a confirmed CVE or strict historical reproduction.

## Risk of API Misuse

The trigger is a pre-initialization call to a secure heap query API. That may be a valid safe-query expectation or a caller precondition violation depending on documented semantics. This sprint therefore treats the issue as a controlled secure-heap state lifecycle candidate and adds initialized control cases before interpreting the crash.

## Runnable Sprint Decision

The artifact is suitable for a small runnable sprint because it has:

- a minimal local C API PoC,
- local crash evidence,
- a narrow API surface,
- obvious state dimensions: pre-init, initialized, done, done-then-used.

The sprint must not claim a confirmed vulnerability unless documentation and version behavior support that conclusion.
