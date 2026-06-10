# secure_heap_state_lifecycle_v1 Final Report

## Scope

This sprint starts from `OPENSSL-ISSUE-28669`, whose local artifact describes a
NULL rwlock dereference in `CRYPTO_secure_used()` when the secure heap is not
initialized.

The route is `D_then_B_precondition_triage`: first audit the local issue
evidence, then run a controlled OpenSSL-only state lifecycle matrix. This is not
an A-path cross-library migration because no clear target-library equivalent for
OpenSSL secure-heap internal state was identified.

No LLM / GLM adapter generation was used, and no direct LLM-to-C generation was
used.

## Evidence Audit

Local artifacts exist under `datasets/openssl/poc_artifacts/issue_28669`:

- `README.md`
- `metadata.json`
- `poc.c`
- `run.sh`

The local metadata reports testing against `OpenSSL 3.0.13 / libcrypto.so.3`.
The reported local evidence includes SIGSEGV, exit code 139, and a Valgrind
Invalid read summary. The artifact does not establish strict historical
reproduction and does not identify a confirmed affected-version range.

## API Precondition

Local OpenSSL 3.5.5 source inspection found that `CRYPTO_secure_used()` calls
`CRYPTO_THREAD_read_lock(sec_malloc_lock)` without an explicit
`secure_mem_initialized` guard. By contrast, `CRYPTO_secure_allocated()` has a
guard that returns 0 when secure heap is not initialized.

The manpage documents that `CRYPTO_secure_used()` returns the number of bytes
allocated in the secure heap, but it does not clearly state pre-init behavior for
this API. Therefore the precondition status remains:

```text
needs_manual_doc_confirmation
```

## Controlled Matrix

Rendered cases: 5

```text
secure_heap_0000_pre_init_used_only
secure_heap_0001_initialized_used
secure_heap_0002_initialized_check_used
secure_heap_0003_done_then_used
secure_heap_0004_done_check_then_used
```

Run summary:

```text
total_cases: 5
raw_status_counts: {'run_nonzero': 2, 'run_ok': 3}
verdict_counts: {'crash_candidate': 2, 'normal_defined_behavior': 2, 'safe_precondition_failure': 1}
```

Crash-candidate cases:

```text
secure_heap_0000_pre_init_used_only
secure_heap_0003_done_then_used
```

Both crash-candidate cases produced SIGSEGV / exit 139 through the harness crash
oracle. The initialized controls returned defined behavior, and
`CRYPTO_secure_malloc_initialized()` prevented the post-done `CRYPTO_secure_used()`
call.

Current Valgrind was not run because `valgrind` is unavailable in this
environment. No current ASAN / UBSAN signal was observed in this sprint run.

## RAG And Feedback

The sprint wrote analyzer feedback to:

```text
artifacts/feedback/secure_heap_state_lifecycle_feedback.jsonl
```

The pattern bank and RAG source layers were updated so that `OPENSSL-ISSUE-28669`
is classified as:

```text
family: secure_heap_state_lifecycle
oracle_type: secure_heap_preinit_crash_oracle
```

After rebuilding RAG, the validation query:

```text
OPENSSL-ISSUE-28669 CRYPTO_secure_used secure heap state lifecycle NULL rwlock
```

returned `OPENSSL-ISSUE-28669` as the top result with family
`secure_heap_state_lifecycle`.

## Interpretation

This sprint confirms a runnable, controlled `secure_heap_state_lifecycle` crash
candidate pattern with safe initialized controls. It should not be reported as a
confirmed vulnerability or CVE yet.

The correct current positioning is:

```text
crash_candidate / precondition triage
```

The next step is manual documentation confirmation plus a version matrix,
preferably with Valgrind or sanitizer instrumentation available.
