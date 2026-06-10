# Current Evidence Snapshot

Seed issue: `OPENSSL-ISSUE-28669`

Family: `secure_heap_state_lifecycle`

API: `CRYPTO_secure_used`

## Current Analyzer Classification

```text
total_cases: 5
raw_status_counts: {'run_nonzero': 2, 'run_ok': 3}
verdict_counts: {'crash_candidate': 2, 'normal_defined_behavior': 2, 'safe_precondition_failure': 1}
```

## Crash Cases

- `secure_heap_0000_pre_init_used_only`: `pre_init + used_only`, exit 139, signal 11, `crash_candidate`
- `secure_heap_0003_done_then_used`: `initialized_then_done + done_then_used`, exit 139, signal 11, `crash_candidate`

## Control Cases

- `secure_heap_0001_initialized_used`: initialized control, exit 0, `normal_defined_behavior`
- `secure_heap_0002_initialized_check_used`: initialized check control, exit 0, `normal_defined_behavior`
- `secure_heap_0004_done_check_then_used`: post-done check prevents `used`, exit 0, `safe_precondition_failure`

## Crash / Sanitizer Evidence

- Current run has SIGSEGV / exit 139.
- Historical local artifact reports Valgrind Invalid read.
- Current sprint did not observe ASAN or UBSAN output.
- Current sprint did not run Valgrind.

## Missing Evidence

- Manual API contract confirmation for `CRYPTO_secure_used()` before init and after done.
- Current gdb backtrace.
- Current Valgrind run if available.
- ASAN/UBSAN build and rerun.
- Version matrix beyond local `openssl-3.5.5`.

Current strict interpretation: crash candidate / precondition triage, not a confirmed vulnerability or CVE.
