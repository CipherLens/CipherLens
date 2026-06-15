# decodeblock_oracle_fix_and_null_deref_dispatch_v1 Report

## Summary

- quality_status: pass_crash_or_sanitizer_candidate_found
- families_attempted: 1
- candidate_found: True
- run_attempted_total: 43

## Families

- null_deref_dispatch: pass_crash_or_sanitizer_candidate_found cases=50 compile=43 run=43 asan=0 ubsan=1 crash=0 timeout=0 canary=0 candidates=1

## Policy

Only sanitizer, crash, or hang signals are candidates in this null-deref dispatch pass. Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
