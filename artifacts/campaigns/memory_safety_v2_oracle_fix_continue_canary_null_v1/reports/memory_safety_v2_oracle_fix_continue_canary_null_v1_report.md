# memory_safety_v2_oracle_fix_continue_canary_null_v1 Report

## Summary

- quality_status: pass_crash_or_sanitizer_candidate_found
- families_attempted: 1
- candidate_found: True
- run_attempted_total: 32

## Families

- buffer_canary_boundary: pass_memory_candidate_found cases=40 compile=32 run=32 asan=1 ubsan=0 crash=1 timeout=0 canary=2 candidates=3

## Policy

Only sanitizer, crash, hang, or canary corruption signals are candidates. Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
