# memory_safety_focused_campaign_v2_remaining_boundaries Report

## Summary

- quality_status: pass_crash_or_sanitizer_candidate_found
- families_attempted: 1
- candidate_found: True
- run_attempted_total: 19

## Families

- memory_length_boundary: pass_memory_candidate_found cases=30 compile=19 run=19 asan=0 ubsan=1 crash=0 timeout=0 canary=0 candidates=1

## Policy

Only sanitizer, crash, hang, or canary corruption signals are candidates. Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
