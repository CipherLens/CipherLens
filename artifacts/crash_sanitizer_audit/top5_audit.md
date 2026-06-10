# Crash/Sanitizer Top5 Evidence Audit

Top5 source: `artifacts/candidate_queue/candidate_queue.yaml`

## Summary

- needs_manual_confirmation: `4`
- ready_for_runnable_family: `1`

## Issues

### OPENSSL-ISSUE-16196

- family: `asn1_nested_boundary`
- recommended_verdict: `needs_manual_confirmation`
- crash_signal: `{'asan': False, 'ubsan': False, 'segv': False, 'exit_139': False, 'heap_buffer_overflow': False, 'stack_buffer_overflow': False, 'use_after_free': False, 'other': []}`
- reproducibility_score: `0.35`
- crash_confidence_score: `0.35`
- harness_validity_score: `0.45`
- migration_readiness_score: `0.35`
- action: Do manual repro audit before promoting to runnable family.

### OPENSSL-ISSUE-18168

- family: `asn1_nested_boundary`
- recommended_verdict: `needs_manual_confirmation`
- crash_signal: `{'asan': False, 'ubsan': False, 'segv': False, 'exit_139': False, 'heap_buffer_overflow': False, 'stack_buffer_overflow': False, 'use_after_free': False, 'other': []}`
- reproducibility_score: `0.35`
- crash_confidence_score: `0.35`
- harness_validity_score: `0.45`
- migration_readiness_score: `0.35`
- action: Do manual repro audit before promoting to runnable family.

### OPENSSL-ISSUE-26106

- family: `asn1_nested_boundary`
- recommended_verdict: `needs_manual_confirmation`
- crash_signal: `{'asan': False, 'ubsan': False, 'segv': True, 'exit_139': False, 'heap_buffer_overflow': False, 'stack_buffer_overflow': False, 'use_after_free': False, 'other': []}`
- reproducibility_score: `0.55`
- crash_confidence_score: `0.7`
- harness_validity_score: `0.55`
- migration_readiness_score: `0.55`
- action: Recover original input/environment and confirm crash under the affected version.

### OPENSSL-ISSUE-28669

- family: `secure_heap_state_lifecycle`
- recommended_verdict: `ready_for_runnable_family`
- crash_signal: `{'asan': False, 'ubsan': False, 'segv': True, 'exit_139': True, 'heap_buffer_overflow': False, 'stack_buffer_overflow': False, 'use_after_free': False, 'other': ['valgrind_invalid_read']}`
- reproducibility_score: `0.85`
- crash_confidence_score: `0.9`
- harness_validity_score: `0.75`
- migration_readiness_score: `0.8`
- action: Start a small D_then_A secure-heap lifecycle sprint that reproduces CRYPTO_secure_used without secure heap init, then adds safe-control cases.

### OPENSSL-ISSUE-30581

- family: `asn1_nested_boundary`
- recommended_verdict: `needs_manual_confirmation`
- crash_signal: `{'asan': False, 'ubsan': False, 'segv': False, 'exit_139': False, 'heap_buffer_overflow': False, 'stack_buffer_overflow': False, 'use_after_free': False, 'other': []}`
- reproducibility_score: `0.35`
- crash_confidence_score: `0.35`
- harness_validity_score: `0.45`
- migration_readiness_score: `0.35`
- action: Do manual repro audit before promoting to runnable family.

## Recommended Next Family

- family: `secure_heap_state_lifecycle`
- seed_issue: `OPENSSL-ISSUE-28669`
- proposed_execution_path: `D_then_A`
- proposed_sprint_name: `secure_heap_state_lifecycle_v1`
- should_start_runnable_sprint_now: `true`

This is the only top5 candidate with local crash evidence: SIGSEGV/exit 139 plus Valgrind Invalid read. Treat it as a sprint seed, not as a new vulnerability claim.
