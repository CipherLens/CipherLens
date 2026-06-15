# pkey_verify_semantic_compile_run_analyze_v1

## Summary

- family: pkey_verify_semantic
- track: semantic
- target_library: openssl
- rendered_case_count: 10
- compile_success: 10
- compile_failed: 0
- run_attempted: 10
- oracle_events: 10
- candidate_count: 0
- quality_status: pass_no_candidate

## Policy

- No DER parsing, trailing-garbage, or full-consumption oracle was used.
- Nonzero exits are not treated as crashes without sanitizer or signal evidence.
- No feedback main store, pattern bank, adapter recipe, or normalized template was modified.
- No confirmed vulnerability, CVE, or exploitable claim is made.

## Next

- Continue with semantic feedback triage only if a non-normal semantic candidate is present.
- Otherwise continue scheduler selection for the next local family/stage.
