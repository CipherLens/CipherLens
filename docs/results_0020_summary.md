# MBEDTLS-POC-0020 Result Summary

`MBEDTLS-POC-0020` models RSA DER top-level `SEQUENCE` trailing-garbage
handling. The experiment migrated this pattern from mbedTLS 4.1.0 to OpenSSL
3.5.5 using the `der_pointer_consumption` harness family.

Final reproduced result:

```text
total_cases: 54
raw_status_counts: {'run_ok': 36, 'run_nonzero': 18}
verdict_counts: {'safe_reject_behavior': 27, 'bug_candidate': 18, 'normal_behavior_needs_triage': 9}
total_pairs: 27
migration_verdict_counts: {'migrated_bug_candidate': 18, 'migration_needs_triage': 9}
```

All 54 rendered C cases compiled successfully.

The 18 `bug_candidate` cases are not crashes. They are semantic
pointer-consumption findings: OpenSSL `d2i_*` returns success for the leading
DER object, but the consumed pointer shows `consumed_len < der_len`, meaning
trailing garbage remains unconsumed.

The migrated signal is:

```text
mbedTLS: safe_reject_behavior
OpenSSL: bug_candidate
cross result: migrated_bug_candidate
```

This should be reported as an API usage semantic candidate rather than a direct
memory-safety vulnerability. OpenSSL exposes the advanced pointer through
`ppin`, so callers can defend by checking that the parser consumed the full
input buffer.
