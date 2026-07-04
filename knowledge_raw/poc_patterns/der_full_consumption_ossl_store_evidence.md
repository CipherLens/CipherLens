# DER Full-Consumption OSSL_STORE Evidence

Pattern family: `der_full_consumption`

Primary classification: `app_level_validation_gap_candidate`

This note makes the DER v2 plus OSSL_STORE evidence visible to the RAG knowledge layer.

## Evidence Layers

The older `artifacts/triage/ossl_store_full_consumption/` material is issue-level evidence. It shows that user-facing OpenSSL commands can process a valid leading DER object and produce observable output while ignoring malformed ASN.1 trailing bytes. The same triage also checked malformed-only inputs, which were rejected. That distinction keeps the finding scoped to valid-prefix acceptance with trailing malformed content, not arbitrary malformed input acceptance.

The DER full-consumption v2 sprint is framework-level systematic reproduction. It connects the Pattern Bank, candidate queue, scheduler, controlled mutation matrix, app-level runner, analyzer, and feedback loop to the same behavior.

## Current DER v2 Result

The controlled DER v2 sprint produced 75 cases:

- 30 `app_level_validation_gap_candidate`
- 39 `expected_prefix_accept_behavior`
- 3 `malformed_baseline_reject`
- 3 `valid_baseline_success`

The 30 app-level validation gap candidates are valid DER prefix plus malformed trailing content cases across OpenSSL app-level parser targets such as x509, pkey, and pkcs8.

## Interpretation

This is not crash evidence. There is no ASAN/UBSAN report, SEGV, heap overflow, stack overflow, or use-after-free signal in the current result.

This is not a validated issue and must not be described as a CVE. The current label is `app_level_validation_gap_candidate`. A stronger claim would require documentation review, caller-impact analysis, and a minimized upstream-quality reproducer.

If an upstream issue is prepared later, cite the existing minimal reproducer and summaries under:

- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_README.md`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_summary.json`
- `artifacts/sprints/der_full_consumption_v2/results/behavior_summary.json`
- `artifacts/feedback/der_full_consumption_feedback.jsonl`

## Related Pattern

`MBEDTLS-POC-0020` remains the source historical DER full-consumption pattern. DER v2 extends it into an app-level validation-gap family and feedback signal.
