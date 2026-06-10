# DER v2 + OSSL_STORE Evidence Summary

## What The Earlier OSSL_STORE Triage Shows

The earlier triage under `artifacts/triage/ossl_store_full_consumption/` provides issue-level evidence for app-level DER full-consumption gaps. Its overall summary classifies the behavior as `real_app_level_validation_gap_candidate`, not a crash and not a confirmed CVE.

The tested app surfaces include `openssl x509`, `openssl pkey`, `openssl pkcs8`, public-key handling, CSR commands, and CRL commands. The common observation is that app commands can accept a valid leading DER object followed by malformed ASN.1 trailing bytes while rejecting the malformed-only tail. That boundary matters: this is valid-prefix acceptance with ignored malformed trailing content, not arbitrary malformed input acceptance.

Key OSSL_STORE and app-level evidence files:

- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_README.md`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_summary.json`
- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/`
- `artifacts/triage/ossl_store_full_consumption/csr_crl_boundary/`
- `artifacts/triage/ossl_store_full_consumption/ossl_store_doc_semantics.md`
- `artifacts/triage/ossl_store_full_consumption/ossl_store_source_callchain.md`
- `artifacts/sprints/der_full_consumption_v2/ossl_store_related_files.txt`
- `artifacts/sprints/der_full_consumption_v2/ossl_store_keyword_hits.txt`

## What DER v2 Adds

The DER full-consumption v2 controlled sprint adds framework-level evidence. It connects the Pattern Bank, scheduler seed, controlled mutation dimensions, app-level runner, and feedback loop to the same semantic shape.

The controlled sprint produced 75 cases:

- 30 `app_level_validation_gap_candidate`
- 39 `expected_prefix_accept_behavior`
- 3 `malformed_baseline_reject`
- 3 `valid_baseline_success`

The 30 gap candidates occur for `valid_der_plus_malformed_tail` across `openssl_app_x509`, `openssl_app_pkey`, and `openssl_app_pkcs8`. The feedback has been written back to `artifacts/feedback/der_full_consumption_feedback.jsonl`, and the scheduler priority for `der_full_consumption` is now 0.9.

## Relationship Between The Two Evidence Layers

The older OSSL_STORE triage is the issue-level evidence: it demonstrates that real user-facing OpenSSL commands can process the leading valid DER object and produce useful output while ignoring malformed ASN.1 tail bytes.

DER v2 is the framework-level reproduction: it shows that the same behavior can be represented as a Pattern Bank family, scheduled as a candidate, explored through controlled mutation, classified by an app-level oracle, and fed back into the scheduler/RAG loop.

Together they support the label `app_level_validation_gap_candidate`. They do not by themselves establish a confirmed vulnerability or CVE.

## Why This Is Not A Confirmed Vulnerability Or CVE

This evidence is semantic, not crash evidence. There is no ASAN/UBSAN signature, no SEGV, and no memory-corruption signal in the current classification. Low-level `d2i_*` prefix parsing is also not enough by itself because OpenSSL exposes pointer-consumption semantics and some callers may intentionally parse streams of DER objects.

The stronger observation is app-level acceptance of a valid prefix plus malformed tail. Whether that is security-impacting depends on caller expectations, command documentation, downstream use of generated artifacts, and whether users reasonably expect whole-file validation for the specific command.

## Files To Cite If Preparing An Upstream Issue Later

If this is later turned into an upstream issue, cite existing evidence rather than rewriting it:

- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_README.md`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_summary.json`
- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/results/minimal_command_summary.json`
- `artifacts/triage/ossl_store_full_consumption/csr_crl_boundary/results/csr_crl_command_summary.json`
- `artifacts/sprints/der_full_consumption_v2/results/run.summary.json`
- `artifacts/sprints/der_full_consumption_v2/results/behavior_summary.json`
- `artifacts/feedback/der_full_consumption_feedback.jsonl`

This sprint did not prepare a new upstream issue draft.
