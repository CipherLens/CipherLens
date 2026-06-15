# orchestrator_execute_x509_compile_run_analyze_v1 Report

## Scope

- previous state loaded: True
- selected family: x509_parsing
- executed stages: compile_run, oracle_aware_analyze, candidate_queue
- next stage: triage

## Compile/Run

- rendered cases: 4
- compile success: 4
- run attempted: 4
- normal exit: 3
- nonzero exit: 1
- crash signals: 0
- timeout: 0
- ASAN/UBSAN: 0 / 0
- OpenSSL path: /home/wen/work/install-openssl-3.5.5-asan/bin/openssl
- OpenSSL version: OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
- ASAN OpenSSL available: True
- fallback reason: 

## Oracle-Aware Analyze

- oracle events: 4
- normal_accept: 1
- normal_reject: 2
- full_consumption_gap_candidate: 1
- semantic_divergence_candidate: 0
- needs_triage: 0
- candidate queue total: 4

## Claim Policy

No confirmed vulnerability, CVE, or exploitability claim is made.

## Quality

- quality_status: pass
