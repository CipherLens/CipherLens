# memory_candidate_closure_and_valid_contract_campaign_v1 Report

## Summary

- quality_status: pass_no_candidate_valid_contract_completed
- families_attempted: 3
- candidate_found: False
- run_attempted_total: 90

## Families

- valid_decode_boundary: pass_no_candidate cases=30 compile=30 run=30 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0
- valid_evp_mac_boundary: pass_no_candidate cases=30 compile=30 run=30 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0
- valid_bio_boundary: pass_no_candidate cases=30 compile=30 run=30 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0

## Policy

Only contract-valid sanitizer, crash, hang, or canary corruption signals are candidates; invalid-contract observations are blocked from candidate promotion. Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
