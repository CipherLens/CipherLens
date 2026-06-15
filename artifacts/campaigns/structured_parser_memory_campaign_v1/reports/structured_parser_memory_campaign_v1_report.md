# structured_parser_memory_campaign_v1 Report

## Summary

- quality_status: pass_no_candidate_structured_parser_completed
- families_attempted: 3
- candidate_found: False
- run_attempted_total: 180

## Families

- asn1_nested_boundary_structured: pass_no_candidate cases=60 compile=60 run=60 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0
- x509_inner_boundary_structured: pass_no_candidate cases=60 compile=60 run=60 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0
- pkcs_container_inner_boundary_structured: pass_no_candidate cases=60 compile=60 run=60 asan=0 ubsan=0 crash=0 timeout=0 canary=0 candidates=0

## Policy

Only malformed-only structured parser sanitizer, crash, or hang signals are candidates; trailing-garbage and full-consumption oracle patterns are not used. Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
