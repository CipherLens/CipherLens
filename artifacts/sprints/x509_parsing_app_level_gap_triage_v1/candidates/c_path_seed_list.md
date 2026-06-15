# C-Path Seed List

- C-path seed 总数: `7`

- `OPENSSL-ISSUE-11567`: `openssl x509 -text app-visible wrong result`
- `OPENSSL-ISSUE-11772`: `openssl x509 -checkend app-visible wrong result`
- `OPENSSL-ISSUE-14457`: `openssl verify app-visible wrong output`
- `OPENSSL-ISSUE-14675`: `openssl verify certificate bundle handling semantic gap`
- `OPENSSL-ISSUE-23325`: `openssl verify -crl_check app-visible wrong result`
- `OPENSSL-ISSUE-29418`: `openssl x509 purpose app-visible inconsistency`
- `OPENSSL-ISSUE-6788`: `openssl crl app-visible wrong result`

- Excluded:
  - `MBEDTLS-POC-0027`: `A_recipe_slot_cross_library_migration`
  - `OPENSSL-ISSUE-13860`: `needs_more_evidence`
  - `OPENSSL-ISSUE-29574`: `overlap_asn1_nested_boundary`
  - `OPENSSL-ISSUE-9043`: `D_crash_sanitizer_evidence_audit`
