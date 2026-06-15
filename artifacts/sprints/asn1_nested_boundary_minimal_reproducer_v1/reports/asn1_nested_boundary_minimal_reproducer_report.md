# ASN.1 Nested Boundary Minimal Reproducer Report

## Seed Status

- OPENSSL-ISSUE-30581 artifact found: `true`
- Real input seed found: `false`
- Only placeholder input: `true`
- seed_status: `only_placeholder_input_found`

The artifact metadata explicitly says `placeholder_input_used`, `missing_original_input: true`, and references the original expected input `/tmp/pbmac1_null_salt.p12`. The bundled `inputs/test.p12` is therefore not treated as a real reproduction seed.

## CLI Reproducer

- Script: `cli_reproducer/run_pkcs12_info_repro.sh`
- Result: refused to run strict reproduction with placeholder input
- exit_code: `3`
- signal: none
- observed_behavior: `seed_missing_or_placeholder`

## C API Reproducer

- Generated: `false`
- Compiled: `false`
- Run: `false`
- Reason: no real seed and no valuable CLI reproduction to carry forward.

## gdb / sanitizer

- gdb backtrace: not run, no crash
- sanitizer evidence: metadata mentions sanitizer log, but no local sanitizer log is bundled and current OpenSSL 3.5.5 build is not ASAN/UBSAN-enabled.
- Future sanitizer sprint needed: yes, after real seed recovery.

## Classification

`placeholder_only`, `seed_missing`, `strict_reproduction_failed`, `sanitizer_needed`, `not_enough_for_claim`

## Claims

- strict_reproduction_success: `false`
- crash_candidate: `false`
- confirmed vulnerability: `false`
- enter A-path now: `false`

## Next Task

`asn1_nested_boundary_seed_enrichment_v1`
