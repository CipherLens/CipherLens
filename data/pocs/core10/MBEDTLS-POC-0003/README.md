# MBEDTLS-POC-0003: [Bugfix] Fix null dereference in `mbedtls_pk_verify_ext()`

## Basic information

- Source: PR #8942
- URL: https://github.com/Mbed-TLS/mbedtls/pull/8942
- PoC type: memory_safety
- Primary module: pk/rsa
- Target function: mbedtls_pk_verify_ext
- Failure signal: NULL dereference crash

## Root cause

Missing NULL pointer validation before RSA key access in extended PK verification.

## Mutation point

library/pk.c: mbedtls_pk_verify_ext(), NULL check before RSA key access for opaque RSA keys.

## Buggy behavior

opaque RSA key path can dereference a NULL pointer

## Fixed behavior

NULL validation prevents invalid key access

## Regression test / PoC extraction plan

- Candidate test file: `tests/suites/test_suite_pk.function`
- Step 1: Inspect listed test files and identify the exact regression test case.
- Step 2: Extract a minimal input or API call sequence that triggers the buggy behavior.
- Step 3: Record build version, run command, and observed failure signal.
- Step 4: Map the triggering code to AST-level mutation points.

## Reproduction status

- Current status: reconstructable
- Local reproduction command: TBD
- Buggy version/commit: TBD
- Fixed version/commit: TBD

## Notes

Primary fix PR #8942; explicit NULL dereference crash with test evidence.
