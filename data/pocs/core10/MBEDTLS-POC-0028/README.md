# MBEDTLS-POC-0028: Detect invalid tag lengths in psa_aead_setup

## Basic information

- Source: PR #5350
- URL: https://github.com/Mbed-TLS/mbedtls/pull/5350
- PoC type: crypto_algorithm_or_api
- Primary module: psa/aead
- Target function: psa_aead_setup
- Failure signal: invalid parameter accepted

## Root cause

Missing validation of AEAD tag lengths from PSA drivers.

## Mutation point

library/psa_crypto.c: psa_aead_setup(), tag length validation against preset values.

## Buggy behavior

invalid AEAD tag length can be accepted

## Fixed behavior

invalid AEAD tag lengths are rejected during setup

## Regression test / PoC extraction plan

- Candidate test file: `tests/suites/test_suite_psa_crypto.data`
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

Concrete invalid-length validation fix with PSA crypto tests.
