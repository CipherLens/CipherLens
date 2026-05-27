# MBEDTLS-POC-0004: Add invalid `padding_len` check in `get_pkcs_padding`

## Basic information

- Source: PR #9082
- URL: https://github.com/Mbed-TLS/mbedtls/pull/9082
- PoC type: memory_safety
- Primary module: cipher/pkcs_padding
- Target function: get_pkcs_padding / mbedtls_cipher_finish
- Failure signal: wrong output length / potential caller-side overflow

## Root cause

Incorrect output length assignment on invalid PKCS padding error path.

## Mutation point

library/cipher.c: get_pkcs_padding(), padding_len validation and output length assignment on error.

## Buggy behavior

invalid padding can leave an oversized output length

## Fixed behavior

padding length validation leaves output length safe on error

## Regression test / PoC extraction plan

- Candidate test file: `tests/suites/test_suite_cipher.function`
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

Primary fix candidate; invalid padding can leave huge output length and has cipher test evidence.
