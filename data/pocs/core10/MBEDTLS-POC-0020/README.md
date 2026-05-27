# MBEDTLS-POC-0020: mbedtls_rsa_parse_key and mbedtls_rsa_parse_pubkey accept trailing garbage

## Basic information

- Source: PR #8804
- URL: https://github.com/Mbed-TLS/mbedtls/pull/8804
- PoC type: parser_or_encoding
- Primary module: rsa/pkparse
- Target function: mbedtls_rsa_parse_key / mbedtls_rsa_parse_pubkey
- Failure signal: accepts malformed key / trailing garbage

## Root cause

Incorrect edge-case handling in mbedtls_pk_parse_key.

## Mutation point

library/pem.c: PEM input boundary checks and padding/error return handling.

## Buggy behavior

RSA key parser accepts trailing garbage after DER object

## Fixed behavior

parser rejects trailing bytes after valid RSA key object

## Regression test / PoC extraction plan

- Candidate test file: `tests/suites/test_suite_pem.data`
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

Defect semantics with library patch and test/patch evidence; reconstructable candidate.
