# MBEDTLS-POC-0001: Fix 1-byte buffer overflow in mbedtls_mpi_write_string() for negative MPIs

## Basic information

- Source: PR #2405
- URL: https://github.com/Mbed-TLS/mbedtls/pull/2405
- PoC type: memory_safety
- Primary module: bignum/mpi
- Target function: mbedtls_mpi_write_string
- Failure signal: buffer overflow / out-of-bounds write

## Root cause

Missing boundary check in output buffer length calculation for negative MPI string conversion.

## Mutation point

library/bignum.c: mbedtls_mpi_write_string(), output length calculation and 1-byte boundary check for negative MPIs.

## Buggy behavior

negative MPI string conversion can write past the output buffer

## Fixed behavior

output length calculation and boundary check prevent one-byte overflow

## Regression test / PoC extraction plan

- Candidate test file: `tests/suites/test_suite_mpi.data`
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

Primary fix candidate PR #2405; has library patch, issue reference, and MPI regression tests.
