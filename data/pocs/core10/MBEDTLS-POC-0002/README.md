# MBEDTLS-POC-0002: Fix buffer overflow in mbedtls_mpi_sub_abs negative case

## Basic information

- Source: PR #4096
- URL: https://github.com/Mbed-TLS/mbedtls/pull/4096
- PoC type: memory_safety
- Primary module: bignum/mpi
- Target function: mbedtls_mpi_sub_abs
- Failure signal: buffer overflow

## Root cause

Incorrect handling of negative MPI subtraction when |B| has more limbs than |A|.

## Mutation point

library/bignum.c: mbedtls_mpi_sub_abs(), limb comparison and negative-result boundary handling.

## Buggy behavior

negative absolute subtraction edge case can trigger buffer overflow

## Fixed behavior

negative-result and limb-boundary handling is corrected

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

Primary fix candidate PR #4096; explicit buffer overflow regression with MPI test evidence.
