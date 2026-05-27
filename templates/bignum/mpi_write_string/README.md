# Bignum Template: mpi_write_string negative small buffer

## Source PoC

`poc_mpi_write_string_min.c`

## Target API

`mbedtls_mpi_write_string`

## Vulnerability Pattern

This template checks whether serializing a negative MPI value into an undersized caller-provided buffer can corrupt canary bytes placed immediately after the buffer.

## Key Mutation Points

- `[VALUE]`: integer value assigned to `mbedtls_mpi`
- `[RADIX]`: output radix used by `mbedtls_mpi_write_string`
- `[BUFLEN]`: caller-provided output buffer length
- `[CANARY_SIZE]`: canary region size

## Oracle

- Canary corrupted: possible out-of-bounds write
- Non-zero return with intact canary: safe rejection
- Zero return with intact canary: safe success
- Crash under ASAN/UBSAN: memory safety issue requiring triage

## Current Status

Golden example. This file is manually prepared and will be used as the target output format for future `mask.py` and `generator.py`.
