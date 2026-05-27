# Reproduction Result: MBEDTLS-POC-0001

## Status

reproduced

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0001-buggy
- commit: eff335d575e0949ba25b60a358f31461eab055fe^

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0001-fixed
- commit: eff335d575e0949ba25b60a358f31461eab055fe

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0001/poc/poc_mpi_write_string_min.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0001/poc/poc_min_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0001/poc/poc_min_fixed

## Trigger

- value: -1
- radix: 2
- buflen: 4

## Buggy output

ret=0
olen=3
buf/canary prefix=-1\x00B1\xa5\xa5\xa5\xa5\xa5\xa5\xa5
[BUG] Canary corrupted: out-of-bounds write detected.

## Fixed output

ret=0
olen=3
buf/canary prefix=-1\x001\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5
[OK] Canary intact.

## Root cause

In the buggy version, `mbedtls_mpi_write_string()` writes the negative sign `'-'` but does not decrement `buflen`. The remaining conversion code therefore receives an incorrect remaining buffer length and can write one byte past the caller-provided buffer.

## Confirmed mutation point

library/bignum.c: mbedtls_mpi_write_string()

Critical fixed statement:

buflen--;

## Occlusion candidates

- identifier-level: `buflen`
- statement-level: `buflen--;`
- block-level: `if( X->s == -1 ) { *p++ = '-'; buflen--; }`
