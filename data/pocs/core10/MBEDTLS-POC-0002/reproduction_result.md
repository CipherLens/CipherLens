# Reproduction Result: MBEDTLS-POC-0002

## Status

reproduced

## Buggy version

- worktree: repos/worktrees/MBEDTLS-POC-0002-buggy
- commit: bbd2bfb666c134fe534104e66a7f34f66f555781^1

## Fixed version

- worktree: repos/worktrees/MBEDTLS-POC-0002-fixed
- commit: bbd2bfb666c134fe534104e66a7f34f66f555781

## Minimal PoC

- source: data/pocs/core10/MBEDTLS-POC-0002/poc/poc_mpi_sub_abs_min.c
- buggy binary: data/pocs/core10/MBEDTLS-POC-0002/poc/poc_min_buggy
- fixed binary: data/pocs/core10/MBEDTLS-POC-0002/poc/poc_min_fixed

## Trigger

Regression-test-derived input:

- A radix: 10
- A value: 5
- B radix: 16
- B value: 123456789abcdef01

Internal state:

- A.n = 1
- B.n = 2
- X.n = 1
- sizeof(mbedtls_mpi_uint) = 8

## Buggy output

A.n=1 B.n=2 X.n=1 sizeof(mbedtls_mpi_uint)=8
ret=0
expected=-10
[BUG] Canary corrupted: mbedtls_mpi_sub_abs wrote beyond X->p.

## Fixed output

A.n=1 B.n=2 X.n=1 sizeof(mbedtls_mpi_uint)=8
ret=-10
expected=-10
[OK] Canary intact.

## Root cause

In the buggy version, mbedtls_mpi_sub_abs() does not reject the case where the effective limb count of B is greater than A->n. It then proceeds to mpi_sub_hlp(n, X->p, B->p), where n is larger than the allocated limb count of X, causing an out-of-bounds write.

## Confirmed fix

The fixed version adds:

if( n > A->n )
{
    ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    goto cleanup;
}

## Confirmed mutation point

library/bignum.c: mbedtls_mpi_sub_abs()

Statement-level mutation point:

if( n > A->n )
{
    ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    goto cleanup;
}

## Occlusion candidates

- identifier-level: n, A->n
- expression-level: n > A->n
- statement-level: ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
- block-level: if( n > A->n ) { ... }
