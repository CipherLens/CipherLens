# Working Notes

## Manual tasks

- [ ] Confirm exact fixing commit.
- [ ] Locate exact regression test case.
- [ ] Extract minimal PoC or API call sequence.
- [ ] Identify buggy and fixed versions.
- [ ] Run reproduction test locally.
- [ ] Record failure signal.
- [ ] Confirm AST mutation point.
- [ ] Prepare RAG context sources.

## Investigation log

- TBD

## Candidate commands

```bash
# Inspect source files
cat library_files.txt

# Inspect test files
cat test_files.txt

# Inspect commits
cat commits.txt
```

## Exact fixing commit confirmed

Confirmed PR #4096 merge commit:

- bbd2bfb666c134fe534104e66a7f34f66f555781

The merge contains:

- regression_test_commit=43e89e1b1583a5847520573ddb761bd5a842e70f
- library_fix_commit=c8a917711097eff2775415d1ef68058696194928

Root cause:
mbedtls_mpi_sub_abs() did not reject the case where the effective limb count of B is greater than A->n.
The buggy code then proceeds to mpi_sub_hlp( n, X->p, B->p ), which can write beyond X->p.

Confirmed fixed check:

if( n > A->n )
{
    ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    goto cleanup;
}

Regression tests added:
- mbedtls_mpi_sub_abs:10:"5":16:"123456789abcdef01":10:"0":MBEDTLS_ERR_MPI_NEGATIVE_VALUE
- mbedtls_mpi_sub_abs:10:"-5":16:"-123456789abcdef01":10:"0":MBEDTLS_ERR_MPI_NEGATIVE_VALUE
- mbedtls_mpi_sub_abs:10:"-5":16:"123456789abcdef01":10:"0":MBEDTLS_ERR_MPI_NEGATIVE_VALUE
- mbedtls_mpi_sub_abs:10:"5":16:"-123456789abcdef01":10:"0":MBEDTLS_ERR_MPI_NEGATIVE_VALUE

## Minimal PoC reproduction completed

The deterministic minimal PoC was created and executed.

Trigger:

- A = 5, radix 10
- B = 0x123456789abcdef01, radix 16
- A.n = 1
- B.n = 2
- X.n = 1

Buggy result:

- ret = 0
- expected = MBEDTLS_ERR_MPI_NEGATIVE_VALUE (-10)
- canary corrupted

Fixed result:

- ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE (-10)
- canary intact

Conclusion:

MBEDTLS-POC-0002 is now locally reproduced. The confirmed failure signal is canary corruption / out-of-bounds write in mbedtls_mpi_sub_abs().
