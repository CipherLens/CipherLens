# MBEDTLS-POC-0002: mbedtls_mpi_sub_abs output limb boundary

## Source

This pattern comes from Mbed TLS PR #4096 and issue #4042. The affected API is
`mbedtls_mpi_sub_abs` in `library/bignum.c`.

The confirmed merge commit is `bbd2bfb666c134fe534104e66a7f34f66f555781`.
The local buggy worktree used `bbd2bfb666c134fe534104e66a7f34f66f555781^1`,
and the library fix commit is `c8a917711097eff2775415d1ef68058696194928`.

## Root Cause

In the buggy version, `mbedtls_mpi_sub_abs()` does not reject the case where the
effective limb count of `B` is greater than `A->n`. The function then continues
to the subtraction helper:

```c
mpi_sub_hlp( n, X->p, B->p )
```

In the reproduced case, `n` is larger than the allocated limb count of `X`. The
helper can therefore write beyond `X->p`.

The fixed version adds an early negative-result check:

```c
if( n > A->n )
{
    ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    goto cleanup;
}
```

## Trigger Condition

The minimal PoC uses regression-test-derived operands:

- `A` radix: `10`
- `A` value: `5`
- `B` radix: `16`
- `B` value: `123456789abcdef01`

The resulting internal state is:

```text
A.n=1 B.n=2 X.n=1 sizeof(mbedtls_mpi_uint)=8
```

The PoC manually prepares `X` with one output limb followed immediately by a
canary region. This makes the buggy helper write observable.

## Buggy and Fixed Behavior

Buggy output:

```text
A.n=1 B.n=2 X.n=1 sizeof(mbedtls_mpi_uint)=8
ret=0
expected=-10
[BUG] Canary corrupted: mbedtls_mpi_sub_abs wrote beyond X->p.
```

Fixed output:

```text
A.n=1 B.n=2 X.n=1 sizeof(mbedtls_mpi_uint)=8
ret=-10
expected=-10
[OK] Canary intact.
```

The key behavioral difference is that the buggy version returns success and
corrupts the canary, while the fixed version returns
`MBEDTLS_ERR_MPI_NEGATIVE_VALUE` and keeps the canary intact.

## Mutation Points

- `A_VALUE`: controls the magnitude and effective limb count of the left operand.
- `B_VALUE`: controls the magnitude and effective limb count of the right operand.
- `A_RADIX`: controls parsing of the left operand.
- `B_RADIX`: controls parsing of the right operand.
- `OUTPUT_LIMBS`: controls the manually prepared `X->n` / `X->p` output boundary.
- `CANARY_SIZE`: controls the oracle region after `X->p`.

## Multi-granularity Masking Guidance

### Identifier-level Candidates

- `n`: effective limb count used by the subtraction helper.
- `A->n`: allocated/effective limb count boundary for the left operand.
- `X->n`: output limb count prepared by the harness.
- `X->p`: output limb storage.
- `B->p`: right operand limb storage read by the helper.

### Expression-level Candidates

- `n > A->n`: fixed negative-result boundary check.

### Statement-level Candidates

- `ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;`
- `goto cleanup;`
- `mpi_sub_hlp( n, X->p, B->p )`

### Block-level Candidates

```c
if( n > A->n )
{
    ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE;
    goto cleanup;
}
```

## Vulnerability Path Features

The migrated target API should preserve these features:

- bignum absolute subtraction,
- left operand has fewer effective limbs than the right operand,
- caller or harness controls output limb storage,
- explicit output limb boundary,
- library writes into output limb storage,
- canary or sanitizer observable boundary oracle,
- negative-result rejection or error path.

Optional features:

- radix-based operand parsing,
- exact Mbed TLS limb size,
- exact error-code value.

Not required features:

- exact same function name,
- exact internal helper name,
- exact regression test syntax.

## Migration Guidance

This pattern is about output limb storage boundary behavior, not merely about
whether two APIs both perform bignum subtraction.

Good target API features:

- accepts big integer operands,
- performs absolute or unsigned bignum subtraction,
- exposes or allows harness control over output limb storage,
- can observe output storage boundary writes with a canary or sanitizer,
- returns an observable error when subtraction would be negative.

Weak target API features:

- performs bignum subtraction but fully owns output allocation and limb growth,
- exposes only high-level result semantics without caller-controlled limb storage.

For example, OpenSSL `BN_usub` and `BN_sub` are functionally related to bignum
subtraction, but they do not naturally preserve the same manual `X->p` / `X->n`
limb boundary vulnerability path. They should be treated as weak candidates for
automatic migration unless a specialized harness can control or instrument
internal result limb storage.

## Expected Oracle

Bug candidate signals:

- canary corruption after `X->p`,
- sanitizer crash,
- out-of-bounds write,
- unexpected success return `0`.

Safe or fixed behavior:

- return value is `MBEDTLS_ERR_MPI_NEGATIVE_VALUE`,
- canary remains intact,
- no sanitizer crash.

## Evidence Files

- Metadata: `data/pocs/core10/MBEDTLS-POC-0002/metadata.json`
- Notes: `data/pocs/core10/MBEDTLS-POC-0002/notes.md`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0002/reproduction_result.md`
- PoC source: `data/pocs/core10/MBEDTLS-POC-0002/poc/poc_mpi_sub_abs_min.c`
- Buggy log: `data/pocs/core10/MBEDTLS-POC-0002/poc/run_min_buggy.log`
- Fixed log: `data/pocs/core10/MBEDTLS-POC-0002/poc/run_min_fixed.log`
- Library files: `data/pocs/core10/MBEDTLS-POC-0002/library_files.txt`
- Test files: `data/pocs/core10/MBEDTLS-POC-0002/test_files.txt`
- Commits: `data/pocs/core10/MBEDTLS-POC-0002/commits.txt`
- Fix commits: `data/pocs/core10/MBEDTLS-POC-0002/fix_commits.txt`
