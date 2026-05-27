# MBEDTLS-POC-0001: mbedtls_mpi_write_string negative MPI buffer boundary

## Source

This pattern comes from Mbed TLS PR #2405 and issue #2404. The affected API is `mbedtls_mpi_write_string` in `library/bignum.c`.

## Root Cause

In the buggy version, `mbedtls_mpi_write_string()` writes the negative sign `'-'` when `X->s == -1`, but it does not decrement `buflen` after writing the sign byte. As a result, the remaining conversion logic receives an incorrect remaining buffer length and may write one byte past the caller-provided output buffer.

The critical fix is:

```c
if (X->s == -1) {
    *p++ = '-';
    buflen--;
}
```

## Trigger Condition

The minimal PoC sets the MPI value to `-1`, uses radix `2`, and passes a small output buffer with `BUFLEN = 4`. A canary region is placed immediately after the output buffer.

The buggy version corrupts the canary:

```text
ret=0
olen=3
buf/canary prefix=-1\x00B1\xa5...
[BUG] Canary corrupted: out-of-bounds write detected.
```

The fixed version keeps the canary intact:

```text
ret=0
olen=3
buf/canary prefix=-1\x001\xa5...
[OK] Canary intact.
```

## Mutation Points

- `VALUE`: controls whether the MPI value is negative.
- `RADIX`: controls the string conversion path and output representation length.
- `BUFLEN`: controls the caller-provided output buffer boundary.
- `CANARY_SIZE`: controls the oracle detection region.

## Multi-granularity Masking Guidance

### Identifier-level Candidates

- `buflen`: the remaining output buffer length.
- `X->s`: the sign field of the MPI value.
- `p`: the output pointer advanced after writing the sign byte.

### Value-level Candidates

- `-1`: negative MPI value used to enter the sign-handling branch.
- `2`: radix used by the PoC.
- `4`: small output buffer size.

### Statement-level Candidates

- `*p++ = '-'`: writes the negative sign byte.
- `buflen--`: the missing/fixed statement that updates the remaining buffer length.

### Block-level Candidates

- The negative-number handling block:

```c
if (X->s == -1) {
    *p++ = '-';
    buflen--;
}
```

## Vulnerability Path Features

The migrated target API should preserve these features:

- negative integer path,
- sign byte or sign handling before serialized digits,
- caller-provided output buffer,
- explicit output buffer length,
- library writes to caller-provided buffer,
- canary or sanitizer observable boundary oracle.

Optional features:

- radix parameter,
- explicit output length pointer.

Not required features:

- exact same function name,
- exact same return-code convention,
- exact same internal bignum representation.

## Migration Guidance

Good target API features:

- accepts a big integer object,
- supports negative integer representation or sign handling,
- writes serialized output into a caller-provided buffer,
- accepts explicit output length,
- returns observable success/failure or output length.

Bad target API features:

- returns only a library-allocated string,
- hides output allocation internally,
- has no caller-controlled output buffer length,
- cannot represent or observe the negative-number serialization path.

For example, `BN_bn2binpad` is more suitable than `BN_bn2hex` for this specific vulnerability-path migration because `BN_bn2binpad` preserves the caller-provided output buffer and explicit length, while `BN_bn2hex` returns a library-allocated string.

## Expected Oracle

Bug candidate signals:

- canary corruption,
- AddressSanitizer crash,
- out-of-bounds write.

Safe or fixed behavior:

- canary remains intact,
- no sanitizer crash,
- return value and output length are consistent with safe API behavior.

## Evidence Files

- Metadata: `data/pocs/core10/MBEDTLS-POC-0001/metadata.json`
- Fix patch: `data/pocs/core10/MBEDTLS-POC-0001/fix.patch`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0001/reproduction_result.md`
- Buggy log: `data/pocs/core10/MBEDTLS-POC-0001/poc/run_min_buggy.log`
- Fixed log: `data/pocs/core10/MBEDTLS-POC-0001/poc/run_min_fixed.log`
