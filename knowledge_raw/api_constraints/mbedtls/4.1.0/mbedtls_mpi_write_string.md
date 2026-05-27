# API Constraints: mbedtls_mpi_write_string (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_mpi_write_string`
- Source file: `tf-psa-crypto/drivers/builtin/src/bignum.c`
- Declaration: `tf-psa-crypto/drivers/builtin/include/mbedtls/private/bignum.h`
- Signature:

```c
int mbedtls_mpi_write_string(const mbedtls_mpi *X, int radix,
                             char *buf, size_t buflen, size_t *olen);
```

## Parameter Semantics

- `X`: initialized source MPI.
- `radix`: numeric base for output string; valid range is 2 through 16.
- `buf`: caller-provided writable output buffer of length `buflen`.
- `buflen`: available size in bytes of `buf`.
- `olen`: non-NULL output length pointer. On success it includes the final NUL byte. If `buflen == 0` or the buffer is too small, it can be used to obtain the required size.

## Return Value Semantics

- `0`: success.
- `MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL`: `buf` is too small; `*olen` is updated with the required size.
- `MBEDTLS_ERR_MPI_BAD_INPUT_DATA`: invalid radix.
- Other negative error codes may indicate allocation or internal failure.

## Ownership and Buffer Constraints

- The output buffer is owned by the caller.
- The function writes into the caller-provided buffer and NUL-terminates on success.
- The function exposes an explicit output buffer length (`buflen`) and an explicit output length pointer (`olen`).

## Harness Generation Notes

- Initialize `mbedtls_mpi`, set or read a value, allocate a fixed output buffer, and pass `buf`, `buflen`, and `&olen`.
- Negative-value serialization is relevant: current source decrements `buflen` after writing `'-'`.
- Good harness oracles: return code, `olen`, NUL termination, canary after `buf`, ASAN/UBSAN.

## Vulnerability-Pattern Migration Notes

- Preserves the caller-provided output buffer boundary pattern used by `MBEDTLS-POC-0001`.
- Mutation points: MPI sign/value, radix, `buflen`, and oracle canary size.
- Cross-library target APIs should expose caller output buffer, explicit length, and library write into caller memory.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_bignum.function`: direct calls around lines reported by `rg` at 138, 162, 182, and 202.
- `tf-psa-crypto/drivers/builtin/src/bignum.c`: internal use around line 766.
