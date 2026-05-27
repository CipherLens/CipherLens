# API Constraints: mbedtls_mpi_sub_abs (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_mpi_sub_abs`
- Source file: `tf-psa-crypto/drivers/builtin/src/bignum.c`
- Declaration: `tf-psa-crypto/drivers/builtin/include/mbedtls/private/bignum.h`
- Signature:

```c
int mbedtls_mpi_sub_abs(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);
```

## Parameter Semantics

- `X`: initialized destination MPI. The function may grow `X`.
- `A`: initialized minuend MPI.
- `B`: initialized subtrahend MPI.
- Semantics: computes `X = |A| - |B|`.

## Return Value Semantics

- `0`: success.
- `MBEDTLS_ERR_MPI_NEGATIVE_VALUE`: `|B| > |A|`.
- Other negative error codes can indicate allocation/internal failure.

## Ownership and Buffer Constraints

- Public API callers should treat `mbedtls_mpi` as an object managed by the MPI API.
- Current implementation grows `X` to `A->n` before subtraction and rejects `n > A->n`.
- Vulnerability-pattern harnesses that manually control `X->p`/`X->n` are specialized and version-sensitive.

## Harness Generation Notes

- Normal harnesses should use `mbedtls_mpi_init`, `mbedtls_mpi_read_string`, `mbedtls_mpi_sub_abs`, and `mbedtls_mpi_free`.
- A direct public harness should not rely on stable internal limb layout unless the research goal explicitly instruments the internals.
- Good oracles: return code `MBEDTLS_ERR_MPI_NEGATIVE_VALUE`, canary after controlled limb storage only for specialized internal-boundary harnesses, ASAN/UBSAN.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0002`.
- The important path is not just bignum subtraction; it is output limb boundary behavior and negative-result rejection.
- Cross-library candidates that fully hide result limb allocation are weak for automatic migration.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_bignum.function`: direct calls around lines 671, 781, 789, and 797.
- `tf-psa-crypto/tests/suites/test_suite_bignum.misc.data`: many `mbedtls_mpi_sub_abs` cases including `|B| > |A|` and more-limbs cases.
- `tf-psa-crypto/drivers/builtin/src/ecp.c`: internal use in elliptic-curve code.
