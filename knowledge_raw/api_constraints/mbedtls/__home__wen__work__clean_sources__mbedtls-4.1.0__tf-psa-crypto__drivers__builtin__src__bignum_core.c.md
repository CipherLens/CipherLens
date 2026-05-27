# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/bignum_core.c
Knowledge type: api_constraints

## Snippet 1

```c
(unsigned char *) T,
                         NULL,
                         AN_limbs * sizeof(mbedtls_mpi_uint));
}

int mbedtls_mpi_core_get_mont_r2_unsafe(mbedtls_mpi *X,
                                        const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(X, N->n * 2 * biL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(X, X, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shrink(X, N->n));

cleanup:
    return ret;
}

MBEDTLS_STATIC_TESTABLE
void mbedtls_mpi_core_ct_uint_table_lookup(mbedtls_mpi_uint *dest,
                                           const mbedtls_mpi_uint *table,
                                           size_t limbs,
                                           size_t count,
                                           size_t index)
{
    for (size_t i = 0; i < count; i++, table += limbs) {
        mbedtls_ct_condition_t assign = mbedtls_ct_uint_eq(i, index);
```

