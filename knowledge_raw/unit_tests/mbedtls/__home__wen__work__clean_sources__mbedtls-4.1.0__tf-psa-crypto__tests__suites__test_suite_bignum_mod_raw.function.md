# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_bignum_mod_raw.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
{
    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *X = NULL;
    size_t A_limbs, N_limbs, X_limbs;
    mbedtls_mpi_uint *Y = NULL;
    mbedtls_mpi_uint *T = NULL;
    const mbedtls_mpi_uint *R2 = NULL;

    /* Legacy MPIs for computing R2 */
    mbedtls_mpi N_mpi;  /* gets set up manually, aliasing N, so no need to free */
    mbedtls_mpi R2_mpi;
    mbedtls_mpi_init(&R2_mpi);

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&N, &N_limbs, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&X, &X_limbs, input_X));
    TEST_CALLOC(Y, N_limbs);

    TEST_EQUAL(A_limbs, N_limbs);
    TEST_EQUAL(X_limbs, N_limbs);

    N_mpi.s = 1;
    N_mpi.p = N;
    N_mpi.n = N_limbs;
    TEST_EQUAL(0, mbedtls_mpi_core_get_mont_r2_unsafe(&R2_mpi, &N_mpi));
    TEST_EQUAL(0, mbedtls_mpi_grow(&R2_mpi, N_limbs));
    R2 = R2_mpi.p;

    size_t working_limbs = mbedtls_mpi_mod_raw_inv_prime_working_limbs(N_limbs);

    /* No point exactly duplicating the code in mbedtls_mpi_mod_raw_inv_prime_working_limbs()
     * to see if the output is correct, but we can check that it's in a
     * reasonable range.  The current calculation works out as
     * `1 + N_limbs * (welem + 4)`, where welem is the number of elements in
     * the window (1 << 1 up to 1 << 6).
     */
    size_t min_expected_working_limbs = 1 + N_limbs * 5;
    size_t max_expected_working_limbs = 1 + N_limbs * 68;
```

## Call pattern 2

```c
/* Check when output aliased to input */

    mbedtls_mpi_mod_raw_inv_prime(A, A, N, N_limbs, R2, T);

    TEST_EQUAL(0, memcmp(X, A, N_limbs * sizeof(mbedtls_mpi_uint)));

exit:
    mbedtls_free(T);
    mbedtls_free(A);
    mbedtls_free(N);
    mbedtls_free(X);
    mbedtls_free(Y);
    mbedtls_mpi_free(&R2_mpi);
    // R2 doesn't need to be freed as it is only aliasing R2_mpi
    // N_mpi doesn't need to be freed as it is only aliasing N
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_mod_raw_add(char *input_N,
                     char *input_A, char *input_B,
                     char *input_S)
{
    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *B = NULL;
    mbedtls_mpi_uint *S = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *X = NULL;
    size_t A_limbs, B_limbs, N_limbs, S_limbs;

    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_modulus_init(&m);

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&B, &B_limbs, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&N, &N_limbs, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&S, &S_limbs, input_S));

    /* Modulus gives the number of limbs; all inputs must have the same. */
    size_t limbs = N_limbs;
```

