# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_bignum_core.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_sub(char *input_A, char *input_B,
                  char *input_X, int carry)
{
    mbedtls_mpi A, B, X;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *b = NULL;
    mbedtls_mpi_uint *x = NULL; /* expected */
    mbedtls_mpi_uint *r = NULL; /* result */

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&X);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X, input_X));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, X.s);

    /* Get the number of limbs we will need */
    size_t limbs = MAX(A.n, B.n);
    size_t bytes = limbs * sizeof(mbedtls_mpi_uint);

    /* The result shouldn't have more limbs than the longest input */
    TEST_LE_U(X.n, limbs);

    /* Now let's get arrays of mbedtls_mpi_uints, rather than MPI structures */

    /* TEST_CALLOC() uses calloc() under the hood, so these do get zeroed */
    TEST_CALLOC(a, bytes);
    TEST_CALLOC(b, bytes);
    TEST_CALLOC(x, bytes);
    TEST_CALLOC(r, bytes);
```

## Call pattern 2

```c
/* BEGIN_CASE */
void mpi_core_sub(char *input_A, char *input_B,
                  char *input_X, int carry)
{
    mbedtls_mpi A, B, X;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *b = NULL;
    mbedtls_mpi_uint *x = NULL; /* expected */
    mbedtls_mpi_uint *r = NULL; /* result */

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&X);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X, input_X));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, X.s);

    /* Get the number of limbs we will need */
    size_t limbs = MAX(A.n, B.n);
    size_t bytes = limbs * sizeof(mbedtls_mpi_uint);

    /* The result shouldn't have more limbs than the longest input */
    TEST_LE_U(X.n, limbs);

    /* Now let's get arrays of mbedtls_mpi_uints, rather than MPI structures */

    /* TEST_CALLOC() uses calloc() under the hood, so these do get zeroed */
    TEST_CALLOC(a, bytes);
    TEST_CALLOC(b, bytes);
    TEST_CALLOC(x, bytes);
    TEST_CALLOC(r, bytes);

    /* Populate the arrays. As the mbedtls_mpi_uint[]s in mbedtls_mpis (and as
```

## Call pattern 3

```c
/* BEGIN_CASE */
void mpi_core_sub(char *input_A, char *input_B,
                  char *input_X, int carry)
{
    mbedtls_mpi A, B, X;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *b = NULL;
    mbedtls_mpi_uint *x = NULL; /* expected */
    mbedtls_mpi_uint *r = NULL; /* result */

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&X);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X, input_X));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, X.s);

    /* Get the number of limbs we will need */
    size_t limbs = MAX(A.n, B.n);
    size_t bytes = limbs * sizeof(mbedtls_mpi_uint);

    /* The result shouldn't have more limbs than the longest input */
    TEST_LE_U(X.n, limbs);

    /* Now let's get arrays of mbedtls_mpi_uints, rather than MPI structures */

    /* TEST_CALLOC() uses calloc() under the hood, so these do get zeroed */
    TEST_CALLOC(a, bytes);
    TEST_CALLOC(b, bytes);
    TEST_CALLOC(x, bytes);
    TEST_CALLOC(r, bytes);

    /* Populate the arrays. As the mbedtls_mpi_uint[]s in mbedtls_mpis (and as
     * processed by mbedtls_mpi_core_sub()) are little endian, we can just
```

## Call pattern 4

```c
TEST_CF_SECRET(r, bytes);
        TEST_EQUAL(carry, mbedtls_mpi_core_sub(r, r, r, limbs));
        TEST_CF_PUBLIC(r, bytes);
        TEST_MEMORY_COMPARE(r, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(b);
    mbedtls_free(x);
    mbedtls_free(r);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_mla(char *input_A, char *input_B, char *input_S,
                  char *input_X4, char *input_cy4,
                  char *input_X8, char *input_cy8)
{
    /* We are testing A += B * s; A, B are MPIs, s is a scalar.
     *
     * However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
```

## Call pattern 5

```c
TEST_EQUAL(carry, mbedtls_mpi_core_sub(r, r, r, limbs));
        TEST_CF_PUBLIC(r, bytes);
        TEST_MEMORY_COMPARE(r, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(b);
    mbedtls_free(x);
    mbedtls_free(r);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_mla(char *input_A, char *input_B, char *input_S,
                  char *input_X4, char *input_cy4,
                  char *input_X8, char *input_cy8)
{
    /* We are testing A += B * s; A, B are MPIs, s is a scalar.
     *
     * However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
```

## Call pattern 6

```c
TEST_CF_PUBLIC(r, bytes);
        TEST_MEMORY_COMPARE(r, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(b);
    mbedtls_free(x);
    mbedtls_free(r);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_mla(char *input_A, char *input_B, char *input_S,
                  char *input_X4, char *input_cy4,
                  char *input_X8, char *input_cy8)
{
    /* We are testing A += B * s; A, B are MPIs, s is a scalar.
     *
     * However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);
```

## Call pattern 7

```c
/* We are testing A += B * s; A, B are MPIs, s is a scalar.
     *
     * However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
```

## Call pattern 8

```c
*
     * However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
```

## Call pattern 9

```c
* However, we encode s as an MPI in the .data file as the test framework
     * currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, S.s);
```

## Call pattern 10

```c
* currently only supports `int`-typed scalars, and that doesn't cover the
     * full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, S.s);
    TEST_EQUAL(1, X->s);
```

## Call pattern 11

```c
* full range of `mbedtls_mpi_uint`.
     *
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, S.s);
    TEST_EQUAL(1, X->s);
    TEST_EQUAL(1, cy->s);
```

## Call pattern 12

```c
*
     * We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, S.s);
    TEST_EQUAL(1, X->s);
    TEST_EQUAL(1, cy->s);
```

## Call pattern 13

```c
* We also have the different results for sizeof(mbedtls_mpi_uint) == 4 or 8.
     */
    mbedtls_mpi A, B, S, X4, X8, cy4, cy8;
    mbedtls_mpi_uint *a = NULL;
    mbedtls_mpi_uint *x = NULL;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&X4);
    mbedtls_mpi_init(&X8);
    mbedtls_mpi_init(&cy4);
    mbedtls_mpi_init(&cy8);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&S, input_S));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy4, input_cy4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&cy8, input_cy8));

    /* The MPI encoding of scalar s must be only 1 limb */
    TEST_EQUAL(1, S.n);

    /* We only need to work with X4 or X8, and cy4 or cy8, depending on sizeof(mbedtls_mpi_uint) */
    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;
    mbedtls_mpi *cy = (sizeof(mbedtls_mpi_uint) == 4) ? &cy4 : &cy8;

    /* The carry should only have one limb */
    TEST_EQUAL(1, cy->n);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, S.s);
    TEST_EQUAL(1, X->s);
    TEST_EQUAL(1, cy->s);

    /* Get the (max) number of limbs we will need */
```

## Call pattern 14

```c
TEST_EQUAL(mbedtls_mpi_core_mla(a, limbs, a, limbs, *S.p), *cy->p);

        TEST_CF_PUBLIC(a, bytes);
        TEST_CF_PUBLIC(S.p, sizeof(mbedtls_mpi_uint));

        TEST_MEMORY_COMPARE(a, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
```

## Call pattern 15

```c
TEST_CF_PUBLIC(a, bytes);
        TEST_CF_PUBLIC(S.p, sizeof(mbedtls_mpi_uint));

        TEST_MEMORY_COMPARE(a, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);
```

## Call pattern 16

```c
TEST_CF_PUBLIC(S.p, sizeof(mbedtls_mpi_uint));

        TEST_MEMORY_COMPARE(a, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
```

## Call pattern 17

```c
TEST_MEMORY_COMPARE(a, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
```

## Call pattern 18

```c
TEST_MEMORY_COMPARE(a, bytes, x, bytes);
    }

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);
```

## Call pattern 19

```c
}

exit:
    mbedtls_free(a);
    mbedtls_free(x);

    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);
```

## Call pattern 20

```c
mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);

    /* mbedtls_mpi_core_montmul_init() only returns a result, no error possible */
    mbedtls_mpi_uint result = mbedtls_mpi_core_montmul_init(N.p);

    /* Check we got the correct result */
    TEST_EQUAL(result, mm.p[0]);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&mm);
}
```

## Call pattern 21

```c
mbedtls_mpi_free(&cy4);
    mbedtls_mpi_free(&cy8);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_montg_init(char *input_N, char *input_mm)
{
    mbedtls_mpi N, mm;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&mm);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&mm, input_mm));

    /* The MPI encoding of mm should be 1 limb (sizeof(mbedtls_mpi_uint) == 8) or
     * 2 limbs (sizeof(mbedtls_mpi_uint) == 4).
     *
     * The data file contains the expected result for sizeof(mbedtls_mpi_uint) == 8;
     * for sizeof(mbedtls_mpi_uint) == 4 it's just the LSW of this.
     */
    TEST_ASSERT(mm.n == 1  || mm.n == 2);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);

    /* mbedtls_mpi_core_montmul_init() only returns a result, no error possible */
    mbedtls_mpi_uint result = mbedtls_mpi_core_montmul_init(N.p);

    /* Check we got the correct result */
    TEST_EQUAL(result, mm.p[0]);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&mm);
}
/* END_CASE */
```

## Call pattern 22

```c
/* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);

    /* mbedtls_mpi_core_montmul_init() only returns a result, no error possible */
    mbedtls_mpi_uint result = mbedtls_mpi_core_montmul_init(N.p);

    /* Check we got the correct result */
    TEST_EQUAL(result, mm.p[0]);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&mm);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_montmul(int limbs_AN4, int limbs_B4,
                      int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
```

## Call pattern 23

```c
/* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, mm.s);

    /* mbedtls_mpi_core_montmul_init() only returns a result, no error possible */
    mbedtls_mpi_uint result = mbedtls_mpi_core_montmul_init(N.p);

    /* Check we got the correct result */
    TEST_EQUAL(result, mm.p[0]);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&mm);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_montmul(int limbs_AN4, int limbs_B4,
                      int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));
```

## Call pattern 24

```c
/* BEGIN_CASE */
void mpi_core_montmul(int limbs_AN4, int limbs_B4,
                      int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
```

## Call pattern 25

```c
/* BEGIN_CASE */
void mpi_core_montmul(int limbs_AN4, int limbs_B4,
                      int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);
```

## Call pattern 26

```c
void mpi_core_montmul(int limbs_AN4, int limbs_B4,
                      int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);
```

## Call pattern 27

```c
int limbs_AN8, int limbs_B8,
                      char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);

    TEST_EQUAL(0, mbedtls_mpi_grow(&A, limbs_AN));
```

## Call pattern 28

```c
char *input_A,
                      char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);

    TEST_EQUAL(0, mbedtls_mpi_grow(&A, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(&N, limbs_AN));
```

## Call pattern 29

```c
char *input_B,
                      char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);

    TEST_EQUAL(0, mbedtls_mpi_grow(&A, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(&N, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(X, limbs_AN));
```

## Call pattern 30

```c
char *input_N,
                      char *input_X4,
                      char *input_X8)
{
    mbedtls_mpi A, B, N, X4, X8, T, R;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&X4);      /* expected result, sizeof(mbedtls_mpi_uint) == 4 */
    mbedtls_mpi_init(&X8);      /* expected result, sizeof(mbedtls_mpi_uint) == 8 */
    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&R);       /* for the result */

    TEST_EQUAL(0, mbedtls_test_read_mpi(&A, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&B, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X4, input_X4));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&X8, input_X8));

    mbedtls_mpi *X = (sizeof(mbedtls_mpi_uint) == 4) ? &X4 : &X8;

    int limbs_AN = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_AN4 : limbs_AN8;
    int limbs_B = (sizeof(mbedtls_mpi_uint) == 4) ? limbs_B4 : limbs_B8;

    TEST_LE_U(A.n, (size_t) limbs_AN);
    TEST_LE_U(X->n, (size_t) limbs_AN);
    TEST_LE_U(B.n, (size_t) limbs_B);
    TEST_LE_U(limbs_B, limbs_AN);

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, A.s);
    TEST_EQUAL(1, B.s);
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, X->s);

    TEST_EQUAL(0, mbedtls_mpi_grow(&A, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(&N, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(X, limbs_AN));
    TEST_EQUAL(0, mbedtls_mpi_grow(&B, limbs_B));
```

## Call pattern 31

```c
TEST_CF_SECRET(N.p, N.n * sizeof(mbedtls_mpi_uint));
        TEST_CF_SECRET(A.p, A.n * sizeof(mbedtls_mpi_uint));
        TEST_CF_SECRET(B.p, B.n * sizeof(mbedtls_mpi_uint));

        mbedtls_mpi_core_montmul(B.p, A.p, B.p, B.n, N.p, N.n, mm, T.p);

        TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;
```

## Call pattern 32

```c
TEST_CF_SECRET(A.p, A.n * sizeof(mbedtls_mpi_uint));
        TEST_CF_SECRET(B.p, B.n * sizeof(mbedtls_mpi_uint));

        mbedtls_mpi_core_montmul(B.p, A.p, B.p, B.n, N.p, N.n, mm, T.p);

        TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
```

## Call pattern 33

```c
TEST_CF_SECRET(B.p, B.n * sizeof(mbedtls_mpi_uint));

        mbedtls_mpi_core_montmul(B.p, A.p, B.p, B.n, N.p, N.n, mm, T.p);

        TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
```

## Call pattern 34

```c
mbedtls_mpi_core_montmul(B.p, A.p, B.p, B.n, N.p, N.n, mm, T.p);

        TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
```

## Call pattern 35

```c
mbedtls_mpi_core_montmul(B.p, A.p, B.p, B.n, N.p, N.n, mm, T.p);

        TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
```

## Call pattern 36

```c
TEST_CF_PUBLIC(B.p, B.n * sizeof(mbedtls_mpi_uint));
        TEST_MEMORY_COMPARE(B.p, bytes, X->p, bytes);
    }

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
/* END_CASE */
```

## Call pattern 37

```c
mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;
```

## Call pattern 38

```c
mbedtls_mpi_free(&X4);
    mbedtls_mpi_free(&X8);
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&R);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe_neg()
{
    mbedtls_mpi N, RR;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    const char *n = "7ffffffffffffff1";

    /* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
```

## Call pattern 39

```c
/* Test for zero divisor */
    TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
    char *input_rr = (sizeof(mbedtls_mpi_uint) == 4) ? input_RR_X4 : input_RR_X8;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&RR_REF);

    /* Read inputs */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&RR_REF, input_rr));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, RR_REF.s);

    /* Test valid input */
```

## Call pattern 40

```c
TEST_EQUAL(MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test for negative input */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, n));
    N.s = -1;
    TEST_EQUAL(MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
               mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
    N.s = 1;

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
    char *input_rr = (sizeof(mbedtls_mpi_uint) == 4) ? input_RR_X4 : input_RR_X8;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&RR_REF);

    /* Read inputs */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&RR_REF, input_rr));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, RR_REF.s);

    /* Test valid input */
    TEST_EQUAL(0, mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));
```

## Call pattern 41

```c
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
    char *input_rr = (sizeof(mbedtls_mpi_uint) == 4) ? input_RR_X4 : input_RR_X8;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&RR_REF);

    /* Read inputs */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&RR_REF, input_rr));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, RR_REF.s);

    /* Test valid input */
    TEST_EQUAL(0, mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test that the moduli is odd */
    TEST_EQUAL(N.p[0] ^ 1, N.p[0] - 1);

    /* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
```

## Call pattern 42

```c
/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
    char *input_rr = (sizeof(mbedtls_mpi_uint) == 4) ? input_RR_X4 : input_RR_X8;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&RR_REF);

    /* Read inputs */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&RR_REF, input_rr));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, RR_REF.s);

    /* Test valid input */
    TEST_EQUAL(0, mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test that the moduli is odd */
    TEST_EQUAL(N.p[0] ^ 1, N.p[0] - 1);

    /* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
    mbedtls_mpi_free(&N);
```

## Call pattern 43

```c
/* BEGIN_CASE */
void mpi_core_get_mont_r2_unsafe(char *input_N,
                                 char *input_RR_X4,
                                 char *input_RR_X8)
{
    mbedtls_mpi N, RR, RR_REF;

    /* Select the appropriate output */
    char *input_rr = (sizeof(mbedtls_mpi_uint) == 4) ? input_RR_X4 : input_RR_X8;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&RR_REF);

    /* Read inputs */
    TEST_EQUAL(0, mbedtls_test_read_mpi(&N, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi(&RR_REF, input_rr));

    /* All of the inputs are +ve (or zero) */
    TEST_EQUAL(1, N.s);
    TEST_EQUAL(1, RR_REF.s);

    /* Test valid input */
    TEST_EQUAL(0, mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N));

    /* Test that the moduli is odd */
    TEST_EQUAL(N.p[0] ^ 1, N.p[0] - 1);

    /* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
```

## Call pattern 44

```c
TEST_EQUAL(N.p[0] ^ 1, N.p[0] - 1);

    /* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
    mbedtls_mpi_free(&RR_REF);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS */
void mpi_core_ct_uint_table_lookup(int bitlen, int window_size)
{
    size_t limbs = BITS_TO_LIMBS(bitlen);
    size_t count = ((size_t) 1) << window_size;

    mbedtls_mpi_uint *table = NULL;
    mbedtls_mpi_uint *dest = NULL;

    TEST_CALLOC(table, limbs * count);
    TEST_CALLOC(dest, limbs);

    /*
     * Fill the table with a unique counter so that differences are easily
     * detected. (And have their relationship to the index relatively non-trivial just
     * to be sure.)
     */
    for (size_t i = 0; i < count * limbs; i++) {
        table[i] = ~i - 1;
    }

    for (size_t i = 0; i < count; i++) {
```

## Call pattern 45

```c
/* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
    mbedtls_mpi_free(&RR_REF);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS */
void mpi_core_ct_uint_table_lookup(int bitlen, int window_size)
{
    size_t limbs = BITS_TO_LIMBS(bitlen);
    size_t count = ((size_t) 1) << window_size;

    mbedtls_mpi_uint *table = NULL;
    mbedtls_mpi_uint *dest = NULL;

    TEST_CALLOC(table, limbs * count);
    TEST_CALLOC(dest, limbs);

    /*
     * Fill the table with a unique counter so that differences are easily
     * detected. (And have their relationship to the index relatively non-trivial just
     * to be sure.)
     */
    for (size_t i = 0; i < count * limbs; i++) {
        table[i] = ~i - 1;
    }

    for (size_t i = 0; i < count; i++) {
        mbedtls_mpi_uint *current = table + i * limbs;
```

## Call pattern 46

```c
/* Output is +ve (or zero) */
    TEST_EQUAL(1, RR_REF.s);

    /* rr is updated to a valid pointer */
    TEST_ASSERT(RR.p != NULL);

    /* Calculated rr matches expected value */
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&RR, &RR_REF) == 0);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
    mbedtls_mpi_free(&RR_REF);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS */
void mpi_core_ct_uint_table_lookup(int bitlen, int window_size)
{
    size_t limbs = BITS_TO_LIMBS(bitlen);
    size_t count = ((size_t) 1) << window_size;

    mbedtls_mpi_uint *table = NULL;
    mbedtls_mpi_uint *dest = NULL;

    TEST_CALLOC(table, limbs * count);
    TEST_CALLOC(dest, limbs);

    /*
     * Fill the table with a unique counter so that differences are easily
     * detected. (And have their relationship to the index relatively non-trivial just
     * to be sure.)
     */
    for (size_t i = 0; i < count * limbs; i++) {
        table[i] = ~i - 1;
    }

    for (size_t i = 0; i < count; i++) {
        mbedtls_mpi_uint *current = table + i * limbs;
        memset(dest, 0x00, limbs * sizeof(*dest));
```

## Call pattern 47

```c
{
    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *A_copy = NULL;
    mbedtls_mpi_uint *E = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *X = NULL;
    size_t A_limbs, E_limbs, N_limbs, X_limbs;
    const mbedtls_mpi_uint *R2 = NULL;
    mbedtls_mpi_uint *Y = NULL;
    mbedtls_mpi_uint *T = NULL;
    /* Legacy MPIs for computing R2 */
    mbedtls_mpi N_mpi;
    mbedtls_mpi_init(&N_mpi);
    mbedtls_mpi R2_mpi;
    mbedtls_mpi_init(&R2_mpi);

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&E, &E_limbs, input_E));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&N, &N_limbs, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&X, &X_limbs, input_X));
    TEST_CALLOC(Y, N_limbs);

    TEST_EQUAL(A_limbs, N_limbs);
    TEST_EQUAL(X_limbs, N_limbs);

    TEST_EQUAL(0, mbedtls_mpi_grow(&N_mpi, N_limbs));
    memcpy(N_mpi.p, N, N_limbs * sizeof(*N));
    N_mpi.n = N_limbs;
    TEST_EQUAL(0,
               mbedtls_mpi_core_get_mont_r2_unsafe(&R2_mpi, &N_mpi));
    TEST_EQUAL(0, mbedtls_mpi_grow(&R2_mpi, N_limbs));
    R2 = R2_mpi.p;

    size_t working_limbs = mbedtls_mpi_core_exp_mod_working_limbs(N_limbs,
                                                                  E_limbs);

    /* No point exactly duplicating the code in mbedtls_mpi_core_exp_mod_working_limbs()
     * to see if the output is correct, but we can check that it's in a
     * reasonable range.  The current calculation works out as
     * `1 + N_limbs * (welem + 3)`, where welem is the number of elements in
```

## Call pattern 48

```c
mbedtls_mpi_uint *A_copy = NULL;
    mbedtls_mpi_uint *E = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *X = NULL;
    size_t A_limbs, E_limbs, N_limbs, X_limbs;
    const mbedtls_mpi_uint *R2 = NULL;
    mbedtls_mpi_uint *Y = NULL;
    mbedtls_mpi_uint *T = NULL;
    /* Legacy MPIs for computing R2 */
    mbedtls_mpi N_mpi;
    mbedtls_mpi_init(&N_mpi);
    mbedtls_mpi R2_mpi;
    mbedtls_mpi_init(&R2_mpi);

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&E, &E_limbs, input_E));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&N, &N_limbs, input_N));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&X, &X_limbs, input_X));
    TEST_CALLOC(Y, N_limbs);

    TEST_EQUAL(A_limbs, N_limbs);
    TEST_EQUAL(X_limbs, N_limbs);

    TEST_EQUAL(0, mbedtls_mpi_grow(&N_mpi, N_limbs));
    memcpy(N_mpi.p, N, N_limbs * sizeof(*N));
    N_mpi.n = N_limbs;
    TEST_EQUAL(0,
               mbedtls_mpi_core_get_mont_r2_unsafe(&R2_mpi, &N_mpi));
    TEST_EQUAL(0, mbedtls_mpi_grow(&R2_mpi, N_limbs));
    R2 = R2_mpi.p;

    size_t working_limbs = mbedtls_mpi_core_exp_mod_working_limbs(N_limbs,
                                                                  E_limbs);

    /* No point exactly duplicating the code in mbedtls_mpi_core_exp_mod_working_limbs()
     * to see if the output is correct, but we can check that it's in a
     * reasonable range.  The current calculation works out as
     * `1 + N_limbs * (welem + 3)`, where welem is the number of elements in
     * the window (1 << 1 up to 1 << 6).
     */
```

## Call pattern 49

```c
mbedtls_mpi_core_exp_mod_unsafe(A, A, N, N_limbs, E, E_limbs, R2, T);

    TEST_EQUAL(0, memcmp(X, A, N_limbs * sizeof(mbedtls_mpi_uint)));

exit:
    mbedtls_free(T);
    mbedtls_free(A);
    mbedtls_free(A_copy);
    mbedtls_free(E);
    mbedtls_free(N);
    mbedtls_free(X);
    mbedtls_free(Y);
    mbedtls_mpi_free(&N_mpi);
    mbedtls_mpi_free(&R2_mpi);
    // R2 doesn't need to be freed as it is only aliasing R2_mpi
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_sub_int(char *input_A, char *input_B,
                      char *input_X, int borrow)
{
    /* We are testing A - b, where A is an MPI and b is a scalar, expecting
     * result X with borrow borrow.  However, for ease of handling we encode b
     * as a 1-limb MPI (B) in the .data file. */

    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *B = NULL;
    mbedtls_mpi_uint *X = NULL;
    mbedtls_mpi_uint *R = NULL;
    size_t A_limbs, B_limbs, X_limbs;

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&B, &B_limbs, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&X, &X_limbs, input_X));

    /* The MPI encoding of scalar b must be only 1 limb */
    TEST_EQUAL(B_limbs, 1);

    /* The subtraction is fixed-width, so A and X must have the same number of limbs */
```

## Call pattern 50

```c
TEST_EQUAL(0, memcmp(X, A, N_limbs * sizeof(mbedtls_mpi_uint)));

exit:
    mbedtls_free(T);
    mbedtls_free(A);
    mbedtls_free(A_copy);
    mbedtls_free(E);
    mbedtls_free(N);
    mbedtls_free(X);
    mbedtls_free(Y);
    mbedtls_mpi_free(&N_mpi);
    mbedtls_mpi_free(&R2_mpi);
    // R2 doesn't need to be freed as it is only aliasing R2_mpi
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_core_sub_int(char *input_A, char *input_B,
                      char *input_X, int borrow)
{
    /* We are testing A - b, where A is an MPI and b is a scalar, expecting
     * result X with borrow borrow.  However, for ease of handling we encode b
     * as a 1-limb MPI (B) in the .data file. */

    mbedtls_mpi_uint *A = NULL;
    mbedtls_mpi_uint *B = NULL;
    mbedtls_mpi_uint *X = NULL;
    mbedtls_mpi_uint *R = NULL;
    size_t A_limbs, B_limbs, X_limbs;

    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&A, &A_limbs, input_A));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&B, &B_limbs, input_B));
    TEST_EQUAL(0, mbedtls_test_read_mpi_core(&X, &X_limbs, input_X));

    /* The MPI encoding of scalar b must be only 1 limb */
    TEST_EQUAL(B_limbs, 1);

    /* The subtraction is fixed-width, so A and X must have the same number of limbs */
    TEST_EQUAL(A_limbs, X_limbs);
```

