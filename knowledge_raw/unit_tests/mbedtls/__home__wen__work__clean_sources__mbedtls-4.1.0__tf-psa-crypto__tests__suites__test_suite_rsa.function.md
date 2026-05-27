# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_rsa.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
#include "rsa_internal.h"
#include "test/bignum_codepath_check.h"

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_BIGNUM_C)

static int mbedtls_rsa_test_fill_context(mbedtls_rsa_context *rsa,
                                         data_t *N_data, data_t *E_data,
                                         data_t *D_data, data_t *P_data,
                                         data_t *Q_data)
{
    int ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mbedtls_mpi_init(&rsa->N); mbedtls_mpi_init(&rsa->P); mbedtls_mpi_init(&rsa->Q);
    mbedtls_mpi_init(&rsa->E); mbedtls_mpi_init(&rsa->D);

    if (P_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->P, P_data->x, P_data->len));
    }
    if (Q_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->Q, Q_data->x, Q_data->len));
    }
    if (N_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->N, N_data->x, N_data->len));
        rsa->len = mbedtls_mpi_size(&rsa->N);
    }
    if (E_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->E, E_data->x, E_data->len));
    }
    if (D_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->D, D_data->x, D_data->len));
    }

    if (mbedtls_mpi_size(&rsa->D) == 0) {
        if ((mbedtls_mpi_size(&rsa->P) != 0) &&
            (mbedtls_mpi_size(&rsa->Q) != 0) &&
            (mbedtls_mpi_size(&rsa->E) != 0)) {
            MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_private_exponent(&rsa->P, &rsa->Q, &rsa->E,
                                                                &rsa->D));
        }
    }
```

## Call pattern 2

```c
#include "test/bignum_codepath_check.h"

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_BIGNUM_C)

static int mbedtls_rsa_test_fill_context(mbedtls_rsa_context *rsa,
                                         data_t *N_data, data_t *E_data,
                                         data_t *D_data, data_t *P_data,
                                         data_t *Q_data)
{
    int ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mbedtls_mpi_init(&rsa->N); mbedtls_mpi_init(&rsa->P); mbedtls_mpi_init(&rsa->Q);
    mbedtls_mpi_init(&rsa->E); mbedtls_mpi_init(&rsa->D);

    if (P_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->P, P_data->x, P_data->len));
    }
    if (Q_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->Q, Q_data->x, Q_data->len));
    }
    if (N_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->N, N_data->x, N_data->len));
        rsa->len = mbedtls_mpi_size(&rsa->N);
    }
    if (E_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->E, E_data->x, E_data->len));
    }
    if (D_data != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&rsa->D, D_data->x, D_data->len));
    }

    if (mbedtls_mpi_size(&rsa->D) == 0) {
        if ((mbedtls_mpi_size(&rsa->P) != 0) &&
            (mbedtls_mpi_size(&rsa->Q) != 0) &&
            (mbedtls_mpi_size(&rsa->E) != 0)) {
            MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_private_exponent(&rsa->P, &rsa->Q, &rsa->E,
                                                                &rsa->D));
        }
    }
```

## Call pattern 3

```c
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_deduce_private_exponent(char *input_P,
                                         char *input_Q,
                                         char *input_E,
                                         char *output_D,
                                         int corrupt, int result)
{
    mbedtls_mpi P, Q, D, Dp, E, R, Rp;

    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&Dp);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&R); mbedtls_mpi_init(&Rp);

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Dp, output_D) == 0);

    if (corrupt) {
        /* Make E even */
        TEST_ASSERT(mbedtls_mpi_set_bit(&E, 0, 0) == 0);
    }

    /* Try to deduce D from N, P, Q, E. */
    TEST_ASSERT(mbedtls_rsa_deduce_private_exponent(&P, &Q,
                                                    &E, &D) == result);

    if (!corrupt) {
        /*
         * Check that D and Dp agree modulo LCM(P-1, Q-1).
         */

        /* Replace P,Q by P-1, Q-1 */
        TEST_ASSERT(mbedtls_mpi_sub_int(&P, &P, 1) == 0);
        TEST_ASSERT(mbedtls_mpi_sub_int(&Q, &Q, 1) == 0);
```

## Call pattern 4

```c
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_deduce_private_exponent(char *input_P,
                                         char *input_Q,
                                         char *input_E,
                                         char *output_D,
                                         int corrupt, int result)
{
    mbedtls_mpi P, Q, D, Dp, E, R, Rp;

    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&Dp);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&R); mbedtls_mpi_init(&Rp);

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Dp, output_D) == 0);

    if (corrupt) {
        /* Make E even */
        TEST_ASSERT(mbedtls_mpi_set_bit(&E, 0, 0) == 0);
    }

    /* Try to deduce D from N, P, Q, E. */
    TEST_ASSERT(mbedtls_rsa_deduce_private_exponent(&P, &Q,
                                                    &E, &D) == result);

    if (!corrupt) {
        /*
         * Check that D and Dp agree modulo LCM(P-1, Q-1).
         */

        /* Replace P,Q by P-1, Q-1 */
        TEST_ASSERT(mbedtls_mpi_sub_int(&P, &P, 1) == 0);
        TEST_ASSERT(mbedtls_mpi_sub_int(&Q, &Q, 1) == 0);

        /* Check D == Dp modulo P-1 */
```

## Call pattern 5

```c
/* BEGIN_CASE */
void mbedtls_rsa_deduce_private_exponent(char *input_P,
                                         char *input_Q,
                                         char *input_E,
                                         char *output_D,
                                         int corrupt, int result)
{
    mbedtls_mpi P, Q, D, Dp, E, R, Rp;

    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&Dp);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&R); mbedtls_mpi_init(&Rp);

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Dp, output_D) == 0);

    if (corrupt) {
        /* Make E even */
        TEST_ASSERT(mbedtls_mpi_set_bit(&E, 0, 0) == 0);
    }

    /* Try to deduce D from N, P, Q, E. */
    TEST_ASSERT(mbedtls_rsa_deduce_private_exponent(&P, &Q,
                                                    &E, &D) == result);

    if (!corrupt) {
        /*
         * Check that D and Dp agree modulo LCM(P-1, Q-1).
         */

        /* Replace P,Q by P-1, Q-1 */
        TEST_ASSERT(mbedtls_mpi_sub_int(&P, &P, 1) == 0);
        TEST_ASSERT(mbedtls_mpi_sub_int(&Q, &Q, 1) == 0);

        /* Check D == Dp modulo P-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &P) == 0);
```

## Call pattern 6

```c
/* BEGIN_CASE */
void mbedtls_rsa_deduce_private_exponent(char *input_P,
                                         char *input_Q,
                                         char *input_E,
                                         char *output_D,
                                         int corrupt, int result)
{
    mbedtls_mpi P, Q, D, Dp, E, R, Rp;

    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&Dp);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&R); mbedtls_mpi_init(&Rp);

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Dp, output_D) == 0);

    if (corrupt) {
        /* Make E even */
        TEST_ASSERT(mbedtls_mpi_set_bit(&E, 0, 0) == 0);
    }

    /* Try to deduce D from N, P, Q, E. */
    TEST_ASSERT(mbedtls_rsa_deduce_private_exponent(&P, &Q,
                                                    &E, &D) == result);

    if (!corrupt) {
        /*
         * Check that D and Dp agree modulo LCM(P-1, Q-1).
         */

        /* Replace P,Q by P-1, Q-1 */
        TEST_ASSERT(mbedtls_mpi_sub_int(&P, &P, 1) == 0);
        TEST_ASSERT(mbedtls_mpi_sub_int(&Q, &Q, 1) == 0);

        /* Check D == Dp modulo P-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &P) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &P) == 0);
```

## Call pattern 7

```c
TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &P) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &P) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);

        /* Check D == Dp modulo Q-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);
    }

exit:

    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&Dp);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&R); mbedtls_mpi_free(&Rp);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_validate_params(char *input_N,
                                 char *input_P,
                                 char *input_Q,
                                 char *input_D,
                                 char *input_E,
                                 int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);
```

## Call pattern 8

```c
TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &P) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);

        /* Check D == Dp modulo Q-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);
    }

exit:

    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&Dp);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&R); mbedtls_mpi_free(&Rp);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_validate_params(char *input_N,
                                 char *input_P,
                                 char *input_Q,
                                 char *input_D,
                                 char *input_E,
                                 int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
```

## Call pattern 9

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);

        /* Check D == Dp modulo Q-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);
    }

exit:

    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&Dp);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&R); mbedtls_mpi_free(&Rp);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_validate_params(char *input_N,
                                 char *input_P,
                                 char *input_Q,
                                 char *input_D,
                                 char *input_E,
                                 int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
        TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
```

## Call pattern 10

```c
/* Check D == Dp modulo Q-1 */
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&R,  &D,  &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_mod_mpi(&Rp, &Dp, &Q) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R,  &Rp)     == 0);
    }

exit:

    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&Dp);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&R); mbedtls_mpi_free(&Rp);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_rsa_validate_params(char *input_N,
                                 char *input_P,
                                 char *input_Q,
                                 char *input_D,
                                 char *input_E,
                                 int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
        TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    }
```

## Call pattern 11

```c
char *input_E,
                                 int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
        TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    }

    if (have_P) {
        TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    }

    if (have_Q) {
        TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    }

    if (have_D) {
        TEST_ASSERT(mbedtls_test_read_mpi(&D, input_D) == 0);
    }

    if (have_E) {
        TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    }

    /* This test uses an insecure RNG, suitable only for testing.
     * In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
```

## Call pattern 12

```c
int prng, int result)
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
        TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    }

    if (have_P) {
        TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    }

    if (have_Q) {
        TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    }

    if (have_D) {
        TEST_ASSERT(mbedtls_test_read_mpi(&D, input_D) == 0);
    }

    if (have_E) {
        TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    }

    /* This test uses an insecure RNG, suitable only for testing.
     * In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
                                            have_Q ? &Q : NULL,
```

## Call pattern 13

```c
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = (strlen(input_N) > 0);
    const int have_P = (strlen(input_P) > 0);
    const int have_Q = (strlen(input_Q) > 0);
    const int have_D = (strlen(input_D) > 0);
    const int have_E = (strlen(input_E) > 0);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);

    if (have_N) {
        TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    }

    if (have_P) {
        TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    }

    if (have_Q) {
        TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    }

    if (have_D) {
        TEST_ASSERT(mbedtls_test_read_mpi(&D, input_D) == 0);
    }

    if (have_E) {
        TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    }

    /* This test uses an insecure RNG, suitable only for testing.
     * In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
                                            have_Q ? &Q : NULL,
                                            have_D ? &D : NULL,
```

## Call pattern 14

```c
/* This test uses an insecure RNG, suitable only for testing.
     * In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
                                            have_Q ? &Q : NULL,
                                            have_D ? &D : NULL,
                                            have_E ? &E : NULL,
                                            prng ? mbedtls_test_rnd_std_rand : NULL,
                                            prng ? NULL : NULL) == result);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_pkcs1_key(int is_public, data_t *input, int exp_ret_val)
{
    mbedtls_rsa_context rsa_ctx;

    mbedtls_rsa_init(&rsa_ctx);

    if (is_public) {
        TEST_EQUAL(mbedtls_rsa_parse_pubkey(&rsa_ctx, input->x, input->len), exp_ret_val);
    } else {
        TEST_EQUAL(mbedtls_rsa_parse_key(&rsa_ctx, input->x, input->len), exp_ret_val);
    }

exit:
    mbedtls_rsa_free(&rsa_ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_write_pkcs1_key(int is_public, data_t *input)
{
    mbedtls_rsa_context rsa_ctx;
```

## Call pattern 15

```c
/* This test uses an insecure RNG, suitable only for testing.
     * In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
                                            have_Q ? &Q : NULL,
                                            have_D ? &D : NULL,
                                            have_E ? &E : NULL,
                                            prng ? mbedtls_test_rnd_std_rand : NULL,
                                            prng ? NULL : NULL) == result);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_pkcs1_key(int is_public, data_t *input, int exp_ret_val)
{
    mbedtls_rsa_context rsa_ctx;

    mbedtls_rsa_init(&rsa_ctx);

    if (is_public) {
        TEST_EQUAL(mbedtls_rsa_parse_pubkey(&rsa_ctx, input->x, input->len), exp_ret_val);
    } else {
        TEST_EQUAL(mbedtls_rsa_parse_key(&rsa_ctx, input->x, input->len), exp_ret_val);
    }

exit:
    mbedtls_rsa_free(&rsa_ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_write_pkcs1_key(int is_public, data_t *input)
{
    mbedtls_rsa_context rsa_ctx;
    unsigned char *output_buf = NULL;
```

## Call pattern 16

```c
* In production, always use a cryptographically strong RNG! */
    TEST_ASSERT(mbedtls_rsa_validate_params(have_N ? &N : NULL,
                                            have_P ? &P : NULL,
                                            have_Q ? &Q : NULL,
                                            have_D ? &D : NULL,
                                            have_E ? &E : NULL,
                                            prng ? mbedtls_test_rnd_std_rand : NULL,
                                            prng ? NULL : NULL) == result);

exit:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_pkcs1_key(int is_public, data_t *input, int exp_ret_val)
{
    mbedtls_rsa_context rsa_ctx;

    mbedtls_rsa_init(&rsa_ctx);

    if (is_public) {
        TEST_EQUAL(mbedtls_rsa_parse_pubkey(&rsa_ctx, input->x, input->len), exp_ret_val);
    } else {
        TEST_EQUAL(mbedtls_rsa_parse_key(&rsa_ctx, input->x, input->len), exp_ret_val);
    }

exit:
    mbedtls_rsa_free(&rsa_ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void rsa_parse_write_pkcs1_key(int is_public, data_t *input)
{
    mbedtls_rsa_context rsa_ctx;
    unsigned char *output_buf = NULL;
    unsigned char *output_end, *output_p;
```

