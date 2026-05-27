# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_bignum_random.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
mbedtls_free(result);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_legacy_random_values(int min, char *max_hex)
{
    /* Same RNG as in mpi_core_random_basic */
    mbedtls_test_rnd_pseudo_info rnd_core = rnd_pseudo_seed;
    mbedtls_test_rnd_pseudo_info rnd_legacy;
    memcpy(&rnd_legacy, &rnd_core, sizeof(rnd_core));
    mbedtls_mpi max_legacy;
    mbedtls_mpi_init(&max_legacy);
    mbedtls_mpi_uint *R_core = NULL;
    mbedtls_mpi R_legacy;
    mbedtls_mpi_init(&R_legacy);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&max_legacy, max_hex));
    size_t limbs = max_legacy.n;
    TEST_CALLOC(R_core, limbs);

    /* Call the legacy function and the core function with the same random
     * stream. */
    int core_ret = mbedtls_mpi_core_random(R_core, min, max_legacy.p, limbs,
                                           mbedtls_test_rnd_pseudo_rand,
                                           &rnd_core);
    int legacy_ret = mbedtls_mpi_random(&R_legacy, min, &max_legacy,
                                        mbedtls_test_rnd_pseudo_rand,
                                        &rnd_legacy);

    /* They must return the same status, and, on success, output the
     * same number, with the same limb count. */
    TEST_EQUAL(core_ret, legacy_ret);
    if (core_ret == 0) {
        TEST_MEMORY_COMPARE(R_core, limbs * ciL,
                            R_legacy.p, R_legacy.n * ciL);
    }

    /* Also check that they have consumed the RNG in the same way. */
    /* This may theoretically fail on rare platforms with padding in
```

## Call pattern 2

```c
/* BEGIN_CASE */
void mpi_legacy_random_values(int min, char *max_hex)
{
    /* Same RNG as in mpi_core_random_basic */
    mbedtls_test_rnd_pseudo_info rnd_core = rnd_pseudo_seed;
    mbedtls_test_rnd_pseudo_info rnd_legacy;
    memcpy(&rnd_legacy, &rnd_core, sizeof(rnd_core));
    mbedtls_mpi max_legacy;
    mbedtls_mpi_init(&max_legacy);
    mbedtls_mpi_uint *R_core = NULL;
    mbedtls_mpi R_legacy;
    mbedtls_mpi_init(&R_legacy);

    TEST_EQUAL(0, mbedtls_test_read_mpi(&max_legacy, max_hex));
    size_t limbs = max_legacy.n;
    TEST_CALLOC(R_core, limbs);

    /* Call the legacy function and the core function with the same random
     * stream. */
    int core_ret = mbedtls_mpi_core_random(R_core, min, max_legacy.p, limbs,
                                           mbedtls_test_rnd_pseudo_rand,
                                           &rnd_core);
    int legacy_ret = mbedtls_mpi_random(&R_legacy, min, &max_legacy,
                                        mbedtls_test_rnd_pseudo_rand,
                                        &rnd_legacy);

    /* They must return the same status, and, on success, output the
     * same number, with the same limb count. */
    TEST_EQUAL(core_ret, legacy_ret);
    if (core_ret == 0) {
        TEST_MEMORY_COMPARE(R_core, limbs * ciL,
                            R_legacy.p, R_legacy.n * ciL);
    }

    /* Also check that they have consumed the RNG in the same way. */
    /* This may theoretically fail on rare platforms with padding in
     * the structure! If this is a problem in practice, change to a
     * field-by-field comparison. */
    TEST_MEMORY_COMPARE(&rnd_core, sizeof(rnd_core),
```

## Call pattern 3

```c
TEST_MEMORY_COMPARE(R_core, limbs * ciL,
                            R_legacy.p, R_legacy.n * ciL);
    }

    /* Also check that they have consumed the RNG in the same way. */
    /* This may theoretically fail on rare platforms with padding in
     * the structure! If this is a problem in practice, change to a
     * field-by-field comparison. */
    TEST_MEMORY_COMPARE(&rnd_core, sizeof(rnd_core),
                        &rnd_legacy, sizeof(rnd_legacy));

exit:
    mbedtls_mpi_free(&max_legacy);
    mbedtls_free(R_core);
    mbedtls_mpi_free(&R_legacy);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_values(int min, char *max_hex, int rep)
{
    /* Same RNG as in mpi_core_random_basic */
    mbedtls_test_rnd_pseudo_info rnd_core = rnd_pseudo_seed;
    mbedtls_test_rnd_pseudo_info rnd_mod_raw;
    memcpy(&rnd_mod_raw, &rnd_core, sizeof(rnd_core));
    mbedtls_test_rnd_pseudo_info rnd_mod;
    memcpy(&rnd_mod, &rnd_core, sizeof(rnd_core));
    mbedtls_mpi_uint *R_core = NULL;
    mbedtls_mpi_uint *R_mod_raw = NULL;
    mbedtls_mpi_uint *R_mod_digits = NULL;
    mbedtls_mpi_mod_residue R_mod;
    mbedtls_mpi_mod_modulus N;
    mbedtls_mpi_mod_modulus_init(&N);

    TEST_EQUAL(mbedtls_test_read_mpi_modulus(&N, max_hex, rep), 0);
    TEST_CALLOC(R_core, N.limbs);
    TEST_CALLOC(R_mod_raw, N.limbs);
    TEST_CALLOC(R_mod_digits, N.limbs);
    TEST_EQUAL(mbedtls_mpi_mod_residue_setup(&R_mod, &N,
                                             R_mod_digits, N.limbs),
```

## Call pattern 4

```c
}

    /* Also check that they have consumed the RNG in the same way. */
    /* This may theoretically fail on rare platforms with padding in
     * the structure! If this is a problem in practice, change to a
     * field-by-field comparison. */
    TEST_MEMORY_COMPARE(&rnd_core, sizeof(rnd_core),
                        &rnd_legacy, sizeof(rnd_legacy));

exit:
    mbedtls_mpi_free(&max_legacy);
    mbedtls_free(R_core);
    mbedtls_mpi_free(&R_legacy);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_values(int min, char *max_hex, int rep)
{
    /* Same RNG as in mpi_core_random_basic */
    mbedtls_test_rnd_pseudo_info rnd_core = rnd_pseudo_seed;
    mbedtls_test_rnd_pseudo_info rnd_mod_raw;
    memcpy(&rnd_mod_raw, &rnd_core, sizeof(rnd_core));
    mbedtls_test_rnd_pseudo_info rnd_mod;
    memcpy(&rnd_mod, &rnd_core, sizeof(rnd_core));
    mbedtls_mpi_uint *R_core = NULL;
    mbedtls_mpi_uint *R_mod_raw = NULL;
    mbedtls_mpi_uint *R_mod_digits = NULL;
    mbedtls_mpi_mod_residue R_mod;
    mbedtls_mpi_mod_modulus N;
    mbedtls_mpi_mod_modulus_init(&N);

    TEST_EQUAL(mbedtls_test_read_mpi_modulus(&N, max_hex, rep), 0);
    TEST_CALLOC(R_core, N.limbs);
    TEST_CALLOC(R_mod_raw, N.limbs);
    TEST_CALLOC(R_mod_digits, N.limbs);
    TEST_EQUAL(mbedtls_mpi_mod_residue_setup(&R_mod, &N,
                                             R_mod_digits, N.limbs),
               0);
```

## Call pattern 5

```c
min, upper_bound, limbs,
                                              mbedtls_test_rnd_std_rand, NULL));

        /* Temporarily use a legacy MPI for analysis, because the
         * necessary auxiliary functions don't exist yet in core. */
        mbedtls_mpi B = { .s = 1, .n = limbs, .p = upper_bound };
        mbedtls_mpi R = { .s = 1, .n = limbs, .p = result };

        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R, &B) < 0);
        TEST_ASSERT(mbedtls_mpi_cmp_int(&R, min) >= 0);
        if (full_stats) {
            uint8_t value;
            TEST_EQUAL(0, mbedtls_mpi_write_binary(&R, &value, 1));
            TEST_ASSERT(value < stats_len);
            ++stats[value];
        } else {
            for (b = 0; b < n_bits; b++) {
                stats[b] += mbedtls_mpi_get_bit(&R, b);
            }
        }
    }

    if (full_stats) {
        for (b = min; b < stats_len; b++) {
            mbedtls_test_set_step(1000000 + b);
            /* Assert that each value has been reached at least once.
             * This is almost guaranteed if the iteration count is large
             * enough. This is a very crude way of checking the distribution.
             */
            TEST_ASSERT(stats[b] > 0);
        }
    } else {
        bound_bytes.len = limbs * sizeof(mbedtls_mpi_uint);
        TEST_CALLOC(bound_bytes.x, bound_bytes.len);
        mbedtls_mpi_core_write_be(upper_bound, limbs,
                                  bound_bytes.x, bound_bytes.len);
        int statistically_safe_all_the_way =
            is_significantly_above_a_power_of_2(&bound_bytes);
        for (b = 0; b < n_bits; b++) {
            mbedtls_test_set_step(1000000 + b);
```

## Call pattern 6

```c
mbedtls_free(upper_bound);
    mbedtls_free(result);
    mbedtls_free(stats);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_random_sizes(int min, data_t *bound_bytes, int nlimbs, int before)
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    if (before != 0) {
        /* Set result to sign(before) * 2^(|before|-1) */
        TEST_ASSERT(mbedtls_mpi_lset(&result, before > 0 ? 1 : -1) == 0);
        if (before < 0) {
            before = -before;
        }
        TEST_ASSERT(mbedtls_mpi_shift_l(&result, before - 1) == 0);
    }

    TEST_EQUAL(0, mbedtls_mpi_grow(&result, nlimbs));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    TEST_EQUAL(0, mbedtls_mpi_random(&result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL));
    TEST_ASSERT(sign_is_valid(&result));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&result, &upper_bound) < 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&result, min) >= 0);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
```

## Call pattern 7

```c
mbedtls_free(result);
    mbedtls_free(stats);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_random_sizes(int min, data_t *bound_bytes, int nlimbs, int before)
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    if (before != 0) {
        /* Set result to sign(before) * 2^(|before|-1) */
        TEST_ASSERT(mbedtls_mpi_lset(&result, before > 0 ? 1 : -1) == 0);
        if (before < 0) {
            before = -before;
        }
        TEST_ASSERT(mbedtls_mpi_shift_l(&result, before - 1) == 0);
    }

    TEST_EQUAL(0, mbedtls_mpi_grow(&result, nlimbs));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    TEST_EQUAL(0, mbedtls_mpi_random(&result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL));
    TEST_ASSERT(sign_is_valid(&result));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&result, &upper_bound) < 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&result, min) >= 0);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_validation(int min, char *bound_hex,
```

## Call pattern 8

```c
/* BEGIN_CASE */
void mpi_random_sizes(int min, data_t *bound_bytes, int nlimbs, int before)
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    if (before != 0) {
        /* Set result to sign(before) * 2^(|before|-1) */
        TEST_ASSERT(mbedtls_mpi_lset(&result, before > 0 ? 1 : -1) == 0);
        if (before < 0) {
            before = -before;
        }
        TEST_ASSERT(mbedtls_mpi_shift_l(&result, before - 1) == 0);
    }

    TEST_EQUAL(0, mbedtls_mpi_grow(&result, nlimbs));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    TEST_EQUAL(0, mbedtls_mpi_random(&result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL));
    TEST_ASSERT(sign_is_valid(&result));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&result, &upper_bound) < 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&result, min) >= 0);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_validation(int min, char *bound_hex,
                               int result_limbs_delta,
                               int expected_ret)
{
    mbedtls_mpi_uint *result_digits = NULL;
```

## Call pattern 9

```c
}

    TEST_EQUAL(0, mbedtls_mpi_grow(&result, nlimbs));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    TEST_EQUAL(0, mbedtls_mpi_random(&result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL));
    TEST_ASSERT(sign_is_valid(&result));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&result, &upper_bound) < 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&result, min) >= 0);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_validation(int min, char *bound_hex,
                               int result_limbs_delta,
                               int expected_ret)
{
    mbedtls_mpi_uint *result_digits = NULL;
    mbedtls_mpi_mod_modulus N;
    mbedtls_mpi_mod_modulus_init(&N);

    TEST_EQUAL(mbedtls_test_read_mpi_modulus(&N, bound_hex,
                                             MBEDTLS_MPI_MOD_REP_OPT_RED),
               0);
    size_t result_limbs = N.limbs + result_limbs_delta;
    TEST_CALLOC(result_digits, result_limbs);
    /* Build a reside that might not match the modulus, to test that
     * the library function rejects that as expected. */
    mbedtls_mpi_mod_residue result = { result_digits, result_limbs };

    TEST_EQUAL(mbedtls_mpi_mod_random(&result, min, &N,
                                      mbedtls_test_rnd_std_rand, NULL),
               expected_ret);
    if (expected_ret == 0) {
        /* Success should only be expected when the result has the same
```

## Call pattern 10

```c
TEST_EQUAL(0, mbedtls_mpi_grow(&result, nlimbs));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    TEST_EQUAL(0, mbedtls_mpi_random(&result, min, &upper_bound,
                                     mbedtls_test_rnd_std_rand, NULL));
    TEST_ASSERT(sign_is_valid(&result));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&result, &upper_bound) < 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&result, min) >= 0);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_WITH_MPI_UINT */
void mpi_mod_random_validation(int min, char *bound_hex,
                               int result_limbs_delta,
                               int expected_ret)
{
    mbedtls_mpi_uint *result_digits = NULL;
    mbedtls_mpi_mod_modulus N;
    mbedtls_mpi_mod_modulus_init(&N);

    TEST_EQUAL(mbedtls_test_read_mpi_modulus(&N, bound_hex,
                                             MBEDTLS_MPI_MOD_REP_OPT_RED),
               0);
    size_t result_limbs = N.limbs + result_limbs_delta;
    TEST_CALLOC(result_digits, result_limbs);
    /* Build a reside that might not match the modulus, to test that
     * the library function rejects that as expected. */
    mbedtls_mpi_mod_residue result = { result_digits, result_limbs };

    TEST_EQUAL(mbedtls_mpi_mod_random(&result, min, &N,
                                      mbedtls_test_rnd_std_rand, NULL),
               expected_ret);
    if (expected_ret == 0) {
        /* Success should only be expected when the result has the same
         * size as the modulus, otherwise it's a mistake in the test data. */
```

## Call pattern 11

```c
mbedtls_test_mpi_mod_modulus_free_with_limbs(&N);
    mbedtls_free(result_digits);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_random_fail(int min, data_t *bound_bytes, int expected_ret)
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;
    int actual_ret;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    actual_ret = mbedtls_mpi_random(&result, min, &upper_bound,
                                    mbedtls_test_rnd_std_rand, NULL);
    TEST_EQUAL(expected_ret, actual_ret);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */
```

## Call pattern 12

```c
mbedtls_free(result_digits);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_random_fail(int min, data_t *bound_bytes, int expected_ret)
{
    mbedtls_mpi upper_bound;
    mbedtls_mpi result;
    int actual_ret;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    actual_ret = mbedtls_mpi_random(&result, min, &upper_bound,
                                    mbedtls_test_rnd_std_rand, NULL);
    TEST_EQUAL(expected_ret, actual_ret);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */
```

## Call pattern 13

```c
int actual_ret;

    mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    actual_ret = mbedtls_mpi_random(&result, min, &upper_bound,
                                    mbedtls_test_rnd_std_rand, NULL);
    TEST_EQUAL(expected_ret, actual_ret);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */
```

## Call pattern 14

```c
mbedtls_mpi_init(&upper_bound);
    mbedtls_mpi_init(&result);

    TEST_EQUAL(0, mbedtls_mpi_read_binary(&upper_bound,
                                          bound_bytes->x, bound_bytes->len));
    actual_ret = mbedtls_mpi_random(&result, min, &upper_bound,
                                    mbedtls_test_rnd_std_rand, NULL);
    TEST_EQUAL(expected_ret, actual_ret);

exit:
    mbedtls_mpi_free(&upper_bound);
    mbedtls_mpi_free(&result);
}
/* END_CASE */
```

