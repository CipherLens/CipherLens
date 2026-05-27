# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_psa_crypto_driver_wrappers.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
* \param input_data            The input plaintext.
 * \param buf                   The ciphertext produced by the driver.
 * \param length                Length of \p buf in bytes.
 */
static int sanity_check_rsa_encryption_result(
    psa_algorithm_t alg,
    const data_t *modulus, const data_t *private_exponent,
    const data_t *input_data,
    uint8_t *buf, size_t length)
{
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi N, D, C, X;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&X);
#else /* MBEDTLS_BIGNUM_C */
    (void) alg;
    (void) private_exponent;
    (void) input_data;
    (void) buf;
#endif /* MBEDTLS_BIGNUM_C */

    int ok = 0;

    TEST_ASSERT(length == modulus->len);

#if defined(MBEDTLS_BIGNUM_C)
    /* Perform the private key operation */
    TEST_ASSERT(mbedtls_mpi_read_binary(&N, modulus->x, modulus->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&D,
                                        private_exponent->x,
                                        private_exponent->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&C, buf, length) == 0);
    TEST_ASSERT(mbedtls_mpi_exp_mod(&X, &C, &D, &N, NULL) == 0);

    /* Sanity checks on the padded plaintext */
    TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, length) == 0);

    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
```

## Call pattern 2

```c
* \param buf                   The ciphertext produced by the driver.
 * \param length                Length of \p buf in bytes.
 */
static int sanity_check_rsa_encryption_result(
    psa_algorithm_t alg,
    const data_t *modulus, const data_t *private_exponent,
    const data_t *input_data,
    uint8_t *buf, size_t length)
{
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi N, D, C, X;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&X);
#else /* MBEDTLS_BIGNUM_C */
    (void) alg;
    (void) private_exponent;
    (void) input_data;
    (void) buf;
#endif /* MBEDTLS_BIGNUM_C */

    int ok = 0;

    TEST_ASSERT(length == modulus->len);

#if defined(MBEDTLS_BIGNUM_C)
    /* Perform the private key operation */
    TEST_ASSERT(mbedtls_mpi_read_binary(&N, modulus->x, modulus->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&D,
                                        private_exponent->x,
                                        private_exponent->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&C, buf, length) == 0);
    TEST_ASSERT(mbedtls_mpi_exp_mod(&X, &C, &D, &N, NULL) == 0);

    /* Sanity checks on the padded plaintext */
    TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, length) == 0);

    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        TEST_ASSERT(length > input_data->len + 2);
```

## Call pattern 3

```c
* \param length                Length of \p buf in bytes.
 */
static int sanity_check_rsa_encryption_result(
    psa_algorithm_t alg,
    const data_t *modulus, const data_t *private_exponent,
    const data_t *input_data,
    uint8_t *buf, size_t length)
{
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi N, D, C, X;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&X);
#else /* MBEDTLS_BIGNUM_C */
    (void) alg;
    (void) private_exponent;
    (void) input_data;
    (void) buf;
#endif /* MBEDTLS_BIGNUM_C */

    int ok = 0;

    TEST_ASSERT(length == modulus->len);

#if defined(MBEDTLS_BIGNUM_C)
    /* Perform the private key operation */
    TEST_ASSERT(mbedtls_mpi_read_binary(&N, modulus->x, modulus->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&D,
                                        private_exponent->x,
                                        private_exponent->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&C, buf, length) == 0);
    TEST_ASSERT(mbedtls_mpi_exp_mod(&X, &C, &D, &N, NULL) == 0);

    /* Sanity checks on the padded plaintext */
    TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, length) == 0);

    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        TEST_ASSERT(length > input_data->len + 2);
        TEST_EQUAL(buf[0], 0x00);
```

## Call pattern 4

```c
*/
static int sanity_check_rsa_encryption_result(
    psa_algorithm_t alg,
    const data_t *modulus, const data_t *private_exponent,
    const data_t *input_data,
    uint8_t *buf, size_t length)
{
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi N, D, C, X;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&X);
#else /* MBEDTLS_BIGNUM_C */
    (void) alg;
    (void) private_exponent;
    (void) input_data;
    (void) buf;
#endif /* MBEDTLS_BIGNUM_C */

    int ok = 0;

    TEST_ASSERT(length == modulus->len);

#if defined(MBEDTLS_BIGNUM_C)
    /* Perform the private key operation */
    TEST_ASSERT(mbedtls_mpi_read_binary(&N, modulus->x, modulus->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&D,
                                        private_exponent->x,
                                        private_exponent->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&C, buf, length) == 0);
    TEST_ASSERT(mbedtls_mpi_exp_mod(&X, &C, &D, &N, NULL) == 0);

    /* Sanity checks on the padded plaintext */
    TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, length) == 0);

    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        TEST_ASSERT(length > input_data->len + 2);
        TEST_EQUAL(buf[0], 0x00);
        TEST_EQUAL(buf[1], 0x02);
```

## Call pattern 5

```c
TEST_ASSERT(length == modulus->len);

#if defined(MBEDTLS_BIGNUM_C)
    /* Perform the private key operation */
    TEST_ASSERT(mbedtls_mpi_read_binary(&N, modulus->x, modulus->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&D,
                                        private_exponent->x,
                                        private_exponent->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&C, buf, length) == 0);
    TEST_ASSERT(mbedtls_mpi_exp_mod(&X, &C, &D, &N, NULL) == 0);

    /* Sanity checks on the padded plaintext */
    TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, length) == 0);

    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        TEST_ASSERT(length > input_data->len + 2);
        TEST_EQUAL(buf[0], 0x00);
        TEST_EQUAL(buf[1], 0x02);
        TEST_EQUAL(buf[length - input_data->len - 1], 0x00);
        TEST_MEMORY_COMPARE(buf + length - input_data->len, input_data->len,
                            input_data->x, input_data->len);
    } else if (PSA_ALG_IS_RSA_OAEP(alg)) {
        TEST_EQUAL(buf[0], 0x00);
        /* The rest is too hard to check */
    } else {
        TEST_FAIL("Encryption result sanity check not implemented for RSA algorithm");
    }
#endif /* MBEDTLS_BIGNUM_C */

    ok = 1;

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&X);
#endif /* MBEDTLS_BIGNUM_C */
    return ok;
}
```

## Call pattern 6

```c
} else if (PSA_ALG_IS_RSA_OAEP(alg)) {
        TEST_EQUAL(buf[0], 0x00);
        /* The rest is too hard to check */
    } else {
        TEST_FAIL("Encryption result sanity check not implemented for RSA algorithm");
    }
#endif /* MBEDTLS_BIGNUM_C */

    ok = 1;

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&X);
#endif /* MBEDTLS_BIGNUM_C */
    return ok;
}
#endif
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_PSA_CRYPTO_C:PSA_CRYPTO_DRIVER_TEST
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void builtin_key_id_stability()
{
    /* If the range of built-in keys is reduced, it's an API break, since
     * it breaks user code that hard-codes the key id of built-in keys.
     * It's ok to expand this range, but not to shrink it. That is, you
     * may make the MIN smaller or the MAX larger at any time, but
     * making the MIN larger or the MAX smaller can only be done in
     * a new major version of the library.
     */
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MIN, 0x7fff0000);
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, 0x7fffefff);
}
```

## Call pattern 7

```c
TEST_EQUAL(buf[0], 0x00);
        /* The rest is too hard to check */
    } else {
        TEST_FAIL("Encryption result sanity check not implemented for RSA algorithm");
    }
#endif /* MBEDTLS_BIGNUM_C */

    ok = 1;

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&X);
#endif /* MBEDTLS_BIGNUM_C */
    return ok;
}
#endif
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_PSA_CRYPTO_C:PSA_CRYPTO_DRIVER_TEST
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void builtin_key_id_stability()
{
    /* If the range of built-in keys is reduced, it's an API break, since
     * it breaks user code that hard-codes the key id of built-in keys.
     * It's ok to expand this range, but not to shrink it. That is, you
     * may make the MIN smaller or the MAX larger at any time, but
     * making the MIN larger or the MAX smaller can only be done in
     * a new major version of the library.
     */
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MIN, 0x7fff0000);
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, 0x7fffefff);
}
/* END_CASE */
```

## Call pattern 8

```c
/* The rest is too hard to check */
    } else {
        TEST_FAIL("Encryption result sanity check not implemented for RSA algorithm");
    }
#endif /* MBEDTLS_BIGNUM_C */

    ok = 1;

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&X);
#endif /* MBEDTLS_BIGNUM_C */
    return ok;
}
#endif
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_PSA_CRYPTO_C:PSA_CRYPTO_DRIVER_TEST
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void builtin_key_id_stability()
{
    /* If the range of built-in keys is reduced, it's an API break, since
     * it breaks user code that hard-codes the key id of built-in keys.
     * It's ok to expand this range, but not to shrink it. That is, you
     * may make the MIN smaller or the MAX larger at any time, but
     * making the MIN larger or the MAX smaller can only be done in
     * a new major version of the library.
     */
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MIN, 0x7fff0000);
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, 0x7fffefff);
}
/* END_CASE */
```

## Call pattern 9

```c
} else {
        TEST_FAIL("Encryption result sanity check not implemented for RSA algorithm");
    }
#endif /* MBEDTLS_BIGNUM_C */

    ok = 1;

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&X);
#endif /* MBEDTLS_BIGNUM_C */
    return ok;
}
#endif
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_PSA_CRYPTO_C:PSA_CRYPTO_DRIVER_TEST
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void builtin_key_id_stability()
{
    /* If the range of built-in keys is reduced, it's an API break, since
     * it breaks user code that hard-codes the key id of built-in keys.
     * It's ok to expand this range, but not to shrink it. That is, you
     * may make the MIN smaller or the MAX larger at any time, but
     * making the MIN larger or the MAX smaller can only be done in
     * a new major version of the library.
     */
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MIN, 0x7fff0000);
    TEST_EQUAL(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, 0x7fffefff);
}
/* END_CASE */

/* BEGIN_CASE */
```

