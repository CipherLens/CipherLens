# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_random.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_PSA_CRYPTO_C:MBEDTLS_ECDSA_C */
void mbedtls_psa_get_random_ecdsa_sign(int curve)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    unsigned char buf[] = "This is not a hash.";

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 2

```c
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_PSA_CRYPTO_C:MBEDTLS_ECDSA_C */
void mbedtls_psa_get_random_ecdsa_sign(int curve)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    unsigned char buf[] = "This is not a hash.";

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 3

```c
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_PSA_CRYPTO_C:MBEDTLS_ECDSA_C */
void mbedtls_psa_get_random_ecdsa_sign(int curve)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    unsigned char buf[] = "This is not a hash.";

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 4

```c
/* BEGIN_CASE depends_on:MBEDTLS_PSA_CRYPTO_C:MBEDTLS_ECDSA_C */
void mbedtls_psa_get_random_ecdsa_sign(int curve)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    unsigned char buf[] = "This is not a hash.";

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 5

```c
mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 6

```c
mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

## Call pattern 7

```c
mbedtls_mpi_init(&s);

    TEST_EQUAL(0, mbedtls_mpi_lset(&d, 123456789));
    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, curve));
    PSA_ASSERT(psa_crypto_init());
    TEST_EQUAL(0, mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                     buf, sizeof(buf),
                                     mbedtls_psa_get_random,
                                     MBEDTLS_PSA_RANDOM_STATE));
exit:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    PSA_DONE();
}
/* END_CASE */
```

