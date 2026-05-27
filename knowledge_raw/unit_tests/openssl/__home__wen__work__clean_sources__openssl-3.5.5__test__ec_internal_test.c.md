# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/ec_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
TEST_info("Testing GF2m hardening\n");

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    if (!TEST_ptr(b = BN_CTX_get(ctx))
        || !TEST_true(BN_one(a))
        || !TEST_true(BN_one(b)))
        goto out;

    /* Even pentanomial value should be rejected */
    if (!TEST_true(BN_set_word(p, 0xf2)))
        goto out;
    if (!TEST_ptr_null(group1 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Zero constant term accepted in GF2m polynomial");

    /* Odd hexanomial should also be rejected */
    if (!TEST_true(BN_set_word(p, 0xf3)))
        goto out;
    if (!TEST_ptr_null(group2 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Hexanomial accepted as GF2m polynomial");

    /* Excessive polynomial degree should also be rejected */
    if (!TEST_true(BN_set_word(p, 0x71))
        || !TEST_true(BN_set_bit(p, OPENSSL_ECC_MAX_FIELD_BITS + 1)))
        goto out;
    if (!TEST_ptr_null(group3 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("GF2m polynomial degree > %d accepted",
            OPENSSL_ECC_MAX_FIELD_BITS);

    ret = group1 == NULL && group2 == NULL && group3 == NULL;

out:
    EC_GROUP_free(group1);
    EC_GROUP_free(group2);
    EC_GROUP_free(group3);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
```

## Call pattern 2

```c
if (!TEST_ptr(b = BN_CTX_get(ctx))
        || !TEST_true(BN_one(a))
        || !TEST_true(BN_one(b)))
        goto out;

    /* Even pentanomial value should be rejected */
    if (!TEST_true(BN_set_word(p, 0xf2)))
        goto out;
    if (!TEST_ptr_null(group1 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Zero constant term accepted in GF2m polynomial");

    /* Odd hexanomial should also be rejected */
    if (!TEST_true(BN_set_word(p, 0xf3)))
        goto out;
    if (!TEST_ptr_null(group2 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Hexanomial accepted as GF2m polynomial");

    /* Excessive polynomial degree should also be rejected */
    if (!TEST_true(BN_set_word(p, 0x71))
        || !TEST_true(BN_set_bit(p, OPENSSL_ECC_MAX_FIELD_BITS + 1)))
        goto out;
    if (!TEST_ptr_null(group3 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("GF2m polynomial degree > %d accepted",
            OPENSSL_ECC_MAX_FIELD_BITS);

    ret = group1 == NULL && group2 == NULL && group3 == NULL;

out:
    EC_GROUP_free(group1);
    EC_GROUP_free(group2);
    EC_GROUP_free(group3);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

/* test EC_GF2m_simple_method directly */
static int field_tests_ec2_simple(void)
{
```

## Call pattern 3

```c
if (!TEST_true(BN_set_word(p, 0xf2)))
        goto out;
    if (!TEST_ptr_null(group1 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Zero constant term accepted in GF2m polynomial");

    /* Odd hexanomial should also be rejected */
    if (!TEST_true(BN_set_word(p, 0xf3)))
        goto out;
    if (!TEST_ptr_null(group2 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Hexanomial accepted as GF2m polynomial");

    /* Excessive polynomial degree should also be rejected */
    if (!TEST_true(BN_set_word(p, 0x71))
        || !TEST_true(BN_set_bit(p, OPENSSL_ECC_MAX_FIELD_BITS + 1)))
        goto out;
    if (!TEST_ptr_null(group3 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("GF2m polynomial degree > %d accepted",
            OPENSSL_ECC_MAX_FIELD_BITS);

    ret = group1 == NULL && group2 == NULL && group3 == NULL;

out:
    EC_GROUP_free(group1);
    EC_GROUP_free(group2);
    EC_GROUP_free(group3);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

/* test EC_GF2m_simple_method directly */
static int field_tests_ec2_simple(void)
{
    TEST_info("Testing EC_GF2m_simple_method()\n");
    return field_tests(EC_GF2m_simple_method(), params_b283,
        sizeof(params_b283) / 3);
}
#endif
```

