# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/rsa_sp800_56b_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
0x17, 0x98, 0xb3, 0x6f, 0x6b, 0x9a, 0xeb, 0x6b, 0xa3, 0xc4, 0x75, 0xd8, 0x2b, 0xdc, 0x5c,
    0x6f, 0xec, 0x5d, 0x49, 0xac, 0xa8, 0xa4, 0x2f, 0xb8, 0x8c, 0x4f, 0x2e, 0x46, 0x21, 0xee,
    0x72, 0x6a, 0x0e, 0x22, 0x80, 0x71, 0xc8, 0x76, 0x40, 0x44, 0x61, 0x16, 0xbf, 0xa5, 0xf8,
    0x89, 0xc7, 0xe9, 0x87, 0xdf, 0xbd, 0x2e, 0x4b, 0x4e, 0xc2, 0x97, 0x53, 0xe9, 0x49, 0x1c,
    0x05, 0xb0, 0x0b, 0x9b, 0x9f, 0x21, 0x19, 0x41, 0xe9, 0xf5, 0x61, 0xd7, 0x33, 0x2e, 0x2c,
    0x94, 0xb8, 0xa8, 0x9a, 0x3a, 0xcc, 0x6a, 0x24, 0x8d, 0x19, 0x13, 0xee, 0xb9, 0xb0, 0x48,
    0x61
};

/* helper function */
static BIGNUM *bn_load_new(const unsigned char *data, int sz)
{
    BIGNUM *ret = BN_new();
    if (ret != NULL)
        BN_bin2bn(data, sz, ret);
    return ret;
}

/* Check that small rsa exponents are allowed in non FIPS mode */
static int test_check_public_exponent(void)
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
```

## Call pattern 2

```c
BIGNUM *ret = BN_new();
    if (ret != NULL)
        BN_bin2bn(data, sz, ret);
    return ret;
}

/* Check that small rsa exponents are allowed in non FIPS mode */
static int test_check_public_exponent(void)
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
```

## Call pattern 3

```c
BN_bin2bn(data, sz, ret);
    return ret;
}

/* Check that small rsa exponents are allowed in non FIPS mode */
static int test_check_public_exponent(void)
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
```

## Call pattern 4

```c
/* Check that small rsa exponents are allowed in non FIPS mode */
static int test_check_public_exponent(void)
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };
```

## Call pattern 5

```c
{
    int ret = 0;
    BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
```

## Call pattern 6

```c
BIGNUM *e = NULL;

    ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
```

## Call pattern 7

```c
ret = TEST_ptr(e = BN_new())
        /* e is too small will fail */
        && TEST_true(BN_set_word(e, 1))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is even will fail */
        && TEST_true(BN_set_word(e, 65536))
        && TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
```

## Call pattern 8

```c
&& TEST_false(ossl_rsa_check_public_exponent(e))
        /* e is ok */
        && TEST_true(BN_set_word(e, 3))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 17))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        && TEST_true(BN_set_word(e, 65537))
        && TEST_true(ossl_rsa_check_public_exponent(e))
        /* e = 2^256 + 1 is ok */
        && TEST_true(BN_lshift(e, BN_value_one(), 256))
        && TEST_true(BN_add(e, e, BN_value_one()))
        && TEST_true(ossl_rsa_check_public_exponent(e));
    BN_free(e);
    return ret;
}

static int test_check_prime_factor_range(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
```

## Call pattern 9

```c
BIGNUM *p = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL, *bn_p4 = NULL;
    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4F, 0x33, 0x3F };
    static const unsigned char p2[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
    static const unsigned char p3[] = { 0x0B, 0x50, 0x4F, 0x33, 0x40 };
    static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
```

## Call pattern 10

```c
static const unsigned char p4[] = { 0x0F, 0xFF, 0xFF, 0xFF, 0xFF };

    /* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
```

## Call pattern 11

```c
/* (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
     * For 8 bits:   0xB.504F <= p <= 0xF
     * for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;
```

## Call pattern 12

```c
* for 72 bits:  0xB504F333F. <= p <= 0xF_FFFF_FFFF
     */
    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
```

## Call pattern 13

```c
ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
```

## Call pattern 14

```c
&& TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(bn_p4 = bn_load_new(p4, sizeof(p4)))
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_true(BN_set_word(p, 0xA))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0x10))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };
```

## Call pattern 15

```c
&& TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
```

## Call pattern 16

```c
&& TEST_true(BN_set_word(p, 0xB))
        && TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
```

## Call pattern 17

```c
&& TEST_false(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
```

## Call pattern 18

```c
&& TEST_true(BN_set_word(p, 0xC))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
```

## Call pattern 19

```c
&& TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_true(BN_set_word(p, 0xF))
        && TEST_true(ossl_rsa_check_prime_factor_range(p, 8, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p1, 72, ctx))
        && TEST_false(ossl_rsa_check_prime_factor_range(bn_p2, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p3, 72, ctx))
        && TEST_true(ossl_rsa_check_prime_factor_range(bn_p4, 72, ctx));

    BN_free(bn_p4);
    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
```

## Call pattern 20

```c
static int test_check_prime_factor(void)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
```

## Call pattern 21

```c
BIGNUM *p = NULL, *e = NULL;
    BIGNUM *bn_p1 = NULL, *bn_p2 = NULL, *bn_p3 = NULL;

    /* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
```

## Call pattern 22

```c
/* Some range checks that are larger than 32 bits */
    static const unsigned char p1[] = { 0x0B, 0x50, 0x4f, 0x33, 0x73 };
    static const unsigned char p2[] = { 0x0B, 0x50, 0x4f, 0x33, 0x75 };
    static const unsigned char p3[] = { 0x0F, 0x50, 0x00, 0x03, 0x75 };

    ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;
```

## Call pattern 23

```c
ret = TEST_ptr(p = BN_new())
        && TEST_ptr(bn_p1 = bn_load_new(p1, sizeof(p1)))
        && TEST_ptr(bn_p2 = bn_load_new(p2, sizeof(p2)))
        && TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
```

## Call pattern 24

```c
&& TEST_ptr(bn_p3 = bn_load_new(p3, sizeof(p3)))
        && TEST_ptr(e = BN_new())
        && TEST_ptr(ctx = BN_CTX_new())
        /* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
```

## Call pattern 25

```c
/* Fails the prime test */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
```

## Call pattern 26

```c
&& TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
```

## Call pattern 27

```c
&& TEST_false(ossl_rsa_check_prime_factor(bn_p1, e, 72, ctx))
        /* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }
```

## Call pattern 28

```c
/* p is prime and in range and gcd(p-1, e) = 1 */
        && TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }
```

## Call pattern 29

```c
&& TEST_true(ossl_rsa_check_prime_factor(bn_p2, e, 72, ctx))
        /* gcd(p-1,e) = 1 test fails */
        && TEST_true(BN_set_word(e, 0x2))
        && TEST_false(ossl_rsa_check_prime_factor(p, e, 72, ctx))
        /* p fails the range check */
        && TEST_true(BN_set_word(e, 0x1))
        && TEST_false(ossl_rsa_check_prime_factor(bn_p3, e, 72, ctx));

    BN_free(bn_p3);
    BN_free(bn_p2);
    BN_free(bn_p1);
    BN_free(e);
    BN_free(p);
    BN_CTX_free(ctx);
    return ret;
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
```

## Call pattern 30

```c
}

/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
```

## Call pattern 31

```c
/* This test uses legacy functions because they can take invalid numbers */
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
```

## Call pattern 32

```c
static int test_check_private_exponent(void)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
```

## Call pattern 33

```c
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
```

## Call pattern 34

```c
BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
```

## Call pattern 35

```c
BIGNUM *p = NULL, *q = NULL, *e = NULL, *d = NULL, *n = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
```

## Call pattern 36

```c
&& TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
```

## Call pattern 37

```c
&& TEST_ptr(q = BN_new())
        /* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
```

## Call pattern 38

```c
/* lcm(15-1,17-1) = 14*16 / 2 = 112 */
        && TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
```

## Call pattern 39

```c
&& TEST_true(BN_set_word(p, 15))
        && TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}
```

## Call pattern 40

```c
&& TEST_true(BN_set_word(q, 17))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}
```

## Call pattern 41

```c
&& TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
```

## Call pattern 42

```c
BN_free(q);
        goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
```

## Call pattern 43

```c
goto end;
    }

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
```

## Call pattern 44

```c
}

    ret = TEST_ptr(e = BN_new())
        && TEST_ptr(d = BN_new())
        && TEST_ptr(n = BN_new())
        && TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
    const int N = P * Q;
```

## Call pattern 45

```c
&& TEST_true(BN_set_word(e, 5))
        && TEST_true(BN_set_word(d, 157))
        && TEST_true(BN_set_word(n, 15 * 17))
        && TEST_true(RSA_set0_key(key, n, e, d));
    if (!ret) {
        BN_free(e);
        BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
    const int N = P * Q;
    const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
```

## Call pattern 46

```c
BN_free(d);
        BN_free(n);
        goto end;
    }
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
    const int N = P * Q;
    const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
```

## Call pattern 47

```c
}
    /* fails since d >= lcm(p-1, q-1) */
    ret = TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        && TEST_true(BN_set_word(d, 45))
        /* d is correct size and 1 = e.d mod lcm(p-1, q-1) */
        && TEST_true(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* d is too small compared to nbits */
        && TEST_false(ossl_rsa_check_private_exponent(key, 16, ctx))
        /* d is too small compared to nbits */
        && TEST_true(BN_set_word(d, 16))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx))
        /* fail if 1 != e.d mod lcm(p-1, q-1) */
        && TEST_true(BN_set_word(d, 46))
        && TEST_false(ossl_rsa_check_private_exponent(key, 8, ctx));
end:
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_check_crt_components(void)
{
    const int P = 15;
    const int Q = 17;
    const int E = 5;
    const int N = P * Q;
    const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
```

## Call pattern 48

```c
const int N = P * Q;
    const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
```

## Call pattern 49

```c
const int DP = 3;
    const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
```

## Call pattern 50

```c
const int DQ = 13;
    const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
```

## Call pattern 51

```c
const int QINV = 8;

    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
```

## Call pattern 52

```c
int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
```

## Call pattern 53

```c
int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
```

## Call pattern 54

```c
BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
```

## Call pattern 55

```c
ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, P))
        && TEST_true(BN_set_word(q, Q))
        && TEST_true(BN_set_word(e, E))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
```

## Call pattern 56

```c
BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
```

## Call pattern 57

```c
goto end;
    }

    ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
```

## Call pattern 58

```c
ret = TEST_int_eq(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 1)
        && TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
```

## Call pattern 59

```c
&& TEST_BN_eq_word(key->n, N)
        && TEST_BN_eq_word(key->dmp1, DP)
        && TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
```

## Call pattern 60

```c
&& TEST_BN_eq_word(key->dmq1, DQ)
        && TEST_BN_eq_word(key->iqmp, QINV)
        && TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
```

## Call pattern 61

```c
&& TEST_true(ossl_rsa_check_crt_components(key, ctx))
        /* (a) 1 < dP < (p – 1). */
        && TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}
```

## Call pattern 62

```c
&& TEST_true(BN_set_word(key->dmp1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
```

## Call pattern 63

```c
&& TEST_true(BN_set_word(key->dmp1, P - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
```

## Call pattern 64

```c
&& TEST_true(BN_set_word(key->dmp1, DP))
        /* (b) 1 < dQ < (q - 1). */
        && TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};
```

## Call pattern 65

```c
&& TEST_true(BN_set_word(key->dmq1, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
```

## Call pattern 66

```c
&& TEST_true(BN_set_word(key->dmq1, Q - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
```

## Call pattern 67

```c
&& TEST_true(BN_set_word(key->dmq1, DQ))
        /* (c) 1 < qInv < p */
        && TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
```

## Call pattern 68

```c
&& TEST_true(BN_set_word(key->iqmp, 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;
```

## Call pattern 69

```c
&& TEST_true(BN_set_word(key->iqmp, P))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
```

## Call pattern 70

```c
&& TEST_true(BN_set_word(key->iqmp, QINV))
        /* (d) 1 = (dP . e) mod (p - 1)*/
        && TEST_true(BN_set_word(key->dmp1, DP + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
```

## Call pattern 71

```c
&& TEST_true(BN_set_word(key->dmp1, DP))
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && TEST_true(BN_set_word(key->dmq1, DQ - 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->dmq1, DQ))
        /* (f) 1 = (qInv . q) mod p */
        && TEST_true(BN_set_word(key->iqmp, QINV + 1))
        && TEST_false(ossl_rsa_check_crt_components(key, ctx))
        && TEST_true(BN_set_word(key->iqmp, QINV))
        /* check defaults are still valid */
        && TEST_true(ossl_rsa_check_crt_components(key, ctx));
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static const struct derive_from_pq_test {
    int p, q, e;
} derive_from_pq_tests[] = {
    { 15, 17, 6 }, /* Mod_inverse failure */
    { 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
```

## Call pattern 72

```c
{ 0, 17, 5 }, /* d is too small */
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
```

## Call pattern 73

```c
};

static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
```

## Call pattern 74

```c
static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
```

## Call pattern 75

```c
static int test_derive_params_from_pq_fail(int tst)
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
```

## Call pattern 76

```c
{
    int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
        && TEST_true(BN_set_word(q, 1 + 2))
```

## Call pattern 77

```c
int ret = 0;
    RSA *key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
        && TEST_true(BN_set_word(q, 1 + 2))
        && TEST_false(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
```

## Call pattern 78

```c
BIGNUM *p = NULL, *q = NULL, *e = NULL;

    ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
        && TEST_true(BN_set_word(q, 1 + 2))
        && TEST_false(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
        /* Check |p - q| > 2^(nbits/2 - 100) */
        && TEST_true(BN_set_word(q, 1 + 3))
        && TEST_true(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
```

## Call pattern 79

```c
ret = TEST_ptr(key = RSA_new())
        && TEST_ptr(ctx = BN_CTX_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        && TEST_ptr(e = BN_new())
        && TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
        && TEST_true(BN_set_word(q, 1 + 2))
        && TEST_false(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
        /* Check |p - q| > 2^(nbits/2 - 100) */
        && TEST_true(BN_set_word(q, 1 + 3))
        && TEST_true(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
        && TEST_true(BN_set_word(p, 1 + 3))
```

## Call pattern 80

```c
&& TEST_true(BN_set_word(p, derive_from_pq_tests[tst].p))
        && TEST_true(BN_set_word(q, derive_from_pq_tests[tst].q))
        && TEST_true(BN_set_word(e, derive_from_pq_tests[tst].e))
        && TEST_true(RSA_set0_factors(key, p, q));
    if (!ret) {
        BN_free(p);
        BN_free(q);
        goto end;
    }

    ret = TEST_int_le(ossl_rsa_sp800_56b_derive_params_from_pq(key, 8, e, ctx), 0);
end:
    BN_free(e);
    RSA_free(key);
    BN_CTX_free(ctx);
    return ret;
}

static int test_pq_diff(void)
{
    int ret = 0;
    BIGNUM *tmp = NULL, *p = NULL, *q = NULL;

    ret = TEST_ptr(tmp = BN_new())
        && TEST_ptr(p = BN_new())
        && TEST_ptr(q = BN_new())
        /* |1-(2+1)| > 2^1 */
        && TEST_true(BN_set_word(p, 1))
        && TEST_true(BN_set_word(q, 1 + 2))
        && TEST_false(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
        /* Check |p - q| > 2^(nbits/2 - 100) */
        && TEST_true(BN_set_word(q, 1 + 3))
        && TEST_true(ossl_rsa_check_pminusq_diff(tmp, p, q, 202))
        && TEST_true(BN_set_word(p, 1 + 3))
        && TEST_true(BN_set_word(q, 1))
        && TEST_true(ossl_rsa_check_pminusq_diff(tmp, p, q, 202));
    BN_free(p);
    BN_free(q);
    BN_free(tmp);
    return ret;
```

