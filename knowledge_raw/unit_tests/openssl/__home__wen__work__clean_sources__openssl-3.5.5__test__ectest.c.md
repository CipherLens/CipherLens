# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/ectest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
static size_t crv_len = 0;
static EC_builtin_curve *curves = NULL;

/* test multiplication with group order, long and negative scalars */
static int group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1 = NULL, *n2 = NULL, *order = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL, *S = NULL;
    const EC_POINT *G = NULL;
    BN_CTX *ctx = NULL;
    int i = 0, r = 0;

    if (!TEST_ptr(n1 = BN_new())
        || !TEST_ptr(n2 = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(G = EC_GROUP_get0_generator(group))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(S = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(EC_GROUP_get_order(group, order, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
#ifndef OPENSSL_NO_DEPRECATED_3_0
        || !TEST_true(EC_GROUP_precompute_mult(group, ctx))
#endif
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(BN_one(n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))
        || !TEST_true(BN_sub(n1, order, n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_invert(group, Q, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
        goto err;
```

## Call pattern 2

```c
static EC_builtin_curve *curves = NULL;

/* test multiplication with group order, long and negative scalars */
static int group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1 = NULL, *n2 = NULL, *order = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL, *S = NULL;
    const EC_POINT *G = NULL;
    BN_CTX *ctx = NULL;
    int i = 0, r = 0;

    if (!TEST_ptr(n1 = BN_new())
        || !TEST_ptr(n2 = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(G = EC_GROUP_get0_generator(group))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(S = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(EC_GROUP_get_order(group, order, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
#ifndef OPENSSL_NO_DEPRECATED_3_0
        || !TEST_true(EC_GROUP_precompute_mult(group, ctx))
#endif
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(BN_one(n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))
        || !TEST_true(BN_sub(n1, order, n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_invert(group, Q, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
        goto err;
```

## Call pattern 3

```c
/* test multiplication with group order, long and negative scalars */
static int group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1 = NULL, *n2 = NULL, *order = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL, *S = NULL;
    const EC_POINT *G = NULL;
    BN_CTX *ctx = NULL;
    int i = 0, r = 0;

    if (!TEST_ptr(n1 = BN_new())
        || !TEST_ptr(n2 = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(G = EC_GROUP_get0_generator(group))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(S = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(EC_GROUP_get_order(group, order, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
#ifndef OPENSSL_NO_DEPRECATED_3_0
        || !TEST_true(EC_GROUP_precompute_mult(group, ctx))
#endif
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(BN_one(n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))
        || !TEST_true(BN_sub(n1, order, n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_invert(group, Q, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
        goto err;

    for (i = 1; i <= 2; i++) {
```

## Call pattern 4

```c
|| !TEST_true(BN_sub(n1, order, n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_invert(group, Q, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
        goto err;

    for (i = 1; i <= 2; i++) {
#ifndef OPENSSL_NO_DEPRECATED_3_0
        const BIGNUM *scalars[6];
        const EC_POINT *points[6];
#endif

        if (!TEST_true(BN_set_word(n1, i))
            /*
             * If i == 1, P will be the predefined generator for which
             * EC_GROUP_precompute_mult has set up precomputation.
             */
            || !TEST_true(EC_POINT_mul(group, P, n1, NULL, NULL, ctx))
            || (i == 1 && !TEST_int_eq(0, EC_POINT_cmp(group, P, G, ctx)))
            || !TEST_true(BN_one(n1))
            /* n1 = 1 - order */
            || !TEST_true(BN_sub(n1, n1, order))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n1, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = 1 + order */
            || !TEST_true(BN_add(n2, order, BN_value_one()))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
            || !TEST_true(BN_mul(n2, n1, n2, ctx))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
            goto err;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            /* Add P to verify the result. */
```

## Call pattern 5

```c
/* n2 = 1 + order */
            || !TEST_true(BN_add(n2, order, BN_value_one()))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
            || !TEST_true(BN_mul(n2, n1, n2, ctx))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
            goto err;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            /* Add P to verify the result. */
            || !TEST_true(EC_POINT_add(group, Q, Q, P, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, Q))
            || !TEST_false(EC_POINT_is_at_infinity(group, P)))
            goto err;

#ifndef OPENSSL_NO_DEPRECATED_3_0
        /* Exercise EC_POINTs_mul, including corner cases. */
        scalars[0] = scalars[1] = BN_value_one();
        points[0] = points[1] = P;

        if (!TEST_true(EC_POINTs_mul(group, R, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_dbl(group, S, points[0], ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, R, S, ctx)))
            goto err;

        scalars[0] = n1;
        points[0] = Q; /* => infinity */
        scalars[1] = n2;
        points[1] = P; /* => -P */
        scalars[2] = n1;
        points[2] = Q; /* => infinity */
        scalars[3] = n2;
        points[3] = Q; /* => infinity */
        scalars[4] = n1;
        points[4] = P; /* => P */
```

## Call pattern 6

```c
goto err;
#endif
    }

    r = 1;
err:
    if (r == 0 && i != 0)
        TEST_info(i == 1 ? "allowing precomputation" : "without precomputation");
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
    return r;
}

static int prime_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *scalar3 = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
```

## Call pattern 7

```c
#endif
    }

    r = 1;
err:
    if (r == 0 && i != 0)
        TEST_info(i == 1 ? "allowing precomputation" : "without precomputation");
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
    return r;
}

static int prime_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *scalar3 = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
```

## Call pattern 8

```c
}

    r = 1;
err:
    if (r == 0 && i != 0)
        TEST_info(i == 1 ? "allowing precomputation" : "without precomputation");
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
    return r;
}

static int prime_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *scalar3 = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        || !TEST_ptr(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))
```

## Call pattern 9

```c
EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        || !TEST_ptr(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 = x^3 + a*x + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
```

## Call pattern 10

```c
EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        || !TEST_ptr(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 = x^3 + a*x + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
```

## Call pattern 11

```c
BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
#endif
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        || !TEST_ptr(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 = x^3 + a*x + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
```

## Call pattern 12

```c
test_output_bignum("b", b);
    test_output_bignum("p", p);

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx)))
        goto err;

    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P)) {
            TEST_note("     point at infinity");
        } else {
            if (!TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y,
                    ctx)))
```

## Call pattern 13

```c
test_output_bignum("p", p);

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx)))
        goto err;

    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P)) {
            TEST_note("     point at infinity");
        } else {
            if (!TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y,
                    ctx)))
                goto err;
```

## Call pattern 14

```c
buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx)))
        goto err;

    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P)) {
            TEST_note("     point at infinity");
        } else {
            if (!TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y,
                    ctx)))
                goto err;
```

## Call pattern 15

```c
buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx)))
        goto err;

    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P)) {
            TEST_note("     point at infinity");
        } else {
            if (!TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y,
                    ctx)))
                goto err;

            test_output_bignum("x", x);
```

## Call pattern 16

```c
scalars[0] = y; /* (group order + 1)/2, so y*Q + y*Q = Q */
    scalars[1] = y;

    /* z is still the group order */
    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINTs_mul(group, R, z, 2, points, scalars, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, R, Q, ctx))
        || !TEST_true(BN_rand(y, BN_num_bits(y), 0, 0))
        || !TEST_true(BN_add(z, z, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = y;
    scalars[1] = z; /* z = -(order + y) */

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
        || !TEST_true(BN_add(z, x, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = x;
    scalars[1] = y;
    scalars[2] = z; /* z = -(x+y) */

    if (!TEST_ptr(scalar3 = BN_new()))
        goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
```

## Call pattern 17

```c
|| !TEST_true(BN_rand(y, BN_num_bits(y), 0, 0))
        || !TEST_true(BN_add(z, z, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = y;
    scalars[1] = z; /* z = -(order + y) */

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
        || !TEST_true(BN_add(z, x, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = x;
    scalars[1] = y;
    scalars[2] = z; /* z = -(x+y) */

    if (!TEST_ptr(scalar3 = BN_new()))
        goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
```

## Call pattern 18

```c
scalars[1] = z; /* z = -(order + y) */

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
        || !TEST_true(BN_add(z, x, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = x;
    scalars[1] = y;
    scalars[2] = z; /* z = -(x+y) */

    if (!TEST_ptr(scalar3 = BN_new()))
        goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}
```

## Call pattern 19

```c
goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
```

## Call pattern 20

```c
BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
```

## Call pattern 21

```c
scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
```

## Call pattern 22

```c
#endif
    TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
```

## Call pattern 23

```c
TEST_note(" ok\n");
    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
        "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
```

## Call pattern 24

```c
r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
        "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
        "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
```

## Call pattern 25

```c
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
        "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
        "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
        1, "04000000000000000000020108A2E0CC0D99F8A5EF", "2", 163 },
```

## Call pattern 26

```c
BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);
    return r;
}

#ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
        "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
        "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
        1, "04000000000000000000020108A2E0CC0D99F8A5EF", "2", 163 },
    /* Curve B-163 (FIPS PUB 186-2, App. 6) */
```

## Call pattern 27

```c
BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
```

## Call pattern 28

```c
BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
```

## Call pattern 29

```c
BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
```

## Call pattern 30

```c
EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
```

## Call pattern 31

```c
EC_POINT *P = NULL, *Q = NULL, *R = NULL;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
        || !TEST_true(BN_hex2bn(&cof, test->cof))
```

## Call pattern 32

```c
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
        || !TEST_true(BN_hex2bn(&cof, test->cof))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, cof))
```

## Call pattern 33

```c
const EC_POINT *points[3];
    const BIGNUM *scalars[3];
#endif
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone, ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x,
            test->y_bit,
            ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
        || !TEST_true(BN_hex2bn(&cof, test->cof))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, cof))
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, ctx)))
```

## Call pattern 34

```c
scalars[1] = y;

        /* z is still the group order */
        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINTs_mul(group, R, z, 2, points, scalars, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, R, Q, ctx)))
            goto err;

        if (!TEST_true(BN_rand(y, BN_num_bits(y), 0, 0))
            || !TEST_true(BN_add(z, z, y)))
            goto err;
        BN_set_negative(z, 1);
        scalars[0] = y;
        scalars[1] = z; /* z = -(order + y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;

        if (!TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
            || !TEST_true(BN_add(z, x, y)))
            goto err;
        BN_set_negative(z, 1);
        scalars[0] = x;
        scalars[1] = y;
        scalars[2] = z; /* z = -(x+y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
```

## Call pattern 35

```c
goto err;
        BN_set_negative(z, 1);
        scalars[0] = y;
        scalars[1] = z; /* z = -(order + y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;

        if (!TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
            || !TEST_true(BN_add(z, x, y)))
            goto err;
        BN_set_negative(z, 1);
        scalars[0] = x;
        scalars[1] = y;
        scalars[2] = z; /* z = -(x+y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}
```

## Call pattern 36

```c
scalars[1] = y;
        scalars[2] = z; /* z = -(x+y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
```

## Call pattern 37

```c
scalars[2] = z; /* z = -(x+y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
```

## Call pattern 38

```c
if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
```

## Call pattern 39

```c
if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
```

## Call pattern 40

```c
|| !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
```

## Call pattern 41

```c
goto err;
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
```

## Call pattern 42

```c
#endif
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;
```

## Call pattern 43

```c
}

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;
```

## Call pattern 44

```c
static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;

    if (!TEST_ptr(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 + x*y = x^3 + a*x^2 + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
```

## Call pattern 45

```c
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;

    if (!TEST_ptr(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 + x*y = x^3 + a*x^2 + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
```

## Call pattern 46

```c
BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;

    if (!TEST_ptr(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))
        || !TEST_true(EC_GROUP_get_curve(group, p, a, b, ctx)))
        goto err;

    TEST_info("Curve defined by Weierstrass equation");
    TEST_note("     y^2 + x*y = x^3 + a*x^2 + b (mod p)");
    test_output_bignum("a", a);
    test_output_bignum("b", b);
    test_output_bignum("p", p);

    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
```

## Call pattern 47

```c
if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx))
#else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, Q, x, y, ctx))
#endif
    )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
#endif
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
```

## Call pattern 48

```c
if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx))
#else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, Q, x, y, ctx))
#endif
    )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
#endif
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
```

## Call pattern 49

```c
|| !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx))
#else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, Q, x, y, ctx))
#endif
    )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
#endif
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
```

## Call pattern 50

```c
|| !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx))
#else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, Q, x, y, ctx))
#endif
    )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
#endif
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
```

## Call pattern 51

```c
|| !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, Q, x, 1, ctx))
#else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, Q, x, y, ctx))
#endif
    )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates(group, Q, x, y, ctx)))
            goto err;
#endif
        TEST_info("Point is not on curve");
        test_output_bignum("x", x);
        test_output_bignum("y", y);
        goto err;
    }

    TEST_note("A cyclic subgroup:");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;
```

## Call pattern 52

```c
buf, len);
#endif

    if (!TEST_true(EC_POINT_invert(group, P, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx)))
        goto err;

    TEST_note("\n");

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
```

## Call pattern 53

```c
#endif

    if (!TEST_true(EC_POINT_invert(group, P, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx)))
        goto err;

    TEST_note("\n");

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
```

## Call pattern 54

```c
if (!TEST_true(EC_POINT_invert(group, P, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx)))
        goto err;

    TEST_note("\n");

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
```

## Call pattern 55

```c
TEST_note("\n");

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
        || !TEST_ptr(buf = OPENSSL_malloc(len))
        || !TEST_size_t_eq(len, EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, buf, len, NULL)))
        goto err;

    r = 1;
```

## Call pattern 56

```c
r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
        || !TEST_ptr(buf = OPENSSL_malloc(len))
        || !TEST_size_t_eq(len, EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, buf, len, NULL)))
        goto err;

    r = 1;
```

## Call pattern 57

```c
r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
        || !TEST_ptr(buf = OPENSSL_malloc(len))
        || !TEST_size_t_eq(len, EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, buf, len, NULL)))
        goto err;

    r = 1;

    /* buf contains a valid hybrid point, check that we can decode it. */
```

## Call pattern 58

```c
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
        || !TEST_ptr(buf = OPENSSL_malloc(len))
        || !TEST_size_t_eq(len, EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, buf, len, NULL)))
        goto err;

    r = 1;

    /* buf contains a valid hybrid point, check that we can decode it. */
    if (!TEST_true(EC_POINT_oct2point(group, point, buf, len, NULL)))
```

## Call pattern 59

```c
BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}

static int hybrid_point_encoding_test(void)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int r = 0;

    if (!TEST_true(BN_dec2bn(&x, "0"))
        || !TEST_true(BN_dec2bn(&y, "1"))
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sect571k1))
        || !TEST_ptr(point = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        || !TEST_size_t_ne(0, (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, NULL, 0, NULL)))
        || !TEST_ptr(buf = OPENSSL_malloc(len))
        || !TEST_size_t_eq(len, EC_POINT_point2oct(group, point, POINT_CONVERSION_HYBRID, buf, len, NULL)))
        goto err;

    r = 1;

    /* buf contains a valid hybrid point, check that we can decode it. */
    if (!TEST_true(EC_POINT_oct2point(group, point, buf, len, NULL)))
        r = 0;
```

## Call pattern 60

```c
r = 1;

    /* buf contains a valid hybrid point, check that we can decode it. */
    if (!TEST_true(EC_POINT_oct2point(group, point, buf, len, NULL)))
        r = 0;

    /* Flip the y_bit and verify that the invalid encoding is rejected. */
    buf[0] ^= 1;
    if (!TEST_false(EC_POINT_oct2point(group, point, buf, len, NULL)))
        r = 0;

err:
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    OPENSSL_free(buf);
    return r;
}
#endif

static int internal_curve_test(int n)
{
    EC_GROUP *group = NULL;
    int nid = curves[n].nid;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("EC_GROUP_new_curve_name() failed with curve %s\n",
            OBJ_nid2sn(nid));
        return 0;
    }
    if (!TEST_true(EC_GROUP_check(group, NULL))) {
        TEST_info("EC_GROUP_check() failed with curve %s\n", OBJ_nid2sn(nid));
        EC_GROUP_free(group);
        return 0;
    }
    EC_GROUP_free(group);
    return 1;
}
```

## Call pattern 61

```c
/* buf contains a valid hybrid point, check that we can decode it. */
    if (!TEST_true(EC_POINT_oct2point(group, point, buf, len, NULL)))
        r = 0;

    /* Flip the y_bit and verify that the invalid encoding is rejected. */
    buf[0] ^= 1;
    if (!TEST_false(EC_POINT_oct2point(group, point, buf, len, NULL)))
        r = 0;

err:
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    OPENSSL_free(buf);
    return r;
}
#endif

static int internal_curve_test(int n)
{
    EC_GROUP *group = NULL;
    int nid = curves[n].nid;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("EC_GROUP_new_curve_name() failed with curve %s\n",
            OBJ_nid2sn(nid));
        return 0;
    }
    if (!TEST_true(EC_GROUP_check(group, NULL))) {
        TEST_info("EC_GROUP_check() failed with curve %s\n", OBJ_nid2sn(nid));
        EC_GROUP_free(group);
        return 0;
    }
    EC_GROUP_free(group);
    return 1;
}

static int internal_curve_test_method(int n)
```

## Call pattern 62

```c
secp521r1_group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    if (BN_cmp(secp521r1_field, EC_GROUP_get0_field(secp521r1_group)))
        r = 0;

#ifndef OPENSSL_NO_EC2M
    sect163r2_group = EC_GROUP_new_by_curve_name(NID_sect163r2);
    if (BN_cmp(sect163r2_field, EC_GROUP_get0_field(sect163r2_group)))
        r = 0;
#endif

    EC_GROUP_free(secp521r1_group);
    EC_GROUP_free(sect163r2_group);
    BN_free(secp521r1_field);
    BN_free(sect163r2_field);
    return r;
}

/*
 * nistp_test_params contains magic numbers for testing
 * several NIST curves with characteristic > 3.
 */
struct nistp_test_params {
    const int nid;
    int degree;
    /*
     * Qx, Qy and D are taken from
     * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf
     * Otherwise, values are standard curve parameters from FIPS 180-3
     */
    const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
};

static const struct nistp_test_params nistp_tests_params[] = {
    {
        /* P-224 */
        NID_secp224r1,
        224,
        /* p */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        /* a */
```

## Call pattern 63

```c
if (BN_cmp(secp521r1_field, EC_GROUP_get0_field(secp521r1_group)))
        r = 0;

#ifndef OPENSSL_NO_EC2M
    sect163r2_group = EC_GROUP_new_by_curve_name(NID_sect163r2);
    if (BN_cmp(sect163r2_field, EC_GROUP_get0_field(sect163r2_group)))
        r = 0;
#endif

    EC_GROUP_free(secp521r1_group);
    EC_GROUP_free(sect163r2_group);
    BN_free(secp521r1_field);
    BN_free(sect163r2_field);
    return r;
}

/*
 * nistp_test_params contains magic numbers for testing
 * several NIST curves with characteristic > 3.
 */
struct nistp_test_params {
    const int nid;
    int degree;
    /*
     * Qx, Qy and D are taken from
     * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf
     * Otherwise, values are standard curve parameters from FIPS 180-3
     */
    const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
};

static const struct nistp_test_params nistp_tests_params[] = {
    {
        /* P-224 */
        NID_secp224r1,
        224,
        /* p */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        /* a */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
```

## Call pattern 64

```c
{
    const struct nistp_test_params *test = nistp_tests_params + idx;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
```

## Call pattern 65

```c
const struct nistp_test_params *test = nistp_tests_params + idx;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
```

## Call pattern 66

```c
BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
```

## Call pattern 67

```c
BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
```

## Call pattern 68

```c
BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
```

## Call pattern 69

```c
EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
```

## Call pattern 70

```c
EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, G, x, y, ctx))
```

## Call pattern 71

```c
int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, G, x, y, ctx))
        || !TEST_true(BN_hex2bn(&order, test->order))
```

## Call pattern 72

```c
TEST_note("NIST curve P-%d (optimised implementation):",
        test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new_by_curve_name(test->nid))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_check_prime(p, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
        /*
         * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
         * and therefore setting the coordinates should fail.
         */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
            yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
            ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, G, x, y, ctx))
        || !TEST_true(BN_hex2bn(&order, test->order))
        || !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one()))
```

## Call pattern 73

```c
|| !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one())))
        goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;

    /* regression test for felem_neg bug */
    if (!TEST_true(BN_set_word(m, 32))
        || !TEST_true(BN_set_word(n, 31))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(EC_POINT_invert(NISTP, P, ctx))
        || !TEST_true(EC_POINT_mul(NISTP, Q, m, P, n, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}
```

## Call pattern 74

```c
goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;

    /* regression test for felem_neg bug */
    if (!TEST_true(BN_set_word(m, 32))
        || !TEST_true(BN_set_word(n, 31))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(EC_POINT_invert(NISTP, P, ctx))
        || !TEST_true(EC_POINT_mul(NISTP, Q, m, P, n, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
```

## Call pattern 75

```c
|| !TEST_true(EC_POINT_invert(NISTP, P, ctx))
        || !TEST_true(EC_POINT_mul(NISTP, Q, m, P, n, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
```

## Call pattern 76

```c
|| !TEST_true(EC_POINT_mul(NISTP, Q, m, P, n, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
    0x02,
```

## Call pattern 77

```c
|| !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
    0x02,
    0x01,
```

## Call pattern 78

```c
goto err;

    r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
    0x02,
    0x01,
    0x01,
```

## Call pattern 79

```c
r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
    0x02,
    0x01,
    0x01,
    0x30,
```

## Call pattern 80

```c
r = 1;
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}

static const unsigned char p521_named[] = {
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x23,
};

static const unsigned char p521_explicit[] = {
    0x30,
    0x82,
    0x01,
    0xc3,
    0x02,
    0x01,
    0x01,
    0x30,
    0x4d,
```

