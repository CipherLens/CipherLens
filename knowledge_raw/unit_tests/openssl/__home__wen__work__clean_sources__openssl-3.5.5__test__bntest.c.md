# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/bntest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
{
    BIGNUM *ret;
    BN_ULONG word;
    int st = 0;

    if (!TEST_ptr(ret = getBN(s, attribute))
        || !TEST_ulong_le(word = BN_get_word(ret), INT_MAX))
        goto err;

    *out = (int)word;
    st = 1;
err:
    BN_free(ret);
    return st;
}

static int equalBN(const char *op, const BIGNUM *expected, const BIGNUM *actual)
{
    if (BN_cmp(expected, actual) == 0)
        return 1;

    TEST_error("unexpected %s value", op);
    TEST_BN_eq(expected, actual);
    return 0;
}

/*
 * Return a "random" flag for if a BN should be negated.
 */
static int rand_neg(void)
{
    static unsigned int neg = 0;
    static int sign[8] = { 0, 0, 0, 1, 1, 0, 1, 1 };

    return sign[(neg++) % 8];
}

static int test_swap(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
```

## Call pattern 2

```c
{
    static unsigned int neg = 0;
    static int sign[8] = { 0, 0, 0, 1, 1, 0, 1, 1 };

    return sign[(neg++) % 8];
}

static int test_swap(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int top, cond, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 1, 0))
            && TEST_true(BN_bntest_rand(b, 1024, 1, 0))
            && TEST_ptr(BN_copy(c, a))
            && TEST_ptr(BN_copy(d, b))))
        goto err;
    top = BN_num_bits(a) / BN_BITS2;

    /* regular swap */
    BN_swap(a, b);
    if (!equalBN("swap", a, d)
        || !equalBN("swap", b, c))
        goto err;

    /* regular swap: same pointer */
    BN_swap(a, a);
    if (!equalBN("swap with same pointer", a, d))
        goto err;

    /* conditional swap: true */
    cond = 1;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap true", a, c)
```

## Call pattern 3

```c
static unsigned int neg = 0;
    static int sign[8] = { 0, 0, 0, 1, 1, 0, 1, 1 };

    return sign[(neg++) % 8];
}

static int test_swap(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int top, cond, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 1, 0))
            && TEST_true(BN_bntest_rand(b, 1024, 1, 0))
            && TEST_ptr(BN_copy(c, a))
            && TEST_ptr(BN_copy(d, b))))
        goto err;
    top = BN_num_bits(a) / BN_BITS2;

    /* regular swap */
    BN_swap(a, b);
    if (!equalBN("swap", a, d)
        || !equalBN("swap", b, c))
        goto err;

    /* regular swap: same pointer */
    BN_swap(a, a);
    if (!equalBN("swap with same pointer", a, d))
        goto err;

    /* conditional swap: true */
    cond = 1;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap true", a, c)
        || !equalBN("cswap true", b, d))
```

## Call pattern 4

```c
static int sign[8] = { 0, 0, 0, 1, 1, 0, 1, 1 };

    return sign[(neg++) % 8];
}

static int test_swap(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int top, cond, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 1, 0))
            && TEST_true(BN_bntest_rand(b, 1024, 1, 0))
            && TEST_ptr(BN_copy(c, a))
            && TEST_ptr(BN_copy(d, b))))
        goto err;
    top = BN_num_bits(a) / BN_BITS2;

    /* regular swap */
    BN_swap(a, b);
    if (!equalBN("swap", a, d)
        || !equalBN("swap", b, c))
        goto err;

    /* regular swap: same pointer */
    BN_swap(a, a);
    if (!equalBN("swap with same pointer", a, d))
        goto err;

    /* conditional swap: true */
    cond = 1;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap true", a, c)
        || !equalBN("cswap true", b, d))
        goto err;
```

## Call pattern 5

```c
return sign[(neg++) % 8];
}

static int test_swap(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int top, cond, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 1, 0))
            && TEST_true(BN_bntest_rand(b, 1024, 1, 0))
            && TEST_ptr(BN_copy(c, a))
            && TEST_ptr(BN_copy(d, b))))
        goto err;
    top = BN_num_bits(a) / BN_BITS2;

    /* regular swap */
    BN_swap(a, b);
    if (!equalBN("swap", a, d)
        || !equalBN("swap", b, c))
        goto err;

    /* regular swap: same pointer */
    BN_swap(a, a);
    if (!equalBN("swap with same pointer", a, d))
        goto err;

    /* conditional swap: true */
    cond = 1;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap true", a, c)
        || !equalBN("cswap true", b, d))
        goto err;
```

## Call pattern 6

```c
goto err;

    cond = 0;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap false, flags", a, c)
        || !equalBN("cswap false, flags", b, d)
        || !TEST_true(BN_get_flags(a, BN_FLG_CONSTTIME))
        || !TEST_false(BN_get_flags(b, BN_FLG_CONSTTIME)))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
```

## Call pattern 7

```c
cond = 0;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap false, flags", a, c)
        || !equalBN("cswap false, flags", b, d)
        || !TEST_true(BN_get_flags(a, BN_FLG_CONSTTIME))
        || !TEST_false(BN_get_flags(b, BN_FLG_CONSTTIME)))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
```

## Call pattern 8

```c
cond = 0;
    BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap false, flags", a, c)
        || !equalBN("cswap false, flags", b, d)
        || !TEST_true(BN_get_flags(a, BN_FLG_CONSTTIME))
        || !TEST_false(BN_get_flags(b, BN_FLG_CONSTTIME)))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
```

## Call pattern 9

```c
BN_consttime_swap(cond, a, b, top);
    if (!equalBN("cswap false, flags", a, c)
        || !equalBN("cswap false, flags", b, d)
        || !TEST_true(BN_get_flags(a, BN_FLG_CONSTTIME))
        || !TEST_false(BN_get_flags(b, BN_FLG_CONSTTIME)))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
```

## Call pattern 10

```c
BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
```

## Call pattern 11

```c
BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
```

## Call pattern 12

```c
BN_free(c);
    BN_free(d);
    return st;
}

static int test_sub(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
```

## Call pattern 13

```c
goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
```

## Call pattern 14

```c
for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 512, 0, 0)))
                && TEST_ptr(BN_copy(b, a))
                && TEST_int_ne(BN_set_bit(a, i), 0)
                && TEST_true(BN_add_word(b, i)))
                goto err;
        } else {
            if (!TEST_true(BN_bntest_rand(b, 400 + i - NUM1, 0, 0)))
                goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
```

## Call pattern 15

```c
goto err;
            BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
```

## Call pattern 16

```c
BN_set_negative(a, rand_neg());
            BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
```

## Call pattern 17

```c
BN_set_negative(b, rand_neg());
        }
        if (!(TEST_true(BN_sub(c, a, b))
                && TEST_true(BN_add(c, c, b))
                && TEST_true(BN_sub(c, c, a))
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
```

## Call pattern 18

```c
BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
```

## Call pattern 19

```c
BN_free(b);
    BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
```

## Call pattern 20

```c
BN_free(c);
    return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
```

## Call pattern 21

```c
return st;
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
```

## Call pattern 22

```c
}

static int test_div_recip(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    BN_RECP_CTX *recp = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(recp = BN_RECP_CTX_new()))
        goto err;

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
```

## Call pattern 23

```c
for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
```

## Call pattern 24

```c
for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            if (!(TEST_true(BN_bntest_rand(a, 400, 0, 0))
                    && TEST_ptr(BN_copy(b, a))
                    && TEST_true(BN_lshift(a, a, i))
                    && TEST_true(BN_add_word(a, i))))
                goto err;
        } else {
            if (!(TEST_true(BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0))))
                goto err;
        }
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};
```

## Call pattern 25

```c
BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
```

## Call pattern 26

```c
BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
```

## Call pattern 27

```c
if (!(TEST_true(BN_RECP_CTX_set(recp, b, ctx))
                && TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
```

## Call pattern 28

```c
&& TEST_true(BN_div_recp(d, c, a, recp, ctx))
                && TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}
```

## Call pattern 29

```c
&& TEST_true(BN_mul(e, d, b, ctx))
                && TEST_true(BN_add(d, e, c))
                && TEST_true(BN_sub(d, d, a))
                && TEST_BN_eq_zero(d)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return st;
}

static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}
```

## Call pattern 30

```c
static struct {
    int n, divisor, result, remainder;
} signed_mod_tests[] = {
    { 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}

static int test_signed_mod_replace_ab(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
```

## Call pattern 31

```c
{ 10, 3, 3, 1 },
    { -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}

static int test_signed_mod_replace_ab(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
```

## Call pattern 32

```c
{ -10, 3, -3, -1 },
    { 10, -3, -3, 1 },
    { -10, -3, 3, -1 },
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}

static int test_signed_mod_replace_ab(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
```

## Call pattern 33

```c
};

static BIGNUM *set_signed_bn(int value)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL)
        return NULL;
    if (!BN_set_word(bn, value < 0 ? -value : value)) {
        BN_free(bn);
        return NULL;
    }
    BN_set_negative(bn, value < 0);
    return bn;
}

static int test_signed_mod_replace_ab(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_signed_mod_replace_ba(int n)
```

## Call pattern 34

```c
if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_signed_mod_replace_ba(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
```

## Call pattern 35

```c
if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_signed_mod_replace_ba(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}
```

## Call pattern 36

```c
|| !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_signed_mod_replace_ba(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}
```

## Call pattern 37

```c
|| !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(a, b, a, b, ctx))
        && TEST_BN_eq(a, c)
        && TEST_BN_eq(b, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_signed_mod_replace_ba(int n)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    int st = 0;

    if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
```

## Call pattern 38

```c
if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
```

## Call pattern 39

```c
if (!TEST_ptr(a = set_signed_bn(signed_mod_tests[n].n))
        || !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
```

## Call pattern 40

```c
|| !TEST_ptr(b = set_signed_bn(signed_mod_tests[n].divisor))
        || !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
```

## Call pattern 41

```c
|| !TEST_ptr(c = set_signed_bn(signed_mod_tests[n].result))
        || !TEST_ptr(d = set_signed_bn(signed_mod_tests[n].remainder)))
        goto err;

    if (TEST_true(BN_div(b, a, a, b, ctx))
        && TEST_BN_eq(b, c)
        && TEST_BN_eq(a, d))
        st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
```

## Call pattern 42

```c
BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
```

## Call pattern 43

```c
BN_free(b);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
```

## Call pattern 44

```c
BN_free(c);
    BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
```

## Call pattern 45

```c
BN_free(d);
    return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}
```

## Call pattern 46

```c
return st;
}

static int test_mod(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;
    int st = 0, i;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}
```

## Call pattern 47

```c
if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
```

## Call pattern 48

```c
|| !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_bntest_rand(b, 450 + i * 10, 0, 0))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
```

## Call pattern 49

```c
BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};
```

## Call pattern 50

```c
BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};

static const char *bn2strings[] = {
```

## Call pattern 51

```c
if (!(TEST_true(BN_mod(c, a, b, ctx))
                && TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};

static const char *bn2strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
```

## Call pattern 52

```c
&& TEST_true(BN_div(d, e, a, b, ctx))
                && TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};

static const char *bn2strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
```

## Call pattern 53

```c
&& TEST_BN_eq(e, c)
                && TEST_true(BN_mul(c, d, b, ctx))
                && TEST_true(BN_add(d, c, e))
                && TEST_BN_eq(d, a)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};

static const char *bn2strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
```

## Call pattern 54

```c
/*
 * Test constant-time modular exponentiation with 1024-bit inputs, which on
 * x86_64 cause a different code branch to be taken.
 */
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
```

## Call pattern 55

```c
/*
 * Test constant-time modular exponentiation with 1024-bit inputs, which on
 * x86_64 cause a different code branch to be taken.
 */
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
```

## Call pattern 56

```c
* Test constant-time modular exponentiation with 1024-bit inputs, which on
 * x86_64 cause a different code branch to be taken.
 */
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
```

## Call pattern 57

```c
* x86_64 cause a different code branch to be taken.
 */
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
                "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
```

## Call pattern 58

```c
*/
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
                "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
                "E16E57FB4EDB9AE10A0CEFCDC28A894F689A128379DB279D48A2E20849D68593"
```

## Call pattern 59

```c
static int test_modexp_mont5(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
                "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
                "E16E57FB4EDB9AE10A0CEFCDC28A894F689A128379DB279D48A2E20849D68593"
                "9B7803BCF46CEBF5C533FB0DD35B080593DE5472E3FE5DB951B8BFF9B4CB8F03"
```

## Call pattern 60

```c
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
                "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
                "E16E57FB4EDB9AE10A0CEFCDC28A894F689A128379DB279D48A2E20849D68593"
                "9B7803BCF46CEBF5C533FB0DD35B080593DE5472E3FE5DB951B8BFF9B4CB8F03"
                "9CC638A5EE8CDD703719F8000E6A9F63BEED5F2FCD52FF293EA05A251BB4AB81"))
```

## Call pattern 61

```c
BIGNUM *a = NULL, *p = NULL, *m = NULL, *d = NULL, *e = NULL;
    BIGNUM *b = NULL, *n = NULL, *c = NULL;
    BN_MONT_CTX *mont = NULL;
    int st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    /* must be odd for montgomery */
    if (!(TEST_true(BN_bntest_rand(m, 1024, 0, 1))
            /* Zero exponent */
            && TEST_true(BN_bntest_rand(a, 1024, 0, 0))))
        goto err;
    BN_zero(p);

    if (!TEST_true(BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)))
        goto err;
    if (!TEST_BN_eq_one(d))
        goto err;

    /* Regression test for carry bug in mulx4x_mont */
    if (!(TEST_true(BN_hex2bn(&a,
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"
              "7878787878787878787878787878787878787878787878787878787878787878"))
            && TEST_true(BN_hex2bn(&b,
                "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
                "E16E57FB4EDB9AE10A0CEFCDC28A894F689A128379DB279D48A2E20849D68593"
                "9B7803BCF46CEBF5C533FB0DD35B080593DE5472E3FE5DB951B8BFF9B4CB8F03"
                "9CC638A5EE8CDD703719F8000E6A9F63BEED5F2FCD52FF293EA05A251BB4AB81"))
            && TEST_true(BN_hex2bn(&n,
```

## Call pattern 62

```c
goto err;

    if (!(TEST_true(BN_MONT_CTX_set(mont, n, ctx))
            && TEST_true(BN_mod_mul_montgomery(c, a, b, mont, ctx))
            && TEST_true(BN_mod_mul_montgomery(d, b, a, mont, ctx))
            && TEST_BN_eq(c, d)))
        goto err;

    /* Regression test for carry bug in sqr[x]8x_mont */
    if (!(TEST_true(parse_bigBN(&n, bn1strings))
            && TEST_true(parse_bigBN(&a, bn2strings))))
        goto err;
    BN_free(b);
    if (!(TEST_ptr(b = BN_dup(a))
            && TEST_true(BN_MONT_CTX_set(mont, n, ctx))
            && TEST_true(BN_mod_mul_montgomery(c, a, a, mont, ctx))
            && TEST_true(BN_mod_mul_montgomery(d, a, b, mont, ctx))
            && TEST_BN_eq(c, d)))
        goto err;

    /* Regression test for carry bug in bn_sqrx8x_internal */
    {
        static const char *ahex[] = {
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8FFEADBCFC4DAE7FFF908E92820306B",
            "9544D954000000006C0000000000000000000000000000000000000000000000",
            "00000000000000000000FF030202FFFFF8FFEBDBCFC4DAE7FFF908E92820306B",
            "9544D954000000006C000000FF0302030000000000FFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01FC00FF02FFFFFFFF",
            "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00FCFD",
            "FCFFFFFFFFFF000000000000000000FF0302030000000000FFFFFFFFFFFFFFFF",
            "FF00FCFDFDFF030202FF00000000FFFFFFFFFFFFFFFFFF00FCFDFCFFFFFFFFFF",
            NULL
        };
        static const char *nhex[] = {
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
```

## Call pattern 63

```c
"00000010000000006C000000000000000000000000FFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFF000000000000000000000000000000000000FFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            NULL
        };

        if (!(TEST_true(parse_bigBN(&a, ahex))
                && TEST_true(parse_bigBN(&n, nhex))))
            goto err;
    }
    BN_free(b);
    if (!(TEST_ptr(b = BN_dup(a))
            && TEST_true(BN_MONT_CTX_set(mont, n, ctx))))
        goto err;

    if (!TEST_true(BN_mod_mul_montgomery(c, a, a, mont, ctx))
        || !TEST_true(BN_mod_mul_montgomery(d, a, b, mont, ctx))
        || !TEST_BN_eq(c, d))
        goto err;

    /* Regression test for bug in BN_from_montgomery_word */
    if (!(TEST_true(BN_hex2bn(&a,
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
            && TEST_true(BN_hex2bn(&n,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
            && TEST_true(BN_MONT_CTX_set(mont, n, ctx))
            && TEST_false(BN_mod_mul_montgomery(d, a, a, mont, ctx))))
        goto err;

    /* Regression test for bug in rsaz_1024_mul_avx2 */
    if (!(TEST_true(BN_hex2bn(&a,
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2020202020DF"))
```

## Call pattern 64

```c
/* Finally, some regular test vectors. */
    if (!(TEST_true(BN_bntest_rand(e, 1024, 0, 0))
            && TEST_true(BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
            && TEST_true(BN_mod_exp_simple(a, e, p, m, ctx))
            && TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
```

## Call pattern 65

```c
/* Finally, some regular test vectors. */
    if (!(TEST_true(BN_bntest_rand(e, 1024, 0, 0))
            && TEST_true(BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
            && TEST_true(BN_mod_exp_simple(a, e, p, m, ctx))
            && TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
```

## Call pattern 66

```c
if (!(TEST_true(BN_bntest_rand(e, 1024, 0, 0))
            && TEST_true(BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
            && TEST_true(BN_mod_exp_simple(a, e, p, m, ctx))
            && TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
```

## Call pattern 67

```c
&& TEST_true(BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
            && TEST_true(BN_mod_exp_simple(a, e, p, m, ctx))
            && TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
```

## Call pattern 68

```c
&& TEST_true(BN_mod_exp_simple(a, e, p, m, ctx))
            && TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
```

## Call pattern 69

```c
&& TEST_BN_eq(a, d)))
        goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
```

## Call pattern 70

```c
goto err;

    st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
```

## Call pattern 71

```c
st = 1;

err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
```

## Call pattern 72

```c
BN_free(b);
    BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}
```

## Call pattern 73

```c
BN_free(n);
    BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}
```

## Call pattern 74

```c
BN_free(c);
    return st;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add(void)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
```

## Call pattern 75

```c
BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
```

## Call pattern 76

```c
int i, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(c = BN_new()))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!(TEST_true(BN_rand(a, 512, 0, 0))
                && TEST_ptr(BN_copy(b, BN_value_one()))))
            goto err;
        BN_set_negative(a, rand_neg());
        BN_set_negative(b, rand_neg());
        if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
        || !TEST_ptr(c = BN_new())
```

## Call pattern 77

```c
if (!(TEST_true(BN_GF2m_add(c, a, b))
                /* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_GF2m_arr2poly(p0, b[0]))
            && TEST_true(BN_GF2m_arr2poly(p1, b[1]))))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!TEST_true(BN_bntest_rand(a, 1024, 0, 0)))
            goto err;
        for (j = 0; j < 2; j++) {
            if (!(TEST_true(BN_GF2m_mod(c, a, b[j]))
```

## Call pattern 78

```c
/* Test that two added values have the correct parity. */
                && TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_GF2m_arr2poly(p0, b[0]))
            && TEST_true(BN_GF2m_arr2poly(p1, b[1]))))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!TEST_true(BN_bntest_rand(a, 1024, 0, 0)))
            goto err;
        for (j = 0; j < 2; j++) {
            if (!(TEST_true(BN_GF2m_mod(c, a, b[j]))
                    && TEST_true(BN_GF2m_add(d, a, c))
```

## Call pattern 79

```c
&& TEST_false((BN_is_odd(a) && BN_is_odd(c))
                    || (!BN_is_odd(a) && !BN_is_odd(c)))))
            goto err;
        if (!(TEST_true(BN_GF2m_add(c, c, c))
                /* Test that c + c = 0. */
                && TEST_BN_eq_zero(c)))
            goto err;
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_GF2m_arr2poly(p0, b[0]))
            && TEST_true(BN_GF2m_arr2poly(p1, b[1]))))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!TEST_true(BN_bntest_rand(a, 1024, 0, 0)))
            goto err;
        for (j = 0; j < 2; j++) {
            if (!(TEST_true(BN_GF2m_mod(c, a, b[j]))
                    && TEST_true(BN_GF2m_add(d, a, c))
                    && TEST_true(BN_GF2m_mod(e, d, b[j]))
```

## Call pattern 80

```c
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod(void)
{
    BIGNUM *a = NULL, *b[2] = { NULL, NULL }, *c = NULL, *d = NULL, *e = NULL;
    int i, j, st = 0;

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(b[0] = BN_new())
        || !TEST_ptr(b[1] = BN_new())
        || !TEST_ptr(c = BN_new())
        || !TEST_ptr(d = BN_new())
        || !TEST_ptr(e = BN_new()))
        goto err;

    if (!(TEST_true(BN_GF2m_arr2poly(p0, b[0]))
            && TEST_true(BN_GF2m_arr2poly(p1, b[1]))))
        goto err;

    for (i = 0; i < NUM0; i++) {
        if (!TEST_true(BN_bntest_rand(a, 1024, 0, 0)))
            goto err;
        for (j = 0; j < 2; j++) {
            if (!(TEST_true(BN_GF2m_mod(c, a, b[j]))
                    && TEST_true(BN_GF2m_add(d, a, c))
                    && TEST_true(BN_GF2m_mod(e, d, b[j]))
                    /* Test that a + (a mod p) mod p == 0. */
                    && TEST_BN_eq_zero(e)))
                goto err;
        }
    }
    st = 1;
err:
    BN_free(a);
    BN_free(b[0]);
```

