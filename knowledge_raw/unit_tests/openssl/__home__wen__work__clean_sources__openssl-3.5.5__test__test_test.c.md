# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/test_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
|| !TEST(1, TEST_BN_le(c, b))
        || !TEST(0, TEST_BN_le(b, c))
        || !TEST(1, TEST_BN_gt(a, c))
        || !TEST(0, TEST_BN_gt(c, b))
        || !TEST(1, TEST_BN_gt(b, c))
        || !TEST(1, TEST_BN_ge(a, c))
        || !TEST(0, TEST_BN_ge(c, b))
        || !TEST(1, TEST_BN_ge(b, c)))
        goto err;

    r = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return r;
}

static int test_long_output(void)
{
    const char *p = "1234567890123456789012345678901234567890123456789012";
    const char *q = "1234567890klmnopqrs01234567890EFGHIJKLM0123456789XYZ";
    const char *r = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY+"
                    "12345678901234567890123ABC78901234567890123456789012";
    const char *s = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY-"
                    "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    return TEST(0, TEST_str_eq(p, q))
        & TEST(0, TEST_str_eq(q, r))
        & TEST(0, TEST_str_eq(r, s))
        & TEST(0, TEST_mem_eq(r, strlen(r), s, strlen(s)));
}

static int test_long_bignum(void)
{
    int r;
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
```

## Call pattern 2

```c
|| !TEST(0, TEST_BN_le(b, c))
        || !TEST(1, TEST_BN_gt(a, c))
        || !TEST(0, TEST_BN_gt(c, b))
        || !TEST(1, TEST_BN_gt(b, c))
        || !TEST(1, TEST_BN_ge(a, c))
        || !TEST(0, TEST_BN_ge(c, b))
        || !TEST(1, TEST_BN_ge(b, c)))
        goto err;

    r = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return r;
}

static int test_long_output(void)
{
    const char *p = "1234567890123456789012345678901234567890123456789012";
    const char *q = "1234567890klmnopqrs01234567890EFGHIJKLM0123456789XYZ";
    const char *r = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY+"
                    "12345678901234567890123ABC78901234567890123456789012";
    const char *s = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY-"
                    "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    return TEST(0, TEST_str_eq(p, q))
        & TEST(0, TEST_str_eq(q, r))
        & TEST(0, TEST_str_eq(r, s))
        & TEST(0, TEST_mem_eq(r, strlen(r), s, strlen(s)));
}

static int test_long_bignum(void)
{
    int r;
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    const char as[] = "1234567890123456789012345678901234567890123456789012"
```

## Call pattern 3

```c
|| !TEST(1, TEST_BN_gt(a, c))
        || !TEST(0, TEST_BN_gt(c, b))
        || !TEST(1, TEST_BN_gt(b, c))
        || !TEST(1, TEST_BN_ge(a, c))
        || !TEST(0, TEST_BN_ge(c, b))
        || !TEST(1, TEST_BN_ge(b, c)))
        goto err;

    r = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return r;
}

static int test_long_output(void)
{
    const char *p = "1234567890123456789012345678901234567890123456789012";
    const char *q = "1234567890klmnopqrs01234567890EFGHIJKLM0123456789XYZ";
    const char *r = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY+"
                    "12345678901234567890123ABC78901234567890123456789012";
    const char *s = "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY-"
                    "1234567890123456789012345678901234567890123456789012"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    return TEST(0, TEST_str_eq(p, q))
        & TEST(0, TEST_str_eq(q, r))
        & TEST(0, TEST_str_eq(r, s))
        & TEST(0, TEST_mem_eq(r, strlen(r), s, strlen(s)));
}

static int test_long_bignum(void)
{
    int r;
    BIGNUM *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    const char as[] = "1234567890123456789012345678901234567890123456789012"
                      "1234567890123456789012345678901234567890123456789012"
```

## Call pattern 4

```c
"ABCD";

    r = TEST_true(BN_hex2bn(&a, as))
        && TEST_true(BN_hex2bn(&b, bs))
        && TEST_true(BN_hex2bn(&c, cs))
        && TEST_true(BN_hex2bn(&d, ds))
        && (TEST(0, TEST_BN_eq(a, b))
            & TEST(0, TEST_BN_eq(b, a))
            & TEST(0, TEST_BN_eq(b, NULL))
            & TEST(0, TEST_BN_eq(NULL, a))
            & TEST(1, TEST_BN_ne(a, NULL))
            & TEST(0, TEST_BN_eq(c, d)));
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return r;
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

static int test_single_eval(void)
{
    int i = 4;
    long l = -9000;
    char c = 'd';
    unsigned char uc = 22;
    unsigned long ul = 500;
    size_t st = 1234;
    char buf[4] = { 0 }, *p = buf;

    /* int */
    return TEST_int_eq(i++, 4)
        && TEST_int_eq(i, 5)
        && TEST_int_gt(++i, 5)
```

## Call pattern 5

```c
r = TEST_true(BN_hex2bn(&a, as))
        && TEST_true(BN_hex2bn(&b, bs))
        && TEST_true(BN_hex2bn(&c, cs))
        && TEST_true(BN_hex2bn(&d, ds))
        && (TEST(0, TEST_BN_eq(a, b))
            & TEST(0, TEST_BN_eq(b, a))
            & TEST(0, TEST_BN_eq(b, NULL))
            & TEST(0, TEST_BN_eq(NULL, a))
            & TEST(1, TEST_BN_ne(a, NULL))
            & TEST(0, TEST_BN_eq(c, d)));
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return r;
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

static int test_single_eval(void)
{
    int i = 4;
    long l = -9000;
    char c = 'd';
    unsigned char uc = 22;
    unsigned long ul = 500;
    size_t st = 1234;
    char buf[4] = { 0 }, *p = buf;

    /* int */
    return TEST_int_eq(i++, 4)
        && TEST_int_eq(i, 5)
        && TEST_int_gt(++i, 5)
        && TEST_int_le(5, i++)
```

## Call pattern 6

```c
r = TEST_true(BN_hex2bn(&a, as))
        && TEST_true(BN_hex2bn(&b, bs))
        && TEST_true(BN_hex2bn(&c, cs))
        && TEST_true(BN_hex2bn(&d, ds))
        && (TEST(0, TEST_BN_eq(a, b))
            & TEST(0, TEST_BN_eq(b, a))
            & TEST(0, TEST_BN_eq(b, NULL))
            & TEST(0, TEST_BN_eq(NULL, a))
            & TEST(1, TEST_BN_ne(a, NULL))
            & TEST(0, TEST_BN_eq(c, d)));
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return r;
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

static int test_single_eval(void)
{
    int i = 4;
    long l = -9000;
    char c = 'd';
    unsigned char uc = 22;
    unsigned long ul = 500;
    size_t st = 1234;
    char buf[4] = { 0 }, *p = buf;

    /* int */
    return TEST_int_eq(i++, 4)
        && TEST_int_eq(i, 5)
        && TEST_int_gt(++i, 5)
        && TEST_int_le(5, i++)
        && TEST_int_ne(--i, 5)
```

## Call pattern 7

```c
&& TEST_true(BN_hex2bn(&b, bs))
        && TEST_true(BN_hex2bn(&c, cs))
        && TEST_true(BN_hex2bn(&d, ds))
        && (TEST(0, TEST_BN_eq(a, b))
            & TEST(0, TEST_BN_eq(b, a))
            & TEST(0, TEST_BN_eq(b, NULL))
            & TEST(0, TEST_BN_eq(NULL, a))
            & TEST(1, TEST_BN_ne(a, NULL))
            & TEST(0, TEST_BN_eq(c, d)));
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    return r;
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

static int test_single_eval(void)
{
    int i = 4;
    long l = -9000;
    char c = 'd';
    unsigned char uc = 22;
    unsigned long ul = 500;
    size_t st = 1234;
    char buf[4] = { 0 }, *p = buf;

    /* int */
    return TEST_int_eq(i++, 4)
        && TEST_int_eq(i, 5)
        && TEST_int_gt(++i, 5)
        && TEST_int_le(5, i++)
        && TEST_int_ne(--i, 5)
        && TEST_int_eq(12, i *= 2)
```

## Call pattern 8

```c
"1234567890123456789012345678901234567890123456789013"
    "987657"
};

static int test_bn_output(int n)
{
    BIGNUM *b = NULL;

    if (bn_output_tests[n] != NULL
        && !TEST_true(BN_hex2bn(&b, bn_output_tests[n])))
        return 0;
    test_output_bignum(bn_output_tests[n], b);
    BN_free(b);
    return 1;
}

static int test_skip_one(void)
{
    return TEST_skip("skip test");
}

static int test_skip_many(int n)
{
    return TEST_skip("skip tests: %d", n);
}

static int test_skip_null(void)
{
    /*
     * This is not a recommended way of skipping a test, a reason or
     * description should be included.
     */
    return TEST_skip(NULL);
}

int setup_tests(void)
{
    ADD_TEST(test_int);
    ADD_TEST(test_uint);
    ADD_TEST(test_char);
```

