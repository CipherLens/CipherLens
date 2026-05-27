# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/params_api_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!TEST_true(OSSL_PARAM_set_BN(&param, b)))
        goto err;
    le_copy(buf, len, bnbuf, sizeof(bnbuf));
    if (!TEST_mem_eq(raw_values[n].value, len, buf, len))
        goto err;
    param.data_size = param.return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(&param, &c))
        || !TEST_BN_eq(b, c))
        goto err;

    ret = 1;
err:
    BN_free(b);
    BN_free(c);
    return ret;
}

static int test_param_signed_bignum(int n)
{
    unsigned char buf[MAX_LEN], bnbuf[MAX_LEN];
    const size_t len = raw_values[n].len;
    BIGNUM *b = NULL, *c = NULL;
    OSSL_PARAM param = OSSL_PARAM_DEFN("bn", OSSL_PARAM_INTEGER, NULL, 0);
    int ret = 0;

    if (!TEST_int_eq(test_param_type_null(&param), 1))
        return 0;

    param.data = bnbuf;
    param.data_size = sizeof(bnbuf);

    if (!TEST_ptr(b = BN_signed_lebin2bn(raw_values[n].value, (int)len, NULL)))
        goto err;

    /* raw_values are little endian */
    if (!TEST_false(!!(raw_values[n].value[len - 1] & 0x80) ^ BN_is_negative(b)))
        goto err;
    if (!TEST_true(OSSL_PARAM_set_BN(&param, b)))
        goto err;
    le_copy(buf, len, bnbuf, sizeof(bnbuf));
```

## Call pattern 2

```c
goto err;
    le_copy(buf, len, bnbuf, sizeof(bnbuf));
    if (!TEST_mem_eq(raw_values[n].value, len, buf, len))
        goto err;
    param.data_size = param.return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(&param, &c))
        || !TEST_BN_eq(b, c))
        goto err;

    ret = 1;
err:
    BN_free(b);
    BN_free(c);
    return ret;
}

static int test_param_signed_bignum(int n)
{
    unsigned char buf[MAX_LEN], bnbuf[MAX_LEN];
    const size_t len = raw_values[n].len;
    BIGNUM *b = NULL, *c = NULL;
    OSSL_PARAM param = OSSL_PARAM_DEFN("bn", OSSL_PARAM_INTEGER, NULL, 0);
    int ret = 0;

    if (!TEST_int_eq(test_param_type_null(&param), 1))
        return 0;

    param.data = bnbuf;
    param.data_size = sizeof(bnbuf);

    if (!TEST_ptr(b = BN_signed_lebin2bn(raw_values[n].value, (int)len, NULL)))
        goto err;

    /* raw_values are little endian */
    if (!TEST_false(!!(raw_values[n].value[len - 1] & 0x80) ^ BN_is_negative(b)))
        goto err;
    if (!TEST_true(OSSL_PARAM_set_BN(&param, b)))
        goto err;
    le_copy(buf, len, bnbuf, sizeof(bnbuf));
    if (!TEST_mem_eq(raw_values[n].value, len, buf, len))
```

## Call pattern 3

```c
le_copy(buf, len, bnbuf, sizeof(bnbuf));
    if (!TEST_mem_eq(raw_values[n].value, len, buf, len))
        goto err;
    param.data_size = param.return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(&param, &c))
        || !TEST_BN_eq(b, c)) {
        BN_print_fp(stderr, c);
        goto err;
    }

    ret = 1;
err:
    BN_free(b);
    BN_free(c);
    return ret;
}

static int test_param_real(void)
{
    double p;
    OSSL_PARAM param = OSSL_PARAM_double("r", NULL);

    if (!TEST_int_eq(test_param_type_null(&param), 1))
        return 0;

    param.data = &p;
    return TEST_true(OSSL_PARAM_set_double(&param, 3.14159))
        && TEST_double_eq(p, 3.14159);
}

static int test_param_construct(int tstid)
{
    static const char *int_names[] = {
        "int", "long", "int32", "int64"
    };
    static const char *uint_names[] = {
        "uint", "ulong", "uint32", "uint64", "size_t"
    };
    static const unsigned char bn_val[16] = {
        0xac, 0x75, 0x22, 0x7d, 0x81, 0x06, 0x7a, 0x23,
```

## Call pattern 4

```c
if (!TEST_mem_eq(raw_values[n].value, len, buf, len))
        goto err;
    param.data_size = param.return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(&param, &c))
        || !TEST_BN_eq(b, c)) {
        BN_print_fp(stderr, c);
        goto err;
    }

    ret = 1;
err:
    BN_free(b);
    BN_free(c);
    return ret;
}

static int test_param_real(void)
{
    double p;
    OSSL_PARAM param = OSSL_PARAM_double("r", NULL);

    if (!TEST_int_eq(test_param_type_null(&param), 1))
        return 0;

    param.data = &p;
    return TEST_true(OSSL_PARAM_set_double(&param, 3.14159))
        && TEST_double_eq(p, 3.14159);
}

static int test_param_construct(int tstid)
{
    static const char *int_names[] = {
        "int", "long", "int32", "int64"
    };
    static const char *uint_names[] = {
        "uint", "ulong", "uint32", "uint64", "size_t"
    };
    static const unsigned char bn_val[16] = {
        0xac, 0x75, 0x22, 0x7d, 0x81, 0x06, 0x7a, 0x23,
        0xa6, 0xed, 0x87, 0xc7, 0xab, 0xf4, 0x73, 0x22
```

## Call pattern 5

```c
goto err;
    /* Match the return size to avoid trailing garbage bytes */
    cp->data_size = cp->return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(cp, &bn2))
        || !TEST_BN_eq(bn, bn2))
        goto err;
    ret = 1;
err:
    if (p != params)
        OPENSSL_free(p);
    OPENSSL_free(p1);
    OPENSSL_free(vpn);
    BN_free(bn);
    BN_free(bn2);
    return ret;
}

static int test_param_modified(void)
{
    OSSL_PARAM param[3] = { OSSL_PARAM_int("a", NULL),
        OSSL_PARAM_int("b", NULL),
        OSSL_PARAM_END };
    int a, b;

    param->data = &a;
    param[1].data = &b;
    if (!TEST_false(OSSL_PARAM_modified(param))
        && !TEST_true(OSSL_PARAM_set_int32(param, 1234))
        && !TEST_true(OSSL_PARAM_modified(param))
        && !TEST_false(OSSL_PARAM_modified(param + 1))
        && !TEST_true(OSSL_PARAM_set_int32(param + 1, 1))
        && !TEST_true(OSSL_PARAM_modified(param + 1)))
        return 0;
    OSSL_PARAM_set_all_unmodified(param);
    if (!TEST_false(OSSL_PARAM_modified(param))
        && !TEST_true(OSSL_PARAM_set_int32(param, 4321))
        && !TEST_true(OSSL_PARAM_modified(param))
        && !TEST_false(OSSL_PARAM_modified(param + 1))
        && !TEST_true(OSSL_PARAM_set_int32(param + 1, 2))
        && !TEST_true(OSSL_PARAM_modified(param + 1)))
```

## Call pattern 6

```c
/* Match the return size to avoid trailing garbage bytes */
    cp->data_size = cp->return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(cp, &bn2))
        || !TEST_BN_eq(bn, bn2))
        goto err;
    ret = 1;
err:
    if (p != params)
        OPENSSL_free(p);
    OPENSSL_free(p1);
    OPENSSL_free(vpn);
    BN_free(bn);
    BN_free(bn2);
    return ret;
}

static int test_param_modified(void)
{
    OSSL_PARAM param[3] = { OSSL_PARAM_int("a", NULL),
        OSSL_PARAM_int("b", NULL),
        OSSL_PARAM_END };
    int a, b;

    param->data = &a;
    param[1].data = &b;
    if (!TEST_false(OSSL_PARAM_modified(param))
        && !TEST_true(OSSL_PARAM_set_int32(param, 1234))
        && !TEST_true(OSSL_PARAM_modified(param))
        && !TEST_false(OSSL_PARAM_modified(param + 1))
        && !TEST_true(OSSL_PARAM_set_int32(param + 1, 1))
        && !TEST_true(OSSL_PARAM_modified(param + 1)))
        return 0;
    OSSL_PARAM_set_all_unmodified(param);
    if (!TEST_false(OSSL_PARAM_modified(param))
        && !TEST_true(OSSL_PARAM_set_int32(param, 4321))
        && !TEST_true(OSSL_PARAM_modified(param))
        && !TEST_false(OSSL_PARAM_modified(param + 1))
        && !TEST_true(OSSL_PARAM_set_int32(param + 1, 2))
        && !TEST_true(OSSL_PARAM_modified(param + 1)))
        return 0;
```

