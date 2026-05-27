# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/evp_pkey_provided_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
};
    OSSL_PARAM fromdata_params[] = {
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_N, &key_numbers[N]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_E, &key_numbers[E]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_D, &key_numbers[D]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR1, &key_numbers[P]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR2, &key_numbers[Q]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT1, &key_numbers[DP]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT2, &key_numbers[DQ]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &key_numbers[QINV]),
        OSSL_PARAM_END
    };
    BIGNUM *bn = BN_new();
    BIGNUM *bn_from = BN_new();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)))
        goto err;

    if (!TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1))
        goto err;

    for (;;) {
        ret = 0;
        if (!TEST_int_eq(EVP_PKEY_get_bits(pk), 32)
            || !TEST_int_eq(EVP_PKEY_get_security_bits(pk), 8)
            || !TEST_int_eq(EVP_PKEY_get_size(pk), 4)
            || !TEST_false(EVP_PKEY_missing_parameters(pk)))
            goto err;

        EVP_PKEY_CTX_free(key_ctx);
        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
```

## Call pattern 2

```c
OSSL_PARAM fromdata_params[] = {
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_N, &key_numbers[N]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_E, &key_numbers[E]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_D, &key_numbers[D]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR1, &key_numbers[P]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR2, &key_numbers[Q]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT1, &key_numbers[DP]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT2, &key_numbers[DQ]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &key_numbers[QINV]),
        OSSL_PARAM_END
    };
    BIGNUM *bn = BN_new();
    BIGNUM *bn_from = BN_new();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)))
        goto err;

    if (!TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1))
        goto err;

    for (;;) {
        ret = 0;
        if (!TEST_int_eq(EVP_PKEY_get_bits(pk), 32)
            || !TEST_int_eq(EVP_PKEY_get_security_bits(pk), 8)
            || !TEST_int_eq(EVP_PKEY_get_size(pk), 4)
            || !TEST_false(EVP_PKEY_missing_parameters(pk)))
            goto err;

        EVP_PKEY_CTX_free(key_ctx);
        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
```

## Call pattern 3

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    /* for better diagnostics always compare key params */
    for (i = 0; fromdata_params[i].key != NULL; ++i) {
        if (!TEST_true(BN_set_word(bn_from, key_numbers[i]))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, fromdata_params[i].key,
                &bn))
            || !TEST_BN_eq(bn, bn_from))
            ret = 0;
    }
    BN_free(bn_from);
    BN_free(bn);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

struct check_data {
    const char *pname;
    BIGNUM *comparebn;
};

static int do_fromdata_rsa_derive(OSSL_PARAM *fromdata_params,
    struct check_data check[],
    int expected_nbits, int expected_sbits,
    int expected_ksize)
{
    const OSSL_PARAM *check_param = NULL;
    BIGNUM *check_bn = NULL;
```

## Call pattern 4

```c
if (!ret)
            goto err;
    }
err:
    /* for better diagnostics always compare key params */
    for (i = 0; fromdata_params[i].key != NULL; ++i) {
        if (!TEST_true(BN_set_word(bn_from, key_numbers[i]))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, fromdata_params[i].key,
                &bn))
            || !TEST_BN_eq(bn, bn_from))
            ret = 0;
    }
    BN_free(bn_from);
    BN_free(bn);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

struct check_data {
    const char *pname;
    BIGNUM *comparebn;
};

static int do_fromdata_rsa_derive(OSSL_PARAM *fromdata_params,
    struct check_data check[],
    int expected_nbits, int expected_sbits,
    int expected_ksize)
{
    const OSSL_PARAM *check_param = NULL;
    BIGNUM *check_bn = NULL;
    OSSL_PARAM *todata_params = NULL;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    int i;
    int ret = 0;
```

## Call pattern 5

```c
goto err;
    }
err:
    /* for better diagnostics always compare key params */
    for (i = 0; fromdata_params[i].key != NULL; ++i) {
        if (!TEST_true(BN_set_word(bn_from, key_numbers[i]))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, fromdata_params[i].key,
                &bn))
            || !TEST_BN_eq(bn, bn_from))
            ret = 0;
    }
    BN_free(bn_from);
    BN_free(bn);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

struct check_data {
    const char *pname;
    BIGNUM *comparebn;
};

static int do_fromdata_rsa_derive(OSSL_PARAM *fromdata_params,
    struct check_data check[],
    int expected_nbits, int expected_sbits,
    int expected_ksize)
{
    const OSSL_PARAM *check_param = NULL;
    BIGNUM *check_bn = NULL;
    OSSL_PARAM *todata_params = NULL;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    int i;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL))
```

## Call pattern 6

```c
goto err;

    for (i = 0; check[i].pname != NULL; i++) {
        if (!TEST_ptr(check_param = OSSL_PARAM_locate_const(todata_params,
                          check[i].pname)))
            goto err;
        if (!TEST_int_eq(OSSL_PARAM_get_BN(check_param, &check_bn), 1))
            goto err;
        if (!TEST_BN_eq(check_bn, check[i].comparebn)) {
            TEST_info("Data mismatch for parameter %s", check[i].pname);
            goto err;
        }
        BN_free(check_bn);
        check_bn = NULL;
    }

    for (;;) {
        if (!TEST_int_eq(EVP_PKEY_get_bits(pk), expected_nbits)
            || !TEST_int_eq(EVP_PKEY_get_security_bits(pk), expected_sbits)
            || !TEST_int_eq(EVP_PKEY_get_size(pk), expected_ksize)
            || !TEST_false(EVP_PKEY_missing_parameters(pk)))
            goto err;

        EVP_PKEY_CTX_free(key_ctx);
        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;

        /* EVP_PKEY_copy_parameters() should fail for RSA */
        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_false(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;
```

## Call pattern 7

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        if (!TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1)) {
            EVP_PKEY_free(dup_pk);
            goto err;
        }
        EVP_PKEY_free(pk);
        pk = dup_pk;
    }
    ret = 1;
err:
    BN_free(check_bn);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_free(todata_params);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_sp800(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[4];
    int ret = 0;
    /*
     * 512-bit RSA key, extracted from this command,
     * openssl genrsa 512 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata, and using
     * crt derivation, openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0xc7, 0x06, 0xd8, 0x6b, 0x3c, 0x4f, 0xb7, 0x95, 0x42, 0x44, 0x90,
        0xbd, 0xef, 0xf3, 0xc4, 0xb5, 0xa8, 0x55, 0x9e, 0x33, 0xa3, 0x04, 0x3a,
        0x90, 0xe5, 0x13, 0xff, 0x87, 0x69, 0x15, 0xa4, 0x8a, 0x17, 0x10, 0xcc,
        0xdf, 0xf9, 0xc5, 0x0f, 0xf1, 0x12, 0xff, 0x12, 0x11, 0xe5, 0x6b, 0x5c,
```

## Call pattern 8

```c
cdata[0].pname = OSSL_PKEY_PARAM_RSA_EXPONENT1;
    cdata[0].comparebn = dmp1;
    cdata[1].pname = OSSL_PKEY_PARAM_RSA_EXPONENT2;
    cdata[1].comparebn = dmq1;
    cdata[2].pname = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
    cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
```

## Call pattern 9

```c
cdata[0].comparebn = dmp1;
    cdata[1].pname = OSSL_PKEY_PARAM_RSA_EXPONENT2;
    cdata[1].comparebn = dmq1;
    cdata[2].pname = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
    cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
```

## Call pattern 10

```c
cdata[1].pname = OSSL_PKEY_PARAM_RSA_EXPONENT2;
    cdata[1].comparebn = dmq1;
    cdata[2].pname = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
    cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
```

## Call pattern 11

```c
cdata[1].comparebn = dmq1;
    cdata[2].pname = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
    cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
        0xde, 0xd9, 0xab, 0xee, 0x88, 0x4a, 0x27, 0x4f, 0xcc, 0x5f, 0xf1, 0x71,
```

## Call pattern 12

```c
cdata[2].pname = OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
    cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
        0xde, 0xd9, 0xab, 0xee, 0x88, 0x4a, 0x27, 0x4f, 0xcc, 0x5f, 0xf1, 0x71,
        0xe1, 0x0b, 0xc3, 0xd1, 0x88, 0x76, 0xf0, 0x83, 0x03, 0x93, 0x7e, 0x39,
```

## Call pattern 13

```c
cdata[2].comparebn = iqmp;
    cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
        0xde, 0xd9, 0xab, 0xee, 0x88, 0x4a, 0x27, 0x4f, 0xcc, 0x5f, 0xf1, 0x71,
        0xe1, 0x0b, 0xc3, 0xd1, 0x88, 0x76, 0xf0, 0x83, 0x03, 0x93, 0x7e, 0x39,
        0xfa, 0x47, 0x89, 0x34, 0x27, 0x18, 0x19, 0x97, 0xfc, 0xd4, 0xfe, 0xe5,
```

## Call pattern 14

```c
cdata[3].pname = NULL;
    cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
        0xde, 0xd9, 0xab, 0xee, 0x88, 0x4a, 0x27, 0x4f, 0xcc, 0x5f, 0xf1, 0x71,
        0xe1, 0x0b, 0xc3, 0xd1, 0x88, 0x76, 0xf0, 0x83, 0x03, 0x93, 0x7e, 0x39,
        0xfa, 0x47, 0x89, 0x34, 0x27, 0x18, 0x19, 0x97, 0xfc, 0xd4, 0xfe, 0xe5,
        0x8a, 0xa9, 0x11, 0x83, 0xb5, 0x15, 0x4a, 0x29, 0xa6, 0xa6, 0xd0, 0x6e,
```

## Call pattern 15

```c
cdata[3].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 512, 56, 64);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_fromdata_rsa_derive_from_pq_multiprime(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL, *p2 = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *exp3 = NULL, *coeff2 = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    struct check_data cdata[12];
    int ret = 0;
    /*
     * multiprime RSA key,  extracted from this command,
     * openssl genrsa -primes 3 | openssl rsa -text
     * Note: When generating a key with EVP_PKEY_fromdata,  and using
     * crt derivation,  openssl requires a minimum of 512 bits of n data,
     * and 2048 bits in the FIPS case
     */
    static unsigned char n_data[] = { 0x00, 0x95, 0x78, 0x21, 0xe0, 0xca, 0x94, 0x6c, 0x0b, 0x86, 0x2a, 0x01,
        0xde, 0xd9, 0xab, 0xee, 0x88, 0x4a, 0x27, 0x4f, 0xcc, 0x5f, 0xf1, 0x71,
        0xe1, 0x0b, 0xc3, 0xd1, 0x88, 0x76, 0xf0, 0x83, 0x03, 0x93, 0x7e, 0x39,
        0xfa, 0x47, 0x89, 0x34, 0x27, 0x18, 0x19, 0x97, 0xfc, 0xd4, 0xfe, 0xe5,
        0x8a, 0xa9, 0x11, 0x83, 0xb5, 0x15, 0x4a, 0x29, 0xa6, 0xa6, 0xd0, 0x6e,
        0x0c, 0x7f, 0x61, 0x8f, 0x7e, 0x7c, 0xfb, 0xfc, 0x04, 0x8b, 0xca, 0x44,
```

## Call pattern 16

```c
cdata[8].pname = OSSL_PKEY_PARAM_RSA_FACTOR1;
    cdata[8].comparebn = p;
    cdata[9].pname = OSSL_PKEY_PARAM_RSA_FACTOR2;
    cdata[9].comparebn = q;
    cdata[10].pname = OSSL_PKEY_PARAM_RSA_FACTOR3;
    cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
```

## Call pattern 17

```c
cdata[8].comparebn = p;
    cdata[9].pname = OSSL_PKEY_PARAM_RSA_FACTOR2;
    cdata[9].comparebn = q;
    cdata[10].pname = OSSL_PKEY_PARAM_RSA_FACTOR3;
    cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
```

## Call pattern 18

```c
cdata[9].pname = OSSL_PKEY_PARAM_RSA_FACTOR2;
    cdata[9].comparebn = q;
    cdata[10].pname = OSSL_PKEY_PARAM_RSA_FACTOR3;
    cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
```

## Call pattern 19

```c
cdata[9].comparebn = q;
    cdata[10].pname = OSSL_PKEY_PARAM_RSA_FACTOR3;
    cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
```

## Call pattern 20

```c
cdata[10].pname = OSSL_PKEY_PARAM_RSA_FACTOR3;
    cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
```

## Call pattern 21

```c
cdata[10].comparebn = p2;
    cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
```

## Call pattern 22

```c
cdata[11].pname = NULL;
    cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
    };
```

## Call pattern 23

```c
cdata[11].comparebn = NULL;

    ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
    };
```

## Call pattern 24

```c
ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
    };

    /* N is a large buffer */
```

## Call pattern 25

```c
ret = do_fromdata_rsa_derive(fromdata_params, cdata, 2048, 112, 256);

err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
    };

    /* N is a large buffer */
    memset(n_data, 0xCE, sizeof(n_data));
```

## Call pattern 26

```c
err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(p2);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(exp3);
    BN_free(coeff2);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int test_evp_pkey_get_bn_param_large(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *n_out = NULL;
    /*
     * The buffer size chosen here for n_data larger than the buffer used
     * internally in EVP_PKEY_get_bn_param.
     */
    static unsigned char n_data[2050];
    static const unsigned char e_data[] = {
        0x1, 0x00, 0x01
    };
    static const unsigned char d_data[] = {
        0x99, 0x33, 0x13, 0x7b
    };

    /* N is a large buffer */
    memset(n_data, 0xCE, sizeof(n_data));
```

## Call pattern 27

```c
|| !TEST_ptr(fromdata_params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1)
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, ""))
        || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n_out))
        || !TEST_BN_eq(n, n_out))
        goto err;
    ret = 1;
err:
    BN_free(n_out);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

#ifndef OPENSSL_NO_DH
static int test_fromdata_dh_named_group(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    char name_out[80];
    unsigned char seed_out[32];
```

## Call pattern 28

```c
|| !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1)
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, ""))
        || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n_out))
        || !TEST_BN_eq(n, n_out))
        goto err;
    ret = 1;
err:
    BN_free(n_out);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

#ifndef OPENSSL_NO_DH
static int test_fromdata_dh_named_group(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    char name_out[80];
    unsigned char seed_out[32];

    /*
```

## Call pattern 29

```c
|| !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1)
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, ""))
        || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n_out))
        || !TEST_BN_eq(n, n_out))
        goto err;
    ret = 1;
err:
    BN_free(n_out);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

#ifndef OPENSSL_NO_DH
static int test_fromdata_dh_named_group(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    char name_out[80];
    unsigned char seed_out[32];

    /*
     * DH key data was generated using the following:
```

## Call pattern 30

```c
|| !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR,
                            fromdata_params),
            1)
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, ""))
        || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n_out))
        || !TEST_BN_eq(n, n_out))
        goto err;
    ret = 1;
err:
    BN_free(n_out);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

#ifndef OPENSSL_NO_DH
static int test_fromdata_dh_named_group(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    char name_out[80];
    unsigned char seed_out[32];

    /*
     * DH key data was generated using the following:
     * openssl genpkey -algorithm DH -pkeyopt group:ffdhe2048
```

## Call pattern 31

```c
&len))
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_GINDEX,
                &gindex))
            || !TEST_int_eq(gindex, -1)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
```

## Call pattern 32

```c
&gindex))
            || !TEST_int_eq(gindex, -1)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;
```

## Call pattern 33

```c
|| !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);
```

## Call pattern 34

```c
|| !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
```

## Call pattern 35

```c
OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;
```

## Call pattern 36

```c
|| !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
```

## Call pattern 37

```c
if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
```

## Call pattern 38

```c
break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
```

## Call pattern 39

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
```

## Call pattern 40

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    char name_out[80];
```

## Call pattern 41

```c
goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    char name_out[80];
    unsigned char seed_out[32];
```

## Call pattern 42

```c
ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    char name_out[80];
    unsigned char seed_out[32];
```

## Call pattern 43

```c
EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    char name_out[80];
    unsigned char seed_out[32];

    /*
```

## Call pattern 44

```c
pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

static int test_fromdata_dh_fips186_4(void)
{
    int ret = 0;
    int gindex = 0, pcounter = 0, hindex = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *dup_pk = NULL;
    size_t len;
    BIGNUM *pub = NULL, *priv = NULL;
    BIGNUM *pub_out = NULL, *priv_out = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *j = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    char name_out[80];
    unsigned char seed_out[32];

    /*
     * DH key data was generated using the following:
```

## Call pattern 45

```c
|| !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_GINDEX,
                &gindex))
            || !TEST_int_eq(gindex, -1)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
```

## Call pattern 46

```c
&gindex))
            || !TEST_int_eq(gindex, -1)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;
```

## Call pattern 47

```c
|| !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex))
            || !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
```

## Call pattern 48

```c
|| !TEST_int_eq(hindex, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
```

## Call pattern 49

```c
OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter))
            || !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
```

## Call pattern 50

```c
|| !TEST_int_eq(pcounter, -1))
            goto err;
        BN_free(p);
        p = NULL;
        BN_free(q);
        q = NULL;
        BN_free(g);
        g = NULL;
        BN_free(j);
        j = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        ret = test_print_key_using_pem("DH", pk)
            && test_print_key_using_encoder("DH", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
```

## Call pattern 51

```c
if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
```

## Call pattern 52

```c
break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3
```

## Call pattern 53

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3
```

## Call pattern 54

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3

/*
```

## Call pattern 55

```c
goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3

/*
 * tst uses indexes 0 ... (3 * 4 - 1)
```

## Call pattern 56

```c
ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3

/*
 * tst uses indexes 0 ... (3 * 4 - 1)
 * For the 4 ECX key types (X25519_IDX..ED448_IDX)
```

## Call pattern 57

```c
EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3

/*
 * tst uses indexes 0 ... (3 * 4 - 1)
 * For the 4 ECX key types (X25519_IDX..ED448_IDX)
 * 0..3  = public + private key.
```

## Call pattern 58

```c
pk = dup_pk;
        if (!ret)
            goto err;
    }
err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(j);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_out);
    BN_free(priv_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);

    return ret;
}

#endif

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
/* Array indexes used in test_fromdata_ecx */
#define PRIV_KEY 0
#define PUB_KEY 1

#define X25519_IDX 0
#define X448_IDX 1
#define ED25519_IDX 2
#define ED448_IDX 3

/*
 * tst uses indexes 0 ... (3 * 4 - 1)
 * For the 4 ECX key types (X25519_IDX..ED448_IDX)
 * 0..3  = public + private key.
 * 4..7  = private key (This will generate the public key from the private key)
```

## Call pattern 59

```c
copy_pk = NULL;

        if (!TEST_ptr(gettable = EVP_PKEY_gettable_params(pk))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_GROUP_NAME))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PUB_KEY))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PRIV_KEY)))
            goto err;

        if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve)))
            || !TEST_ptr(group_p = BN_new())
            || !TEST_ptr(group_a = BN_new())
            || !TEST_ptr(group_b = BN_new())
            || !TEST_true(EC_GROUP_get_curve(group, group_p, group_a, group_b, NULL)))
            goto err;

        if (!TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_A, &a))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_B, &b))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_P, &p)))
            goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
```

## Call pattern 60

```c
if (!TEST_ptr(gettable = EVP_PKEY_gettable_params(pk))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_GROUP_NAME))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PUB_KEY))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PRIV_KEY)))
            goto err;

        if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve)))
            || !TEST_ptr(group_p = BN_new())
            || !TEST_ptr(group_a = BN_new())
            || !TEST_ptr(group_b = BN_new())
            || !TEST_true(EC_GROUP_get_curve(group, group_p, group_a, group_b, NULL)))
            goto err;

        if (!TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_A, &a))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_B, &b))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_P, &p)))
            goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
            || !TEST_str_eq(out_curve_name, curve)
```

## Call pattern 61

```c
if (!TEST_ptr(gettable = EVP_PKEY_gettable_params(pk))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_GROUP_NAME))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PUB_KEY))
            || !TEST_ptr(OSSL_PARAM_locate_const(gettable,
                OSSL_PKEY_PARAM_PRIV_KEY)))
            goto err;

        if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve)))
            || !TEST_ptr(group_p = BN_new())
            || !TEST_ptr(group_a = BN_new())
            || !TEST_ptr(group_b = BN_new())
            || !TEST_true(EC_GROUP_get_curve(group, group_p, group_a, group_b, NULL)))
            goto err;

        if (!TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_A, &a))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_B, &b))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_P, &p)))
            goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
            || !TEST_str_eq(out_curve_name, curve)
            || !EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
```

## Call pattern 62

```c
if (!TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_A, &a))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_B, &b))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_P, &p)))
            goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
            || !TEST_str_eq(out_curve_name, curve)
            || !EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                out_pub, sizeof(out_pub), &len)

            /*
             * Our providers use uncompressed format by default if
             * `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` was not
             * explicitly set, irrespective of the format used for the
             * input point given as a param to create this key.
             */
            || !TEST_true(out_pub[0] == POINT_CONVERSION_UNCOMPRESSED)
            || !TEST_mem_eq(out_pub + 1, len - 1,
                ec_pub_keydata + 1, sizeof(ec_pub_keydata) - 1)

            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY,
                &bn_priv))
            || !TEST_BN_eq(ec_priv_bn, bn_priv))
```

## Call pattern 63

```c
|| !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_B, &b))
            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_P, &p)))
            goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
            || !TEST_str_eq(out_curve_name, curve)
            || !EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                out_pub, sizeof(out_pub), &len)

            /*
             * Our providers use uncompressed format by default if
             * `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` was not
             * explicitly set, irrespective of the format used for the
             * input point given as a param to create this key.
             */
            || !TEST_true(out_pub[0] == POINT_CONVERSION_UNCOMPRESSED)
            || !TEST_mem_eq(out_pub + 1, len - 1,
                ec_pub_keydata + 1, sizeof(ec_pub_keydata) - 1)

            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY,
                &bn_priv))
            || !TEST_BN_eq(ec_priv_bn, bn_priv))
            goto err;
        BN_free(bn_priv);
```

## Call pattern 64

```c
goto err;

        if (!TEST_BN_eq(group_p, p) || !TEST_BN_eq(group_a, a)
            || !TEST_BN_eq(group_b, b))
            goto err;

        EC_GROUP_free(group);
        group = NULL;
        BN_free(group_p);
        group_p = NULL;
        BN_free(group_a);
        group_a = NULL;
        BN_free(group_b);
        group_b = NULL;

        if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                out_curve_name,
                sizeof(out_curve_name),
                &len)
            || !TEST_str_eq(out_curve_name, curve)
            || !EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                out_pub, sizeof(out_pub), &len)

            /*
             * Our providers use uncompressed format by default if
             * `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` was not
             * explicitly set, irrespective of the format used for the
             * input point given as a param to create this key.
             */
            || !TEST_true(out_pub[0] == POINT_CONVERSION_UNCOMPRESSED)
            || !TEST_mem_eq(out_pub + 1, len - 1,
                ec_pub_keydata + 1, sizeof(ec_pub_keydata) - 1)

            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY,
                &bn_priv))
            || !TEST_BN_eq(ec_priv_bn, bn_priv))
            goto err;
        BN_free(bn_priv);
        bn_priv = NULL;
```

## Call pattern 65

```c
* `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` was not
             * explicitly set, irrespective of the format used for the
             * input point given as a param to create this key.
             */
            || !TEST_true(out_pub[0] == POINT_CONVERSION_UNCOMPRESSED)
            || !TEST_mem_eq(out_pub + 1, len - 1,
                ec_pub_keydata + 1, sizeof(ec_pub_keydata) - 1)

            || !TEST_true(EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY,
                &bn_priv))
            || !TEST_BN_eq(ec_priv_bn, bn_priv))
            goto err;
        BN_free(bn_priv);
        bn_priv = NULL;

        ret = test_print_key_using_pem(alg, pk)
            && test_print_key_using_encoder(alg, pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
```

## Call pattern 66

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
```

## Call pattern 67

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
```

## Call pattern 68

```c
goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;
```

## Call pattern 69

```c
ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;
```

## Call pattern 70

```c
EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;

    EVP_PKEY_CTX_free(pctx);
```

## Call pattern 71

```c
pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
```

## Call pattern 72

```c
if (!ret)
            goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
```

## Call pattern 73

```c
goto err;
    }

err:
    EC_GROUP_free(group);
    BN_free(group_a);
    BN_free(group_b);
    BN_free(group_p);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(bn_priv);
    BN_free(ec_priv_bn);
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_ec_dup_no_operation(void)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx = NULL, *ctx = NULL, *kctx = NULL;
    EVP_PKEY *param = NULL, *pkey = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
        || !TEST_int_gt(EVP_PKEY_paramgen_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                            NID_X9_62_prime256v1),
            0)
        || !TEST_int_gt(EVP_PKEY_paramgen(pctx, &param), 0)
        || !TEST_ptr(param))
        goto err;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param, NULL))
```

## Call pattern 74

```c
|| !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_GINDEX,
                &gindex_out))
            || !TEST_int_eq(gindex, gindex_out)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex_out))
            || !TEST_int_eq(hindex_out, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter_out))
            || !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
```

## Call pattern 75

```c
&gindex_out))
            || !TEST_int_eq(gindex, gindex_out)
            || !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex_out))
            || !TEST_int_eq(hindex_out, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter_out))
            || !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;
```

## Call pattern 76

```c
|| !TEST_true(EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_FFC_H,
                &hindex_out))
            || !TEST_int_eq(hindex_out, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter_out))
            || !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DSA", pk)
            && test_print_key_using_encoder("DSA", pk);
```

## Call pattern 77

```c
|| !TEST_int_eq(hindex_out, 0)
            || !TEST_true(EVP_PKEY_get_int_param(pk,
                OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter_out))
            || !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DSA", pk)
            && test_print_key_using_encoder("DSA", pk);

        if (!ret || dup_pk != NULL)
```

## Call pattern 78

```c
OSSL_PKEY_PARAM_FFC_PCOUNTER,
                &pcounter_out))
            || !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DSA", pk)
            && test_print_key_using_encoder("DSA", pk);

        if (!ret || dup_pk != NULL)
            break;
```

## Call pattern 79

```c
|| !TEST_int_eq(pcounter, pcounter_out))
            goto err;
        BN_free(p_out);
        p_out = NULL;
        BN_free(q_out);
        q_out = NULL;
        BN_free(g_out);
        g_out = NULL;
        BN_free(j_out);
        j_out = NULL;
        BN_free(pub_out);
        pub_out = NULL;
        BN_free(priv_out);
        priv_out = NULL;

        if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
            goto err;

        if (!TEST_int_gt(EVP_PKEY_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_public_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_private_check(key_ctx), 0)
            || !TEST_int_gt(EVP_PKEY_pairwise_check(key_ctx), 0))
            goto err;
        EVP_PKEY_CTX_free(key_ctx);
        key_ctx = NULL;

        if (!TEST_ptr(copy_pk = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
            goto err;
        EVP_PKEY_free(copy_pk);
        copy_pk = NULL;

        ret = test_print_key_using_pem("DSA", pk)
            && test_print_key_using_encoder("DSA", pk);

        if (!ret || dup_pk != NULL)
            break;

        if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
```

## Call pattern 80

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;
        ret = ret && TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    OSSL_PARAM_free(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    BN_free(pub_out);
    BN_free(priv_out);
    BN_free(j_out);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);

    return ret;
}

static int test_check_dsa(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        || !TEST_int_le(EVP_PKEY_check(ctx), 0)
        || !TEST_int_le(EVP_PKEY_public_check(ctx), 0)
        || !TEST_int_le(EVP_PKEY_private_check(ctx), 0)
```

