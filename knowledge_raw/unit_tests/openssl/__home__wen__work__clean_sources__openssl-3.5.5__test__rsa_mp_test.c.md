# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/rsa_mp_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!TEST_true(RSA_set0_multi_prime_params(key, pris, exps,
            coeffs, NUM_EXTRA_PRIMES)))
        goto err;

ret:
    OPENSSL_free(pris);
    OPENSSL_free(exps);
    OPENSSL_free(coeffs);
    return rv;
err:
    if (pris != NULL)
        BN_free(pris[0]);
    if (exps != NULL)
        BN_free(exps[0]);
    if (coeffs != NULL)
        BN_free(coeffs[0]);
    rv = 0;
    goto ret;
}

static int key2048p3_v2(RSA *key)
{
    STACK_OF(BIGNUM) *primes = NULL, *exps = NULL, *coeffs = NULL;
    BIGNUM *num = NULL;
    int rv = RSA_size(key);

    if (!TEST_ptr(primes = sk_BIGNUM_new_null())
        || !TEST_ptr(exps = sk_BIGNUM_new_null())
        || !TEST_ptr(coeffs = sk_BIGNUM_new_null()))
        goto err;

    if (!TEST_ptr(num = BN_bin2bn(p, sizeof(p) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(q, sizeof(q) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(ex_prime, sizeof(ex_prime) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0))
        goto err;
```

## Call pattern 2

```c
coeffs, NUM_EXTRA_PRIMES)))
        goto err;

ret:
    OPENSSL_free(pris);
    OPENSSL_free(exps);
    OPENSSL_free(coeffs);
    return rv;
err:
    if (pris != NULL)
        BN_free(pris[0]);
    if (exps != NULL)
        BN_free(exps[0]);
    if (coeffs != NULL)
        BN_free(coeffs[0]);
    rv = 0;
    goto ret;
}

static int key2048p3_v2(RSA *key)
{
    STACK_OF(BIGNUM) *primes = NULL, *exps = NULL, *coeffs = NULL;
    BIGNUM *num = NULL;
    int rv = RSA_size(key);

    if (!TEST_ptr(primes = sk_BIGNUM_new_null())
        || !TEST_ptr(exps = sk_BIGNUM_new_null())
        || !TEST_ptr(coeffs = sk_BIGNUM_new_null()))
        goto err;

    if (!TEST_ptr(num = BN_bin2bn(p, sizeof(p) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(q, sizeof(q) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(ex_prime, sizeof(ex_prime) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0))
        goto err;

    if (!TEST_ptr(num = BN_bin2bn(dmp1, sizeof(dmp1) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(exps, num), 0)
```

## Call pattern 3

```c
ret:
    OPENSSL_free(pris);
    OPENSSL_free(exps);
    OPENSSL_free(coeffs);
    return rv;
err:
    if (pris != NULL)
        BN_free(pris[0]);
    if (exps != NULL)
        BN_free(exps[0]);
    if (coeffs != NULL)
        BN_free(coeffs[0]);
    rv = 0;
    goto ret;
}

static int key2048p3_v2(RSA *key)
{
    STACK_OF(BIGNUM) *primes = NULL, *exps = NULL, *coeffs = NULL;
    BIGNUM *num = NULL;
    int rv = RSA_size(key);

    if (!TEST_ptr(primes = sk_BIGNUM_new_null())
        || !TEST_ptr(exps = sk_BIGNUM_new_null())
        || !TEST_ptr(coeffs = sk_BIGNUM_new_null()))
        goto err;

    if (!TEST_ptr(num = BN_bin2bn(p, sizeof(p) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(q, sizeof(q) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0)
        || !TEST_ptr(num = BN_bin2bn(ex_prime, sizeof(ex_prime) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(primes, num), 0))
        goto err;

    if (!TEST_ptr(num = BN_bin2bn(dmp1, sizeof(dmp1) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(exps, num), 0)
        || !TEST_ptr(num = BN_bin2bn(dmq1, sizeof(dmq1) - 1, NULL))
        || !TEST_int_ne(sk_BIGNUM_push(exps, num), 0)
```

## Call pattern 4

```c
|| !TEST_int_ne(sk_BIGNUM_push(coeffs, num), 0))
        goto err;

    if (!TEST_true(ossl_rsa_set0_all_params(key, primes, exps, coeffs)))
        goto err;

ret:
    sk_BIGNUM_free(primes);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    return rv;
err:
    sk_BIGNUM_pop_free(primes, BN_free);
    sk_BIGNUM_pop_free(exps, BN_free);
    sk_BIGNUM_pop_free(coeffs, BN_free);
    primes = exps = coeffs = NULL;
    rv = 0;
    goto ret;
}

static int test_rsa_mp(int i)
{
    int ret = 0;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    int plen;
    int clen = 0;
    int num;
    static int (*param_set[])(RSA *) = {
        key2048p3_v1,
        key2048p3_v2,
    };

    plen = sizeof(ptext_ex) - 1;
    key = RSA_new();
    if (!TEST_ptr(key))
        goto err;
```

## Call pattern 5

```c
goto err;

    if (!TEST_true(ossl_rsa_set0_all_params(key, primes, exps, coeffs)))
        goto err;

ret:
    sk_BIGNUM_free(primes);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    return rv;
err:
    sk_BIGNUM_pop_free(primes, BN_free);
    sk_BIGNUM_pop_free(exps, BN_free);
    sk_BIGNUM_pop_free(coeffs, BN_free);
    primes = exps = coeffs = NULL;
    rv = 0;
    goto ret;
}

static int test_rsa_mp(int i)
{
    int ret = 0;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    int plen;
    int clen = 0;
    int num;
    static int (*param_set[])(RSA *) = {
        key2048p3_v1,
        key2048p3_v2,
    };

    plen = sizeof(ptext_ex) - 1;
    key = RSA_new();
    if (!TEST_ptr(key))
        goto err;

    if (!TEST_int_eq((clen = key2048_key(key)), 256)
```

## Call pattern 6

```c
if (!TEST_true(ossl_rsa_set0_all_params(key, primes, exps, coeffs)))
        goto err;

ret:
    sk_BIGNUM_free(primes);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    return rv;
err:
    sk_BIGNUM_pop_free(primes, BN_free);
    sk_BIGNUM_pop_free(exps, BN_free);
    sk_BIGNUM_pop_free(coeffs, BN_free);
    primes = exps = coeffs = NULL;
    rv = 0;
    goto ret;
}

static int test_rsa_mp(int i)
{
    int ret = 0;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    int plen;
    int clen = 0;
    int num;
    static int (*param_set[])(RSA *) = {
        key2048p3_v1,
        key2048p3_v2,
    };

    plen = sizeof(ptext_ex) - 1;
    key = RSA_new();
    if (!TEST_ptr(key))
        goto err;

    if (!TEST_int_eq((clen = key2048_key(key)), 256)
        || !TEST_int_eq((clen = param_set[i](key)), 256))
```

## Call pattern 7

```c
return ret;
}

static int test_rsa_mp_gen_bad_input(void)
{
    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *ebn = NULL;

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(ebn = BN_new()))
        goto err;
    if (!TEST_true(BN_set_word(ebn, 65537)))
        goto err;

    /* Test that a NULL exponent fails and does not segfault */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 2, NULL, NULL), 0))
        goto err;

    /* Test invalid bitsize fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 500, 2, ebn, NULL), 0))
        goto err;

    /* Test invalid prime count fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 1, ebn, NULL), 0))
        goto err;
    ret = 1;
err:
    BN_free(ebn);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_rsa_mp_gen_bad_input);
    ADD_ALL_TESTS(test_rsa_mp, 2);
    return 1;
```

## Call pattern 8

```c
static int test_rsa_mp_gen_bad_input(void)
{
    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *ebn = NULL;

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(ebn = BN_new()))
        goto err;
    if (!TEST_true(BN_set_word(ebn, 65537)))
        goto err;

    /* Test that a NULL exponent fails and does not segfault */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 2, NULL, NULL), 0))
        goto err;

    /* Test invalid bitsize fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 500, 2, ebn, NULL), 0))
        goto err;

    /* Test invalid prime count fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 1, ebn, NULL), 0))
        goto err;
    ret = 1;
err:
    BN_free(ebn);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_rsa_mp_gen_bad_input);
    ADD_ALL_TESTS(test_rsa_mp, 2);
    return 1;
}
```

## Call pattern 9

```c
if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 2, NULL, NULL), 0))
        goto err;

    /* Test invalid bitsize fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 500, 2, ebn, NULL), 0))
        goto err;

    /* Test invalid prime count fails */
    if (!TEST_int_eq(RSA_generate_multi_prime_key(rsa, 1024, 1, ebn, NULL), 0))
        goto err;
    ret = 1;
err:
    BN_free(ebn);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_rsa_mp_gen_bad_input);
    ADD_ALL_TESTS(test_rsa_mp, 2);
    return 1;
}
```

