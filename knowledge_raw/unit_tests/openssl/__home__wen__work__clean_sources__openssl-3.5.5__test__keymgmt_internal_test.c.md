# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/keymgmt_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
* be any size.  In this particular test, we know that the expected data
 * fits within an unsigned long, and we want to get the data in that form
 * to make testing of values easier.
 */
static int get_ulong_via_BN(const OSSL_PARAM *p, unsigned long *goal)
{
    BIGNUM *n = NULL;
    int ret = 1; /* Ever so hopeful */

    if (!TEST_true(OSSL_PARAM_get_BN(p, &n))
        || !TEST_int_ge(BN_bn2nativepad(n, (unsigned char *)goal, sizeof(*goal)), 0))
        ret = 0;
    BN_free(n);
    return ret;
}

static int export_cb(const OSSL_PARAM *params, void *arg)
{
    unsigned long *keydata = arg;
    const OSSL_PARAM *p = NULL;

    if (keydata == NULL)
        return 0;

    if (!TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N))
        || !TEST_true(get_ulong_via_BN(p, &keydata[N]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E))
        || !TEST_true(get_ulong_via_BN(p, &keydata[E]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D))
        || !TEST_true(get_ulong_via_BN(p, &keydata[D])))
        return 0;

    if (!TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1))
        || !TEST_true(get_ulong_via_BN(p, &keydata[P]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2))
        || !TEST_true(get_ulong_via_BN(p, &keydata[Q]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR3))
        || !TEST_true(get_ulong_via_BN(p, &keydata[F3])))
        return 0;
```

## Call pattern 2

```c
2, /* E3 */
        0xcc3b, /* QINV */
        3, /* C3 */
        0 /* Extra, should remain zero */
    };
    static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
```

## Call pattern 3

```c
0xcc3b, /* QINV */
        3, /* C3 */
        0 /* Extra, should remain zero */
    };
    static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
```

## Call pattern 4

```c
3, /* C3 */
        0 /* Extra, should remain zero */
    };
    static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
```

## Call pattern 5

```c
0 /* Extra, should remain zero */
    };
    static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
```

## Call pattern 6

```c
};
    static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
```

## Call pattern 7

```c
static unsigned long keydata[OSSL_NELEM(expected)] = {
        0,
    };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
```

## Call pattern 8

```c
if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
```

## Call pattern 9

```c
goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
```

## Call pattern 10

```c
if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
```

## Call pattern 11

```c
if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;
```

## Call pattern 12

```c
|| !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
```

## Call pattern 13

```c
|| !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
```

## Call pattern 14

```c
|| !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;
```

## Call pattern 15

```c
goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;
```

## Call pattern 16

```c
if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
```

## Call pattern 17

```c
if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
```

## Call pattern 18

```c
goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
        km = km3;
        /* Check that we can't export an RSA key into an RSA-PSS keymanager */
        if (!TEST_ptr_null(provkey2 = evp_pkey_export_to_provider(pk, NULL,
                               &km,
                               NULL)))
```

## Call pattern 19

```c
if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
        km = km3;
        /* Check that we can't export an RSA key into an RSA-PSS keymanager */
        if (!TEST_ptr_null(provkey2 = evp_pkey_export_to_provider(pk, NULL,
                               &km,
                               NULL)))
            goto err;
```

## Call pattern 20

```c
|| !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
        km = km3;
        /* Check that we can't export an RSA key into an RSA-PSS keymanager */
        if (!TEST_ptr_null(provkey2 = evp_pkey_export_to_provider(pk, NULL,
                               &km,
                               NULL)))
            goto err;

        if (!TEST_ptr(provkey = evp_pkey_export_to_provider(pk, NULL, &km1,
```

## Call pattern 21

```c
|| !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
        km = km3;
        /* Check that we can't export an RSA key into an RSA-PSS keymanager */
        if (!TEST_ptr_null(provkey2 = evp_pkey_export_to_provider(pk, NULL,
                               &km,
                               NULL)))
            goto err;

        if (!TEST_ptr(provkey = evp_pkey_export_to_provider(pk, NULL, &km1,
                          NULL))
```

## Call pattern 22

```c
|| !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(bn_primes[0] = BN_new())
        || !TEST_true(BN_set_word(bn_primes[0], expected[F3]))
        || !TEST_ptr(bn_exps[0] = BN_new())
        || !TEST_true(BN_set_word(bn_exps[0], expected[E3]))
        || !TEST_ptr(bn_coeffs[0] = BN_new())
        || !TEST_true(BN_set_word(bn_coeffs[0], expected[C2]))
        || !TEST_true(RSA_set0_multi_prime_params(rsa, bn_primes, bn_exps,
            bn_coeffs, 1)))
        goto err;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr(km3 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA-PSS", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    for (;;) {
        ret = 0;
        km = km3;
        /* Check that we can't export an RSA key into an RSA-PSS keymanager */
        if (!TEST_ptr_null(provkey2 = evp_pkey_export_to_provider(pk, NULL,
                               &km,
                               NULL)))
            goto err;

        if (!TEST_ptr(provkey = evp_pkey_export_to_provider(pk, NULL, &km1,
                          NULL))
            || !TEST_true(evp_keymgmt_export(km2, provkey,
```

## Call pattern 23

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pk)))
            goto err;

        ret = TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    RSA_free(rsa);
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    EVP_PKEY_free(pk);
    EVP_KEYMGMT_free(km1);
    EVP_KEYMGMT_free(km2);
    EVP_KEYMGMT_free(km3);

    return ret;
}

static int (*tests[])(FIXTURE *) = {
    test_pass_rsa
};

static int test_pass_key(int n)
{
    SETUP_TEST_FIXTURE(FIXTURE, set_up);
    EXECUTE_TEST(tests[n], tear_down);
    return result;
}

static int test_evp_pkey_export_to_provider(int n)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;
```

## Call pattern 24

```c
goto err;

        ret = TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    RSA_free(rsa);
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    EVP_PKEY_free(pk);
    EVP_KEYMGMT_free(km1);
    EVP_KEYMGMT_free(km2);
    EVP_KEYMGMT_free(km3);

    return ret;
}

static int (*tests[])(FIXTURE *) = {
    test_pass_rsa
};

static int test_pass_key(int n)
{
    SETUP_TEST_FIXTURE(FIXTURE, set_up);
    EXECUTE_TEST(tests[n], tear_down);
    return result;
}

static int test_evp_pkey_export_to_provider(int n)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;
    X509_PUBKEY *pubkey = NULL;
```

## Call pattern 25

```c
ret = TEST_int_eq(EVP_PKEY_eq(pk, dup_pk), 1);
        EVP_PKEY_free(pk);
        pk = dup_pk;
        if (!ret)
            goto err;
    }

err:
    RSA_free(rsa);
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    EVP_PKEY_free(pk);
    EVP_KEYMGMT_free(km1);
    EVP_KEYMGMT_free(km2);
    EVP_KEYMGMT_free(km3);

    return ret;
}

static int (*tests[])(FIXTURE *) = {
    test_pass_rsa
};

static int test_pass_key(int n)
{
    SETUP_TEST_FIXTURE(FIXTURE, set_up);
    EXECUTE_TEST(tests[n], tear_down);
    return result;
}

static int test_evp_pkey_export_to_provider(int n)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;
    X509_PUBKEY *pubkey = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
```

