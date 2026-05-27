# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_depr.c
Knowledge type: api_constraints

## Snippet 1

```c
BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe,
    const BIGNUM *add, const BIGNUM *rem,
    void (*callback)(int, int, void *), void *cb_arg)
{
    BN_GENCB cb;
    BIGNUM *rnd = NULL;

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (ret == NULL) {
        if ((rnd = BN_new()) == NULL)
            goto err;
    } else
        rnd = ret;
    if (!BN_generate_prime_ex(rnd, bits, safe, add, rem, &cb))
        goto err;

    /* we have a prime :-) */
    return rnd;
err:
    BN_free(rnd);
    return NULL;
}

int BN_is_prime(const BIGNUM *a, int checks,
    void (*callback)(int, int, void *), BN_CTX *ctx_passed,
    void *cb_arg)
{
```

## Snippet 2

```c
if ((rnd = BN_new()) == NULL)
            goto err;
    } else
        rnd = ret;
    if (!BN_generate_prime_ex(rnd, bits, safe, add, rem, &cb))
        goto err;

    /* we have a prime :-) */
    return rnd;
err:
    BN_free(rnd);
    return NULL;
}

int BN_is_prime(const BIGNUM *a, int checks,
    void (*callback)(int, int, void *), BN_CTX *ctx_passed,
    void *cb_arg)
{
    BN_GENCB cb;
    BN_GENCB_set_old(&cb, callback, cb_arg);
    return ossl_bn_check_prime(a, checks, ctx_passed, 0, &cb);
}

int BN_is_prime_fasttest(const BIGNUM *a, int checks,
    void (*callback)(int, int, void *),
    BN_CTX *ctx_passed, void *cb_arg,
    int do_trial_division)
{
```

