# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_gcd.c
Knowledge type: api_constraints

## Snippet 1

```c
B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    if (!BN_one(X))
        goto err;
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;

    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        /*
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
```

## Snippet 2

```c
*pnoinv = 1;
        /* caller sets the BN_R_NO_INVERSE error */
        goto err;
    }

    ret = R;
    *pnoinv = 0;

err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return ret;
}

/*
 * This is an internal function, we assume all callers pass valid arguments:
 * all pointers passed here are assumed non-NULL.
 */
BIGNUM *int_bn_mod_inverse(BIGNUM *in,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx,
    int *pnoinv)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;
```

## Snippet 3

```c
B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    if (!BN_one(X))
        goto err;
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;
    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        if (!BN_nnmod(B, B, A, ctx))
            goto err;
    }
```

## Snippet 4

```c
if (!BN_sub(M, A, B))
                        goto err;
                } else {
                    /* A >= 2*B, so D=2 or D=3 */
                    if (!BN_sub(M, A, T))
                        goto err;
                    if (!BN_add(D, T, B))
                        goto err; /* use D (:= 3*B) as temp */
                    if (BN_ucmp(A, D) < 0) {
                        /* A < 3*B, so D=2 */
                        if (!BN_set_word(D, 2))
                            goto err;
                        /*
                         * M (= A - 2*B) already has the correct value
                         */
                    } else {
                        /* only D=3 remains */
                        if (!BN_set_word(D, 3))
                            goto err;
                        /*
                         * currently M = A - 2*B, but we need M = A - 3*B
                         */
                        if (!BN_sub(M, M, B))
                            goto err;
                    }
                }
            } else {
                if (!BN_div(D, M, A, B, ctx))
```

## Snippet 5

```c
goto err; /* use D (:= 3*B) as temp */
                    if (BN_ucmp(A, D) < 0) {
                        /* A < 3*B, so D=2 */
                        if (!BN_set_word(D, 2))
                            goto err;
                        /*
                         * M (= A - 2*B) already has the correct value
                         */
                    } else {
                        /* only D=3 remains */
                        if (!BN_set_word(D, 3))
                            goto err;
                        /*
                         * currently M = A - 2*B, but we need M = A - 3*B
                         */
                        if (!BN_sub(M, M, B))
                            goto err;
                    }
                }
            } else {
                if (!BN_div(D, M, A, B, ctx))
                    goto err;
            }

            /*-
             * Now
             *      A = D*B + M;
             * thus we have
```

## Snippet 6

```c
if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        *pnoinv = 1;
        goto err;
    }
    ret = R;
err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return ret;
}

/* solves ax == 1 (mod n) */
BIGNUM *BN_mod_inverse(BIGNUM *in,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *rv;
    int noinv = 0;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new_ex(NULL);
        if (ctx == NULL) {
            ERR_raise(ERR_LIB_BN, ERR_R_BN_LIB);
```

