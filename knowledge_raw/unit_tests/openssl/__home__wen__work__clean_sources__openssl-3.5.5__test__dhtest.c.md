# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/dhtest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
DH *b = NULL;
    DH *c = NULL;
    const BIGNUM *ap = NULL, *ag = NULL, *apub_key = NULL;
    const BIGNUM *bpub_key = NULL, *bpriv_key = NULL;
    BIGNUM *bp = NULL, *bg = NULL, *cpriv_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    unsigned char *cbuf = NULL;
    int i, alen, blen, clen, aout, bout, cout;
    int ret = 0;

    if (!TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
```

## Call pattern 2

```c
DH *c = NULL;
    const BIGNUM *ap = NULL, *ag = NULL, *apub_key = NULL;
    const BIGNUM *bpub_key = NULL, *bpriv_key = NULL;
    BIGNUM *bp = NULL, *bg = NULL, *cpriv_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    unsigned char *cbuf = NULL;
    int i, alen, blen, clen, aout, bout, cout;
    int ret = 0;

    if (!TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
```

## Call pattern 3

```c
const BIGNUM *ap = NULL, *ag = NULL, *apub_key = NULL;
    const BIGNUM *bpub_key = NULL, *bpriv_key = NULL;
    BIGNUM *bp = NULL, *bg = NULL, *cpriv_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    unsigned char *cbuf = NULL;
    int i, alen, blen, clen, aout, bout, cout;
    int ret = 0;

    if (!TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
        || !TEST_false(i & DH_MODULUS_TOO_LARGE)
```

## Call pattern 4

```c
const BIGNUM *bpub_key = NULL, *bpriv_key = NULL;
    BIGNUM *bp = NULL, *bg = NULL, *cpriv_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    unsigned char *cbuf = NULL;
    int i, alen, blen, clen, aout, bout, cout;
    int ret = 0;

    if (!TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
        || !TEST_false(i & DH_MODULUS_TOO_LARGE)
        || !TEST_false(i))
```

## Call pattern 5

```c
if (!TEST_ptr(dh = DH_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
        || !TEST_false(i & DH_MODULUS_TOO_LARGE)
        || !TEST_false(i))
        goto err2;

    /* test the combined getter for p, q, and g */
    DH_get0_pqg(dh, &p2, &q2, &g2);
    if (!TEST_ptr_eq(p2, p)
        || !TEST_ptr_eq(q2, q)
        || !TEST_ptr_eq(g2, g))
        goto err2;
```

## Call pattern 6

```c
|| !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
        || !TEST_false(i & DH_MODULUS_TOO_LARGE)
        || !TEST_false(i))
        goto err2;

    /* test the combined getter for p, q, and g */
    DH_get0_pqg(dh, &p2, &q2, &g2);
    if (!TEST_ptr_eq(p2, p)
        || !TEST_ptr_eq(q2, q)
        || !TEST_ptr_eq(g2, g))
        goto err2;
```

## Call pattern 7

```c
|| !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(priv_key = BN_new()))
        goto err1;

    /*
     * I) basic tests
     */

    /* using a small predefined Sophie Germain DH group with generator 3 */
    if (!TEST_true(BN_set_word(p, 4079L))
        || !TEST_true(BN_set_word(q, 2039L))
        || !TEST_true(BN_set_word(g, 3L))
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err1;

    /* check fails, because p is way too small */
    if (!TEST_true(DH_check(dh, &i)))
        goto err2;
    i ^= DH_MODULUS_TOO_SMALL;
    if (!TEST_false(i & DH_CHECK_P_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_P_NOT_SAFE_PRIME)
        || !TEST_false(i & DH_UNABLE_TO_CHECK_GENERATOR)
        || !TEST_false(i & DH_NOT_SUITABLE_GENERATOR)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME)
        || !TEST_false(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_INVALID_J_VALUE)
        || !TEST_false(i & DH_MODULUS_TOO_SMALL)
        || !TEST_false(i & DH_MODULUS_TOO_LARGE)
        || !TEST_false(i))
        goto err2;

    /* test the combined getter for p, q, and g */
    DH_get0_pqg(dh, &p2, &q2, &g2);
    if (!TEST_ptr_eq(p2, p)
        || !TEST_ptr_eq(q2, q)
        || !TEST_ptr_eq(g2, g))
        goto err2;

    /* test the simple getters for p, q, and g */
```

## Call pattern 8

```c
if (!TEST_ptr_eq(p2, p)
        || !TEST_ptr_eq(q2, q)
        || !TEST_ptr_eq(g2, g))
        goto err2;

    /* test the simple getters for p, q, and g */
    if (!TEST_ptr_eq(DH_get0_p(dh), p2)
        || !TEST_ptr_eq(DH_get0_q(dh), q2)
        || !TEST_ptr_eq(DH_get0_g(dh), g2))
        goto err2;

    /* set the private key only*/
    if (!TEST_true(BN_set_word(priv_key, 1234L))
        || !TEST_true(DH_set0_key(dh, NULL, priv_key)))
        goto err2;

    /* test the combined getter for pub_key and priv_key */
    DH_get0_key(dh, &pub_key2, &priv_key2);
    if (!TEST_ptr_eq(pub_key2, NULL)
        || !TEST_ptr_eq(priv_key2, priv_key))
        goto err3;

    /* test the simple getters for pub_key and priv_key */
    if (!TEST_ptr_eq(DH_get0_pub_key(dh), pub_key2)
        || !TEST_ptr_eq(DH_get0_priv_key(dh), priv_key2))
        goto err3;

    /* now generate a key pair (expect failure since modulus is too small) */
    if (!TEST_false(DH_generate_key(dh)))
        goto err3;

    /* We'll have a stale error on the queue from the above test so clear it */
    ERR_clear_error();

    if (!TEST_ptr(BN_copy(q, p)) || !TEST_true(BN_add(q, q, BN_value_one())))
        goto err3;

    if (!TEST_true(DH_check(dh, &i)))
        goto err3;
    if (!TEST_true(i & DH_CHECK_INVALID_Q_VALUE)
```

## Call pattern 9

```c
ERR_clear_error();

    if (!TEST_ptr(BN_copy(q, p)) || !TEST_true(BN_add(q, q, BN_value_one())))
        goto err3;

    if (!TEST_true(DH_check(dh, &i)))
        goto err3;
    if (!TEST_true(i & DH_CHECK_INVALID_Q_VALUE)
        || !TEST_false(i & DH_CHECK_Q_NOT_PRIME))
        goto err3;

    /* Modulus of size: dh check max modulus bits + 1 */
    if (!TEST_true(BN_set_word(p, 1))
        || !TEST_true(BN_lshift(p, p, OPENSSL_DH_CHECK_MAX_MODULUS_BITS)))
        goto err3;

    /*
     * We expect no checks at all for an excessively large modulus
     */
    if (!TEST_false(DH_check(dh, &i)))
        goto err3;

    /* We'll have a stale error on the queue from the above test so clear it */
    ERR_clear_error();

    /*
     * II) key generation
     */

    /* generate a DH group ... */
    if (!TEST_ptr(_cb = BN_GENCB_new()))
        goto err3;
    BN_GENCB_set(_cb, &cb, NULL);
    if (!TEST_ptr(a = DH_new())
        || !TEST_true(DH_generate_parameters_ex(a, 512,
            DH_GENERATOR_5, _cb)))
        goto err3;

    /* ... and check whether it is valid */
    if (!TEST_true(DH_check(a, &i)))
```

## Call pattern 10

```c
goto err3;

    if (!TEST_true(aout >= 20)
        || !TEST_mem_eq(abuf, aout, bbuf, bout)
        || !TEST_mem_eq(abuf, aout, cbuf, cout))
        goto err3;

    ret = 1;
    goto success;

err1:
    /* an error occurred before p,q,g were assigned to dh */
    BN_free(p);
    BN_free(q);
    BN_free(g);
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}
```

## Call pattern 11

```c
if (!TEST_true(aout >= 20)
        || !TEST_mem_eq(abuf, aout, bbuf, bout)
        || !TEST_mem_eq(abuf, aout, cbuf, cout))
        goto err3;

    ret = 1;
    goto success;

err1:
    /* an error occurred before p,q,g were assigned to dh */
    BN_free(p);
    BN_free(q);
    BN_free(g);
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
```

## Call pattern 12

```c
if (!TEST_true(aout >= 20)
        || !TEST_mem_eq(abuf, aout, bbuf, bout)
        || !TEST_mem_eq(abuf, aout, cbuf, cout))
        goto err3;

    ret = 1;
    goto success;

err1:
    /* an error occurred before p,q,g were assigned to dh */
    BN_free(p);
    BN_free(q);
    BN_free(g);
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
{
```

## Call pattern 13

```c
goto err3;

    ret = 1;
    goto success;

err1:
    /* an error occurred before p,q,g were assigned to dh */
    BN_free(p);
    BN_free(q);
    BN_free(g);
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
{
    int ret = 0, sz;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
```

## Call pattern 14

```c
BN_free(g);
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
{
    int ret = 0, sz;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    unsigned char *buf = NULL;

    if (!TEST_ptr(p = BN_dup(&ossl_bignum_ffdhe2048_p))
        || !TEST_ptr(q = BN_dup(&ossl_bignum_ffdhe2048_q))
        || !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;
```

## Call pattern 15

```c
err2:
    /* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
{
    int ret = 0, sz;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    unsigned char *buf = NULL;

    if (!TEST_ptr(p = BN_dup(&ossl_bignum_ffdhe2048_p))
        || !TEST_ptr(q = BN_dup(&ossl_bignum_ffdhe2048_q))
        || !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;
```

## Call pattern 16

```c
/* an error occurred before priv_key was assigned to dh */
    BN_free(priv_key);
err3:
success:
    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);
    OPENSSL_free(cbuf);
    DH_free(b);
    DH_free(a);
    DH_free(c);
    BN_free(bp);
    BN_free(bg);
    BN_free(cpriv_key);
    BN_GENCB_free(_cb);
    DH_free(dh);

    return ret;
}

static int cb(int p, int n, BN_GENCB *arg)
{
    return 1;
}

static int dh_computekey_range_test(void)
{
    int ret = 0, sz;
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    unsigned char *buf = NULL;

    if (!TEST_ptr(p = BN_dup(&ossl_bignum_ffdhe2048_p))
        || !TEST_ptr(q = BN_dup(&ossl_bignum_ffdhe2048_q))
        || !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_int_gt(sz = DH_size(dh), 0)
```

## Call pattern 17

```c
unsigned char *buf = NULL;

    if (!TEST_ptr(p = BN_dup(&ossl_bignum_ffdhe2048_p))
        || !TEST_ptr(q = BN_dup(&ossl_bignum_ffdhe2048_q))
        || !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_int_gt(sz = DH_size(dh), 0)
        || !TEST_ptr(buf = OPENSSL_malloc(sz))
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_true(BN_set_word(priv, 1))
        || !TEST_true(DH_set0_key(dh, NULL, priv)))
        goto err;
    priv = NULL;
    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;

    /* Given z = pub ^ priv mod p */

    /* Test that z == 1 fails */
    if (!TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == 0 fails */
    if (!TEST_ptr(BN_copy(pub, DH_get0_p(dh)))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 1 fails */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;
```

## Call pattern 18

```c
if (!TEST_ptr(p = BN_dup(&ossl_bignum_ffdhe2048_p))
        || !TEST_ptr(q = BN_dup(&ossl_bignum_ffdhe2048_q))
        || !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_int_gt(sz = DH_size(dh), 0)
        || !TEST_ptr(buf = OPENSSL_malloc(sz))
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_true(BN_set_word(priv, 1))
        || !TEST_true(DH_set0_key(dh, NULL, priv)))
        goto err;
    priv = NULL;
    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;

    /* Given z = pub ^ priv mod p */

    /* Test that z == 1 fails */
    if (!TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == 0 fails */
    if (!TEST_ptr(BN_copy(pub, DH_get0_p(dh)))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 1 fails */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;
```

## Call pattern 19

```c
|| !TEST_ptr(g = BN_dup(&ossl_bignum_const_2))
        || !TEST_ptr(dh = DH_new())
        || !TEST_true(DH_set0_pqg(dh, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_int_gt(sz = DH_size(dh), 0)
        || !TEST_ptr(buf = OPENSSL_malloc(sz))
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_true(BN_set_word(priv, 1))
        || !TEST_true(DH_set0_key(dh, NULL, priv)))
        goto err;
    priv = NULL;
    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;

    /* Given z = pub ^ priv mod p */

    /* Test that z == 1 fails */
    if (!TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == 0 fails */
    if (!TEST_ptr(BN_copy(pub, DH_get0_p(dh)))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 1 fails */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
```

## Call pattern 20

```c
p = q = g = NULL;

    if (!TEST_int_gt(sz = DH_size(dh), 0)
        || !TEST_ptr(buf = OPENSSL_malloc(sz))
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_true(BN_set_word(priv, 1))
        || !TEST_true(DH_set0_key(dh, NULL, priv)))
        goto err;
    priv = NULL;
    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;

    /* Given z = pub ^ priv mod p */

    /* Test that z == 1 fails */
    if (!TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == 0 fails */
    if (!TEST_ptr(BN_copy(pub, DH_get0_p(dh)))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 1 fails */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
```

## Call pattern 21

```c
/* Test that z == p - 1 fails */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dh);
    return ret;
}

/* Test data from RFC 5114 */

static const unsigned char dhtest_1024_160_xA[] = {
    0xB9, 0xA3, 0xB3, 0xAE, 0x8F, 0xEF, 0xC1, 0xA2, 0x93, 0x04, 0x96, 0x50,
    0x70, 0x86, 0xF8, 0x45, 0x5D, 0x48, 0x94, 0x3E
};

static const unsigned char dhtest_1024_160_yA[] = {
    0x2A, 0x85, 0x3B, 0x3D, 0x92, 0x19, 0x75, 0x01, 0xB9, 0x01, 0x5B, 0x2D,
    0xEB, 0x3E, 0xD8, 0x4F, 0x5E, 0x02, 0x1D, 0xCC, 0x3E, 0x52, 0xF1, 0x09,
    0xD3, 0x27, 0x3D, 0x2B, 0x75, 0x21, 0x28, 0x1C, 0xBA, 0xBE, 0x0E, 0x76,
    0xFF, 0x57, 0x27, 0xFA, 0x8A, 0xCC, 0xE2, 0x69, 0x56, 0xBA, 0x9A, 0x1F,
    0xCA, 0x26, 0xF2, 0x02, 0x28, 0xD8, 0x69, 0x3F, 0xEB, 0x10, 0x84, 0x1D,
    0x84, 0xA7, 0x36, 0x00, 0x54, 0xEC, 0xE5, 0xA7, 0xF5, 0xB7, 0xA6, 0x1A,
    0xD3, 0xDF, 0xB3, 0xC6, 0x0D, 0x2E, 0x43, 0x10, 0x6D, 0x87, 0x27, 0xDA,
    0x37, 0xDF, 0x9C, 0xCE, 0x95, 0xB4, 0x78, 0x75, 0x5D, 0x06, 0xBC, 0xEA,
    0x8F, 0x9D, 0x45, 0x96, 0x5F, 0x75, 0xA5, 0xF3, 0xD1, 0xDF, 0x37, 0x01,
    0x16, 0x5F, 0xC9, 0xE5, 0x0C, 0x42, 0x79, 0xCE, 0xB0, 0x7F, 0x98, 0x95,
    0x40, 0xAE, 0x96, 0xD5, 0xD8, 0x8E, 0xD7, 0x76
```

## Call pattern 22

```c
if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dh);
    return ret;
}

/* Test data from RFC 5114 */

static const unsigned char dhtest_1024_160_xA[] = {
    0xB9, 0xA3, 0xB3, 0xAE, 0x8F, 0xEF, 0xC1, 0xA2, 0x93, 0x04, 0x96, 0x50,
    0x70, 0x86, 0xF8, 0x45, 0x5D, 0x48, 0x94, 0x3E
};

static const unsigned char dhtest_1024_160_yA[] = {
    0x2A, 0x85, 0x3B, 0x3D, 0x92, 0x19, 0x75, 0x01, 0xB9, 0x01, 0x5B, 0x2D,
    0xEB, 0x3E, 0xD8, 0x4F, 0x5E, 0x02, 0x1D, 0xCC, 0x3E, 0x52, 0xF1, 0x09,
    0xD3, 0x27, 0x3D, 0x2B, 0x75, 0x21, 0x28, 0x1C, 0xBA, 0xBE, 0x0E, 0x76,
    0xFF, 0x57, 0x27, 0xFA, 0x8A, 0xCC, 0xE2, 0x69, 0x56, 0xBA, 0x9A, 0x1F,
    0xCA, 0x26, 0xF2, 0x02, 0x28, 0xD8, 0x69, 0x3F, 0xEB, 0x10, 0x84, 0x1D,
    0x84, 0xA7, 0x36, 0x00, 0x54, 0xEC, 0xE5, 0xA7, 0xF5, 0xB7, 0xA6, 0x1A,
    0xD3, 0xDF, 0xB3, 0xC6, 0x0D, 0x2E, 0x43, 0x10, 0x6D, 0x87, 0x27, 0xDA,
    0x37, 0xDF, 0x9C, 0xCE, 0x95, 0xB4, 0x78, 0x75, 0x5D, 0x06, 0xBC, 0xEA,
    0x8F, 0x9D, 0x45, 0x96, 0x5F, 0x75, 0xA5, 0xF3, 0xD1, 0xDF, 0x37, 0x01,
    0x16, 0x5F, 0xC9, 0xE5, 0x0C, 0x42, 0x79, 0xCE, 0xB0, 0x7F, 0x98, 0x95,
    0x40, 0xAE, 0x96, 0xD5, 0xD8, 0x8E, 0xD7, 0x76
};
```

## Call pattern 23

```c
|| !TEST_int_le(ossl_dh_compute_key(buf, pub, dh), 0))
        goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dh);
    return ret;
}

/* Test data from RFC 5114 */

static const unsigned char dhtest_1024_160_xA[] = {
    0xB9, 0xA3, 0xB3, 0xAE, 0x8F, 0xEF, 0xC1, 0xA2, 0x93, 0x04, 0x96, 0x50,
    0x70, 0x86, 0xF8, 0x45, 0x5D, 0x48, 0x94, 0x3E
};

static const unsigned char dhtest_1024_160_yA[] = {
    0x2A, 0x85, 0x3B, 0x3D, 0x92, 0x19, 0x75, 0x01, 0xB9, 0x01, 0x5B, 0x2D,
    0xEB, 0x3E, 0xD8, 0x4F, 0x5E, 0x02, 0x1D, 0xCC, 0x3E, 0x52, 0xF1, 0x09,
    0xD3, 0x27, 0x3D, 0x2B, 0x75, 0x21, 0x28, 0x1C, 0xBA, 0xBE, 0x0E, 0x76,
    0xFF, 0x57, 0x27, 0xFA, 0x8A, 0xCC, 0xE2, 0x69, 0x56, 0xBA, 0x9A, 0x1F,
    0xCA, 0x26, 0xF2, 0x02, 0x28, 0xD8, 0x69, 0x3F, 0xEB, 0x10, 0x84, 0x1D,
    0x84, 0xA7, 0x36, 0x00, 0x54, 0xEC, 0xE5, 0xA7, 0xF5, 0xB7, 0xA6, 0x1A,
    0xD3, 0xDF, 0xB3, 0xC6, 0x0D, 0x2E, 0x43, 0x10, 0x6D, 0x87, 0x27, 0xDA,
    0x37, 0xDF, 0x9C, 0xCE, 0x95, 0xB4, 0x78, 0x75, 0x5D, 0x06, 0xBC, 0xEA,
    0x8F, 0x9D, 0x45, 0x96, 0x5F, 0x75, 0xA5, 0xF3, 0xD1, 0xDF, 0x37, 0x01,
    0x16, 0x5F, 0xC9, 0xE5, 0x0C, 0x42, 0x79, 0xCE, 0xB0, 0x7F, 0x98, 0x95,
    0x40, 0xAE, 0x96, 0xD5, 0xD8, 0x8E, 0xD7, 0x76
};
```

## Call pattern 24

```c
goto err;
    /* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dh);
    return ret;
}

/* Test data from RFC 5114 */

static const unsigned char dhtest_1024_160_xA[] = {
    0xB9, 0xA3, 0xB3, 0xAE, 0x8F, 0xEF, 0xC1, 0xA2, 0x93, 0x04, 0x96, 0x50,
    0x70, 0x86, 0xF8, 0x45, 0x5D, 0x48, 0x94, 0x3E
};

static const unsigned char dhtest_1024_160_yA[] = {
    0x2A, 0x85, 0x3B, 0x3D, 0x92, 0x19, 0x75, 0x01, 0xB9, 0x01, 0x5B, 0x2D,
    0xEB, 0x3E, 0xD8, 0x4F, 0x5E, 0x02, 0x1D, 0xCC, 0x3E, 0x52, 0xF1, 0x09,
    0xD3, 0x27, 0x3D, 0x2B, 0x75, 0x21, 0x28, 0x1C, 0xBA, 0xBE, 0x0E, 0x76,
    0xFF, 0x57, 0x27, 0xFA, 0x8A, 0xCC, 0xE2, 0x69, 0x56, 0xBA, 0x9A, 0x1F,
    0xCA, 0x26, 0xF2, 0x02, 0x28, 0xD8, 0x69, 0x3F, 0xEB, 0x10, 0x84, 0x1D,
    0x84, 0xA7, 0x36, 0x00, 0x54, 0xEC, 0xE5, 0xA7, 0xF5, 0xB7, 0xA6, 0x1A,
    0xD3, 0xDF, 0xB3, 0xC6, 0x0D, 0x2E, 0x43, 0x10, 0x6D, 0x87, 0x27, 0xDA,
    0x37, 0xDF, 0x9C, 0xCE, 0x95, 0xB4, 0x78, 0x75, 0x5D, 0x06, 0xBC, 0xEA,
    0x8F, 0x9D, 0x45, 0x96, 0x5F, 0x75, 0xA5, 0xF3, 0xD1, 0xDF, 0x37, 0x01,
    0x16, 0x5F, 0xC9, 0xE5, 0x0C, 0x42, 0x79, 0xCE, 0xB0, 0x7F, 0x98, 0x95,
    0x40, 0xAE, 0x96, 0xD5, 0xD8, 0x8E, 0xD7, 0x76
};

static const unsigned char dhtest_1024_160_xB[] = {
```

## Call pattern 25

```c
/* Test that z == p - 2 passes */
    if (!TEST_true(BN_sub_word(pub, 1))
        || !TEST_int_eq(ossl_dh_compute_key(buf, pub, dh), sz))
        goto err;

    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(priv);
    BN_free(pub);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DH_free(dh);
    return ret;
}

/* Test data from RFC 5114 */

static const unsigned char dhtest_1024_160_xA[] = {
    0xB9, 0xA3, 0xB3, 0xAE, 0x8F, 0xEF, 0xC1, 0xA2, 0x93, 0x04, 0x96, 0x50,
    0x70, 0x86, 0xF8, 0x45, 0x5D, 0x48, 0x94, 0x3E
};

static const unsigned char dhtest_1024_160_yA[] = {
    0x2A, 0x85, 0x3B, 0x3D, 0x92, 0x19, 0x75, 0x01, 0xB9, 0x01, 0x5B, 0x2D,
    0xEB, 0x3E, 0xD8, 0x4F, 0x5E, 0x02, 0x1D, 0xCC, 0x3E, 0x52, 0xF1, 0x09,
    0xD3, 0x27, 0x3D, 0x2B, 0x75, 0x21, 0x28, 0x1C, 0xBA, 0xBE, 0x0E, 0x76,
    0xFF, 0x57, 0x27, 0xFA, 0x8A, 0xCC, 0xE2, 0x69, 0x56, 0xBA, 0x9A, 0x1F,
    0xCA, 0x26, 0xF2, 0x02, 0x28, 0xD8, 0x69, 0x3F, 0xEB, 0x10, 0x84, 0x1D,
    0x84, 0xA7, 0x36, 0x00, 0x54, 0xEC, 0xE5, 0xA7, 0xF5, 0xB7, 0xA6, 0x1A,
    0xD3, 0xDF, 0xB3, 0xC6, 0x0D, 0x2E, 0x43, 0x10, 0x6D, 0x87, 0x27, 0xDA,
    0x37, 0xDF, 0x9C, 0xCE, 0x95, 0xB4, 0x78, 0x75, 0x5D, 0x06, 0xBC, 0xEA,
    0x8F, 0x9D, 0x45, 0x96, 0x5F, 0x75, 0xA5, 0xF3, 0xD1, 0xDF, 0x37, 0x01,
    0x16, 0x5F, 0xC9, 0xE5, 0x0C, 0x42, 0x79, 0xCE, 0xB0, 0x7F, 0x98, 0x95,
    0x40, 0xAE, 0x96, 0xD5, 0xD8, 0x8E, 0xD7, 0x76
};

static const unsigned char dhtest_1024_160_xB[] = {
    0x93, 0x92, 0xC9, 0xF9, 0xEB, 0x6A, 0x7A, 0x6A, 0x90, 0x22, 0xF7, 0xD8,
```

## Call pattern 26

```c
DH_free(dhB);
        dhB = NULL;
        OPENSSL_free(Z1);
        Z1 = NULL;
        OPENSSL_free(Z2);
        Z2 = NULL;
    }
    return 1;

bad_err:
    DH_free(dhA);
    DH_free(dhB);
    BN_free(pub_key);
    BN_free(priv_key);
    OPENSSL_free(Z1);
    OPENSSL_free(Z2);
    TEST_error("Initialisation error RFC5114 set %d\n", i + 1);
    return 0;

err:
    DH_free(dhA);
    DH_free(dhB);
    OPENSSL_free(Z1);
    OPENSSL_free(Z2);
    TEST_error("Test failed RFC5114 set %d\n", i + 1);
    return 0;
}

static int rfc7919_test(void)
{
    DH *a = NULL, *b = NULL;
    const BIGNUM *apub_key = NULL, *bpub_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    int i, alen, blen, aout, bout;
    int ret = 0;

    if (!TEST_ptr(a = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
```

## Call pattern 27

```c
dhB = NULL;
        OPENSSL_free(Z1);
        Z1 = NULL;
        OPENSSL_free(Z2);
        Z2 = NULL;
    }
    return 1;

bad_err:
    DH_free(dhA);
    DH_free(dhB);
    BN_free(pub_key);
    BN_free(priv_key);
    OPENSSL_free(Z1);
    OPENSSL_free(Z2);
    TEST_error("Initialisation error RFC5114 set %d\n", i + 1);
    return 0;

err:
    DH_free(dhA);
    DH_free(dhB);
    OPENSSL_free(Z1);
    OPENSSL_free(Z2);
    TEST_error("Test failed RFC5114 set %d\n", i + 1);
    return 0;
}

static int rfc7919_test(void)
{
    DH *a = NULL, *b = NULL;
    const BIGNUM *apub_key = NULL, *bpub_key = NULL;
    unsigned char *abuf = NULL;
    unsigned char *bbuf = NULL;
    int i, alen, blen, aout, bout;
    int ret = 0;

    if (!TEST_ptr(a = DH_new_by_nid(NID_ffdhe2048)))
        goto err;

    if (!DH_check(a, &i))
```

## Call pattern 28

```c
if (!TEST_ptr(pcpy = BN_dup(p))
        || !TEST_ptr(qcpy = BN_dup(q))
        || !TEST_ptr(gcpy = BN_dup(g))
        || !TEST_int_eq(BN_add_word(qcpy, 2), 1)
        || !TEST_true(DH_set0_pqg(dh2, pcpy, qcpy, gcpy)))
        goto err;
    pcpy = qcpy = gcpy = NULL;
    if (!TEST_int_eq(DH_get_nid(dh2), NID_undef))
        goto err;

    ok = 1;
err:
    BN_free(pcpy);
    BN_free(qcpy);
    BN_free(gcpy);
    DH_free(dh2);
    DH_free(dh1);
    return ok;
}

static const unsigned char dh_pub_der[] = {
    0x30, 0x82, 0x02, 0x28, 0x30, 0x82, 0x01, 0x1b, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x0c, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
    0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79,
    0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b,
    0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d,
    0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6,
    0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5,
    0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51,
    0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8,
    0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96,
    0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07,
    0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46,
    0x2e, 0x36, 0xce, 0x3b, 0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03,
```

## Call pattern 29

```c
|| !TEST_ptr(qcpy = BN_dup(q))
        || !TEST_ptr(gcpy = BN_dup(g))
        || !TEST_int_eq(BN_add_word(qcpy, 2), 1)
        || !TEST_true(DH_set0_pqg(dh2, pcpy, qcpy, gcpy)))
        goto err;
    pcpy = qcpy = gcpy = NULL;
    if (!TEST_int_eq(DH_get_nid(dh2), NID_undef))
        goto err;

    ok = 1;
err:
    BN_free(pcpy);
    BN_free(qcpy);
    BN_free(gcpy);
    DH_free(dh2);
    DH_free(dh1);
    return ok;
}

static const unsigned char dh_pub_der[] = {
    0x30, 0x82, 0x02, 0x28, 0x30, 0x82, 0x01, 0x1b, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x0c, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
    0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79,
    0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b,
    0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d,
    0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6,
    0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5,
    0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51,
    0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8,
    0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96,
    0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07,
    0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46,
    0x2e, 0x36, 0xce, 0x3b, 0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03,
    0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0,
```

## Call pattern 30

```c
|| !TEST_ptr(gcpy = BN_dup(g))
        || !TEST_int_eq(BN_add_word(qcpy, 2), 1)
        || !TEST_true(DH_set0_pqg(dh2, pcpy, qcpy, gcpy)))
        goto err;
    pcpy = qcpy = gcpy = NULL;
    if (!TEST_int_eq(DH_get_nid(dh2), NID_undef))
        goto err;

    ok = 1;
err:
    BN_free(pcpy);
    BN_free(qcpy);
    BN_free(gcpy);
    DH_free(dh2);
    DH_free(dh1);
    return ok;
}

static const unsigned char dh_pub_der[] = {
    0x30, 0x82, 0x02, 0x28, 0x30, 0x82, 0x01, 0x1b, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01, 0x30, 0x82, 0x01, 0x0c, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
    0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79,
    0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b,
    0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d,
    0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6,
    0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5,
    0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51,
    0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8,
    0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96,
    0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07,
    0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46,
    0x2e, 0x36, 0xce, 0x3b, 0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03,
    0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0,
    0x6f, 0x4c, 0x52, 0xc9, 0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18,
```

