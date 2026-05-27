# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/ffc_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    /* incorrect g */
    BN_add_word(g1, 1);
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    /* fail if g < 2 */
    BN_set_word(g1, 1);
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    BN_copy(g1, p1);
    /* Fail if g >= p */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return ret;
}

static int ffc_params_validate_pq_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;
    BIGNUM *p = NULL, *q = NULL;
```

## Call pattern 2

```c
goto err;

    BN_copy(g1, p1);
    /* Fail if g >= p */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return ret;
}

static int ffc_params_validate_pq_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;
    BIGNUM *p = NULL, *q = NULL;

    ossl_ffc_params_init(&params);
    if (!TEST_ptr(p = BN_bin2bn(dsa_2048_224_sha224_p,
                      sizeof(dsa_2048_224_sha224_p),
                      NULL)))
        goto err;
    if (!TEST_ptr(q = BN_bin2bn(dsa_2048_224_sha224_q,
                      sizeof(dsa_2048_224_sha224_q),
                      NULL)))
        goto err;

    /* No p */
    ossl_ffc_params_set0_pqg(&params, NULL, q, NULL);
    q = NULL;
    ossl_ffc_params_set_flags(&params, FFC_PARAM_FLAG_VALIDATE_PQ);
    ossl_ffc_set_digest(&params, "SHA224", NULL);
```

## Call pattern 3

```c
BN_copy(g1, p1);
    /* Fail if g >= p */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return ret;
}

static int ffc_params_validate_pq_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;
    BIGNUM *p = NULL, *q = NULL;

    ossl_ffc_params_init(&params);
    if (!TEST_ptr(p = BN_bin2bn(dsa_2048_224_sha224_p,
                      sizeof(dsa_2048_224_sha224_p),
                      NULL)))
        goto err;
    if (!TEST_ptr(q = BN_bin2bn(dsa_2048_224_sha224_q,
                      sizeof(dsa_2048_224_sha224_q),
                      NULL)))
        goto err;

    /* No p */
    ossl_ffc_params_set0_pqg(&params, NULL, q, NULL);
    q = NULL;
    ossl_ffc_params_set_flags(&params, FFC_PARAM_FLAG_VALIDATE_PQ);
    ossl_ffc_set_digest(&params, "SHA224", NULL);

    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
```

## Call pattern 4

```c
BN_copy(g1, p1);
    /* Fail if g >= p */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return ret;
}

static int ffc_params_validate_pq_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;
    BIGNUM *p = NULL, *q = NULL;

    ossl_ffc_params_init(&params);
    if (!TEST_ptr(p = BN_bin2bn(dsa_2048_224_sha224_p,
                      sizeof(dsa_2048_224_sha224_p),
                      NULL)))
        goto err;
    if (!TEST_ptr(q = BN_bin2bn(dsa_2048_224_sha224_q,
                      sizeof(dsa_2048_224_sha224_q),
                      NULL)))
        goto err;

    /* No p */
    ossl_ffc_params_set0_pqg(&params, NULL, q, NULL);
    q = NULL;
    ossl_ffc_params_set_flags(&params, FFC_PARAM_FLAG_VALIDATE_PQ);
    ossl_ffc_set_digest(&params, "SHA224", NULL);

    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
```

## Call pattern 5

```c
&res, NULL)))
        goto err;

    /* Bad L/N for FIPS DH */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int ffc_params_gen_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;

    ossl_ffc_params_init(&params);
    if (!TEST_true(ossl_ffc_params_FIPS186_4_generate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            2048, 256, &res, NULL)))
        goto err;
    if (!TEST_true(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    return ret;
}
```

## Call pattern 6

```c
goto err;

    /* Bad L/N for FIPS DH */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    BN_free(p);
    BN_free(q);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int ffc_params_gen_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;

    ossl_ffc_params_init(&params);
    if (!TEST_true(ossl_ffc_params_FIPS186_4_generate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            2048, 256, &res, NULL)))
        goto err;
    if (!TEST_true(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            &res, NULL)))
        goto err;

    ret = 1;
err:
    ossl_ffc_params_cleanup(&params);
    return ret;
}

static int ffc_params_gen_canonicalg_test(void)
```

## Call pattern 7

```c
err:
    ossl_ffc_params_cleanup(&params);
    return ret;
}

static int ffc_params_fips186_2_gen_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS params;
    BIGNUM *bn = NULL;

    ossl_ffc_params_init(&params);
    if (!TEST_ptr(bn = BN_new()))
        goto err;
    if (!TEST_true(ossl_ffc_params_FIPS186_2_generate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            1024, 160, &res, NULL)))
        goto err;
    if (!TEST_true(ossl_ffc_params_FIPS186_2_validate(NULL, &params,
            FFC_PARAM_TYPE_DH,
            &res, NULL)))
        goto err;

    /*
     * The fips186-2 generation should produce a different q compared to
     * fips 186-4 given the same seed value. So validation of q will fail.
     */
    if (!TEST_false(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
            FFC_PARAM_TYPE_DSA,
            &res, NULL)))
        goto err;
    /* As the params are randomly generated the error is one of the following */
    if (!TEST_true(res == FFC_CHECK_Q_MISMATCH || res == FFC_CHECK_Q_NOT_PRIME))
        goto err;

    ossl_ffc_params_set_flags(&params, FFC_PARAM_FLAG_VALIDATE_G);
    /* Partially valid g test will still pass */
    if (!TEST_int_eq(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
                         FFC_PARAM_TYPE_DSA,
                         &res, NULL),
```

## Call pattern 8

```c
/* Partially valid g test will still pass */
    if (!TEST_int_eq(ossl_ffc_params_FIPS186_4_validate(NULL, &params,
                         FFC_PARAM_TYPE_DSA,
                         &res, NULL),
            2))
        goto err;

    if (!TEST_true(ossl_ffc_params_print(bio_out, &params, 4)))
        goto err;

    ret = 1;
err:
    BN_free(bn);
    ossl_ffc_params_cleanup(&params);
    return ret;
}

extern FFC_PARAMS *ossl_dh_get0_params(DH *dh);

static int ffc_public_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *pub = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(pub = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;
    BN_set_negative(pub, 1);
    /* Check must succeed but set res if public key is negative */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
```

## Call pattern 9

```c
return ret;
}

extern FFC_PARAMS *ossl_dh_get0_params(DH *dh);

static int ffc_public_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *pub = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(pub = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;
    BN_set_negative(pub, 1);
    /* Check must succeed but set res if public key is negative */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_set_word(pub, 0)))
        goto err;
    /* Check must succeed but set res if public key is zero */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    /* Check must succeed but set res if public key is 1 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, BN_value_one(), &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_add_word(pub, 2)))
```

## Call pattern 10

```c
int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *pub = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(pub = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;
    BN_set_negative(pub, 1);
    /* Check must succeed but set res if public key is negative */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_set_word(pub, 0)))
        goto err;
    /* Check must succeed but set res if public key is zero */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    /* Check must succeed but set res if public key is 1 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, BN_value_one(), &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_add_word(pub, 2)))
        goto err;
    /* Pass if public key >= 2 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;

    if (!TEST_ptr(BN_copy(pub, params->p)))
        goto err;
```

## Call pattern 11

```c
BIGNUM *pub = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(pub = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;
    BN_set_negative(pub, 1);
    /* Check must succeed but set res if public key is negative */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_set_word(pub, 0)))
        goto err;
    /* Check must succeed but set res if public key is zero */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    /* Check must succeed but set res if public key is 1 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, BN_value_one(), &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_add_word(pub, 2)))
        goto err;
    /* Pass if public key >= 2 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;

    if (!TEST_ptr(BN_copy(pub, params->p)))
        goto err;
    /* Check must succeed but set res if public key = p */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
```

## Call pattern 12

```c
if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(pub, 1)))
        goto err;
    BN_set_negative(pub, 1);
    /* Check must succeed but set res if public key is negative */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_set_word(pub, 0)))
        goto err;
    /* Check must succeed but set res if public key is zero */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    /* Check must succeed but set res if public key is 1 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, BN_value_one(), &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_SMALL, res))
        goto err;
    if (!TEST_true(BN_add_word(pub, 2)))
        goto err;
    /* Pass if public key >= 2 */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;

    if (!TEST_ptr(BN_copy(pub, params->p)))
        goto err;
    /* Check must succeed but set res if public key = p */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PUBKEY_TOO_LARGE, res))
        goto err;

    if (!TEST_true(BN_sub_word(pub, 1)))
        goto err;
```

## Call pattern 13

```c
if (!TEST_true(ossl_ffc_validate_public_key(NULL, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;
    res = -1;
    /* Check must succeed but set res if pubkey is NULL */
    if (!TEST_true(ossl_ffc_validate_public_key(params, NULL, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;
    res = -1;

    BN_free(params->p);
    params->p = NULL;
    /* Check must succeed but set res if params->p is NULL */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;

    ret = 1;
err:
    DH_free(dh);
    BN_free(pub);
    return ret;
}

static int ffc_private_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);
```

## Call pattern 14

```c
BN_free(params->p);
    params->p = NULL;
    /* Check must succeed but set res if params->p is NULL */
    if (!TEST_true(ossl_ffc_validate_public_key(params, pub, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;

    ret = 1;
err:
    DH_free(dh);
    BN_free(pub);
    return ret;
}

static int ffc_private_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(priv, 1)))
        goto err;
    BN_set_negative(priv, 1);
    /* Fail if priv key is negative */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    if (!TEST_true(BN_set_word(priv, 0)))
```

## Call pattern 15

```c
DH_free(dh);
    BN_free(pub);
    return ret;
}

static int ffc_private_validate_test(void)
{
    int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(priv, 1)))
        goto err;
    BN_set_negative(priv, 1);
    /* Fail if priv key is negative */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    if (!TEST_true(BN_set_word(priv, 0)))
        goto err;
    /* Fail if priv key is zero */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    /* Pass if priv key >= 1 */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, BN_value_one(),
            &res)))
        goto err;
```

## Call pattern 16

```c
int ret = 0, res = -1;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(priv, 1)))
        goto err;
    BN_set_negative(priv, 1);
    /* Fail if priv key is negative */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    if (!TEST_true(BN_set_word(priv, 0)))
        goto err;
    /* Fail if priv key is zero */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    /* Pass if priv key >= 1 */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, BN_value_one(),
            &res)))
        goto err;

    if (!TEST_ptr(BN_copy(priv, params->q)))
        goto err;
    /* Fail if priv key = upper */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_LARGE, res))
```

## Call pattern 17

```c
BIGNUM *priv = NULL;
    DH *dh = NULL;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(priv, 1)))
        goto err;
    BN_set_negative(priv, 1);
    /* Fail if priv key is negative */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    if (!TEST_true(BN_set_word(priv, 0)))
        goto err;
    /* Fail if priv key is zero */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    /* Pass if priv key >= 1 */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, BN_value_one(),
            &res)))
        goto err;

    if (!TEST_ptr(BN_copy(priv, params->q)))
        goto err;
    /* Fail if priv key = upper */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_LARGE, res))
        goto err;
```

## Call pattern 18

```c
goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_true(BN_set_word(priv, 1)))
        goto err;
    BN_set_negative(priv, 1);
    /* Fail if priv key is negative */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    if (!TEST_true(BN_set_word(priv, 0)))
        goto err;
    /* Fail if priv key is zero */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_SMALL, res))
        goto err;

    /* Pass if priv key >= 1 */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, BN_value_one(),
            &res)))
        goto err;

    if (!TEST_ptr(BN_copy(priv, params->q)))
        goto err;
    /* Fail if priv key = upper */
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PRIVKEY_TOO_LARGE, res))
        goto err;

    if (!TEST_true(BN_sub_word(priv, 1)))
        goto err;
    /* Pass if priv key <= upper - 1 */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;

    if (!TEST_false(ossl_ffc_validate_private_key(NULL, priv, &res)))
```

## Call pattern 19

```c
goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;
    res = -1;
    if (!TEST_false(ossl_ffc_validate_private_key(params->q, NULL, &res)))
        goto err;
    if (!TEST_int_eq(FFC_ERROR_PASSED_NULL_PARAM, res))
        goto err;

    ret = 1;
err:
    DH_free(dh);
    BN_free(priv);
    return ret;
}

static int ffc_private_gen_test(int index)
{
    int ret = 0, res = -1, N;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = BN_CTX_new_ex(NULL)))
        goto err;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    N = BN_num_bits(params->q);
    /* Fail since N < 2*s - where s = 112*/
    if (!TEST_false(ossl_ffc_generate_private_key(ctx, params, 220, 112, priv)))
        goto err;
    /* fail since N > len(q) */
    if (!TEST_false(ossl_ffc_generate_private_key(ctx, params, N + 1, 112, priv)))
```

## Call pattern 20

```c
static int ffc_private_gen_test(int index)
{
    int ret = 0, res = -1, N;
    FFC_PARAMS *params;
    BIGNUM *priv = NULL;
    DH *dh = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = BN_CTX_new_ex(NULL)))
        goto err;

    if (!TEST_ptr(priv = BN_new()))
        goto err;

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe2048)))
        goto err;
    params = ossl_dh_get0_params(dh);

    N = BN_num_bits(params->q);
    /* Fail since N < 2*s - where s = 112*/
    if (!TEST_false(ossl_ffc_generate_private_key(ctx, params, 220, 112, priv)))
        goto err;
    /* fail since N > len(q) */
    if (!TEST_false(ossl_ffc_generate_private_key(ctx, params, N + 1, 112, priv)))
        goto err;
    /* s must be always set */
    if (!TEST_false(ossl_ffc_generate_private_key(ctx, params, N, 0, priv)))
        goto err;
    /* pass since 2s <= N <= len(q) */
    if (!TEST_true(ossl_ffc_generate_private_key(ctx, params, N, 112, priv)))
        goto err;
    /* pass since N = len(q) */
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
    /* pass since 2s <= N < len(q) */
    if (!TEST_true(ossl_ffc_generate_private_key(ctx, params, N / 2, 112, priv)))
        goto err;
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;
```

## Call pattern 21

```c
if (!TEST_true(ossl_ffc_generate_private_key(ctx, params, 0,
            ossl_ifc_ffc_compute_security_bits(BN_num_bits(params->p)),
            priv)))
        goto err;
    if (!TEST_int_le(BN_num_bits(priv), 225))
        goto err;
    if (!TEST_true(ossl_ffc_validate_private_key(params->q, priv, &res)))
        goto err;

    ret = 1;
err:
    DH_free(dh);
    BN_free(priv);
    BN_CTX_free(ctx);
    return ret;
}

static int ffc_params_copy_test(void)
{
    int ret = 0;
    DH *dh = NULL;
    FFC_PARAMS *params, copy;

    ossl_ffc_params_init(&copy);

    if (!TEST_ptr(dh = DH_new_by_nid(NID_ffdhe3072)))
        goto err;
    params = ossl_dh_get0_params(dh);

    if (!TEST_int_eq(params->keylength, 275))
        goto err;

    if (!TEST_true(ossl_ffc_params_copy(&copy, params)))
        goto err;

    if (!TEST_int_eq(copy.keylength, 275))
        goto err;

    if (!TEST_true(ossl_ffc_params_cmp(&copy, params, 0)))
        goto err;
```

