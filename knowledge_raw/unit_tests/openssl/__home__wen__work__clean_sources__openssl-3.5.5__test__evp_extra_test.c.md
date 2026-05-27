# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/evp_extra_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
OSSL_PARAM *params = NULL;
    EVP_PKEY *just_params = NULL;
    EVP_PKEY *params_and_priv = NULL;
    EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
```

## Call pattern 2

```c
EVP_PKEY *just_params = NULL;
    EVP_PKEY *params_and_priv = NULL;
    EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
```

## Call pattern 3

```c
EVP_PKEY *params_and_priv = NULL;
    EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
```

## Call pattern 4

```c
EVP_PKEY *params_and_pub = NULL;
    EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
```

## Call pattern 5

```c
EVP_PKEY *params_and_keypair = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our pkey object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;

    /* Test !priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld))
        || !TEST_ptr(just_params = make_key_fromdata(keytype, params)))
        goto err;

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    params = NULL;
    bld = NULL;

    if (!test_selection(just_params, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)
        || test_selection(just_params, OSSL_KEYMGMT_SELECT_KEYPAIR))
        goto err;

    /* Test priv and !pub */
    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
```

## Call pattern 6

```c
if (!test_selection(params_and_keypair, EVP_PKEY_KEYPAIR))
        goto err;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted for EC keys
 */
#ifndef OPENSSL_NO_EC
static unsigned char ec_priv[] = {
    0xe9, 0x25, 0xf7, 0x66, 0x58, 0xa4, 0xdd, 0x99, 0x61, 0xe7, 0xe8, 0x23,
    0x85, 0xc2, 0xe8, 0x33, 0x27, 0xc5, 0x5c, 0xeb, 0xdb, 0x43, 0x9f, 0xd5,
    0xf2, 0x5a, 0x75, 0x55, 0xd0, 0x2e, 0x6d, 0x16
};
static unsigned char ec_pub[] = {
    0x04, 0xad, 0x11, 0x90, 0x77, 0x4b, 0x46, 0xee, 0x72, 0x51, 0x15, 0x97,
    0x4a, 0x6a, 0xa7, 0xaf, 0x59, 0xfa, 0x4b, 0xf2, 0x41, 0xc8, 0x3a, 0x81,
    0x23, 0xb6, 0x90, 0x04, 0x6c, 0x67, 0x66, 0xd0, 0xdc, 0xf2, 0x15, 0x1d,
    0x41, 0x61, 0xb7, 0x95, 0x85, 0x38, 0x5a, 0x84, 0x56, 0xe8, 0xb3, 0x0e,
    0xf5, 0xc6, 0x5d, 0xa4, 0x54, 0x26, 0xb0, 0xf7, 0xa5, 0x4a, 0x33, 0xf1,
    0x08, 0x09, 0xb8, 0xdb, 0x03
};
```

## Call pattern 7

```c
goto err;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted for EC keys
 */
#ifndef OPENSSL_NO_EC
static unsigned char ec_priv[] = {
    0xe9, 0x25, 0xf7, 0x66, 0x58, 0xa4, 0xdd, 0x99, 0x61, 0xe7, 0xe8, 0x23,
    0x85, 0xc2, 0xe8, 0x33, 0x27, 0xc5, 0x5c, 0xeb, 0xdb, 0x43, 0x9f, 0xd5,
    0xf2, 0x5a, 0x75, 0x55, 0xd0, 0x2e, 0x6d, 0x16
};
static unsigned char ec_pub[] = {
    0x04, 0xad, 0x11, 0x90, 0x77, 0x4b, 0x46, 0xee, 0x72, 0x51, 0x15, 0x97,
    0x4a, 0x6a, 0xa7, 0xaf, 0x59, 0xfa, 0x4b, 0xf2, 0x41, 0xc8, 0x3a, 0x81,
    0x23, 0xb6, 0x90, 0x04, 0x6c, 0x67, 0x66, 0xd0, 0xdc, 0xf2, 0x15, 0x1d,
    0x41, 0x61, 0xb7, 0x95, 0x85, 0x38, 0x5a, 0x84, 0x56, 0xe8, 0xb3, 0x0e,
    0xf5, 0xc6, 0x5d, 0xa4, 0x54, 0x26, 0xb0, 0xf7, 0xa5, 0x4a, 0x33, 0xf1,
    0x08, 0x09, 0xb8, 0xdb, 0x03
};

static int test_EC_priv_pub(void)
```

## Call pattern 8

```c
ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted for EC keys
 */
#ifndef OPENSSL_NO_EC
static unsigned char ec_priv[] = {
    0xe9, 0x25, 0xf7, 0x66, 0x58, 0xa4, 0xdd, 0x99, 0x61, 0xe7, 0xe8, 0x23,
    0x85, 0xc2, 0xe8, 0x33, 0x27, 0xc5, 0x5c, 0xeb, 0xdb, 0x43, 0x9f, 0xd5,
    0xf2, 0x5a, 0x75, 0x55, 0xd0, 0x2e, 0x6d, 0x16
};
static unsigned char ec_pub[] = {
    0x04, 0xad, 0x11, 0x90, 0x77, 0x4b, 0x46, 0xee, 0x72, 0x51, 0x15, 0x97,
    0x4a, 0x6a, 0xa7, 0xaf, 0x59, 0xfa, 0x4b, 0xf2, 0x41, 0xc8, 0x3a, 0x81,
    0x23, 0xb6, 0x90, 0x04, 0x6c, 0x67, 0x66, 0xd0, 0xdc, 0xf2, 0x15, 0x1d,
    0x41, 0x61, 0xb7, 0x95, 0x85, 0x38, 0x5a, 0x84, 0x56, 0xe8, 0xb3, 0x0e,
    0xf5, 0xc6, 0x5d, 0xa4, 0x54, 0x26, 0xb0, 0xf7, 0xa5, 0x4a, 0x33, 0xf1,
    0x08, 0x09, 0xb8, 0xdb, 0x03
};

static int test_EC_priv_pub(void)
{
```

## Call pattern 9

```c
ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}
#endif /* !OPENSSL_NO_DH || !OPENSSL_NO_DSA */

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted for EC keys
 */
#ifndef OPENSSL_NO_EC
static unsigned char ec_priv[] = {
    0xe9, 0x25, 0xf7, 0x66, 0x58, 0xa4, 0xdd, 0x99, 0x61, 0xe7, 0xe8, 0x23,
    0x85, 0xc2, 0xe8, 0x33, 0x27, 0xc5, 0x5c, 0xeb, 0xdb, 0x43, 0x9f, 0xd5,
    0xf2, 0x5a, 0x75, 0x55, 0xd0, 0x2e, 0x6d, 0x16
};
static unsigned char ec_pub[] = {
    0x04, 0xad, 0x11, 0x90, 0x77, 0x4b, 0x46, 0xee, 0x72, 0x51, 0x15, 0x97,
    0x4a, 0x6a, 0xa7, 0xaf, 0x59, 0xfa, 0x4b, 0xf2, 0x41, 0xc8, 0x3a, 0x81,
    0x23, 0xb6, 0x90, 0x04, 0x6c, 0x67, 0x66, 0xd0, 0xdc, 0xf2, 0x15, 0x1d,
    0x41, 0x61, 0xb7, 0x95, 0x85, 0x38, 0x5a, 0x84, 0x56, 0xe8, 0xb3, 0x0e,
    0xf5, 0xc6, 0x5d, 0xa4, 0x54, 0x26, 0xb0, 0xf7, 0xa5, 0x4a, 0x33, 0xf1,
    0x08, 0x09, 0xb8, 0xdb, 0x03
};

static int test_EC_priv_pub(void)
{
    OSSL_PARAM_BLD *bld = NULL;
```

## Call pattern 10

```c
buffer, 10, &len),
            0))
        goto err;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(just_params);
    EVP_PKEY_free(params_and_priv);
    EVP_PKEY_free(params_and_pub);
    EVP_PKEY_free(params_and_keypair);
    BN_free(priv);

    return ret;
}

/* Also test that we can read the EC PUB affine coordinates */
static int test_evp_get_ec_pub(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pad = NULL;
    EVP_PKEY *keypair = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int ret = 0;

    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    if (!TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_true(OSSL_PARAM_BLD_push_utf8_string(bld,
            OSSL_PKEY_PARAM_GROUP_NAME,
            "P-256", 0))
        || !TEST_true(OSSL_PARAM_BLD_push_octet_string(bld,
            OSSL_PKEY_PARAM_PUB_KEY,
            ec_pub, sizeof(ec_pub)))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
```

## Call pattern 11

```c
if (!test_selection(keypair, EVP_PKEY_KEYPAIR))
        goto err;

    if (!EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_X, &x)
        || !EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_Y, &y))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);
    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;
```

## Call pattern 12

```c
if (!test_selection(keypair, EVP_PKEY_KEYPAIR))
        goto err;

    if (!EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_X, &x)
        || !EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_EC_PUB_Y, &y))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);
    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;

    /* Create the low level EC_KEY */
```

## Call pattern 13

```c
BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);
    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;

    /* Create the low level EC_KEY */
    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!TEST_ptr(eckey))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
        goto err;

    pkey = EVP_PKEY_new();
```

## Call pattern 14

```c
BN_bn2bin(y, &pad[33]);
    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;

    /* Create the low level EC_KEY */
    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!TEST_ptr(eckey))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
        goto err;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
```

## Call pattern 15

```c
if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);
    return ret;
}

/* Test that using a legacy EC key with only a private key in it works */
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EC_priv_only_legacy(void)
{
    BIGNUM *priv = NULL;
    int ret = 0;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    EVP_MD_CTX *ctx = NULL;

    /* Create the low level EC_KEY */
    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!TEST_ptr(eckey))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
        goto err;

    pkey = EVP_PKEY_new();
    if (!TEST_ptr(pkey))
        goto err;
```

## Call pattern 16

```c
ret = TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), -2);
        EVP_PKEY_free(pkey);
        pkey = dup_pk;
        if (!ret)
            goto err;
    }
    ret = 1;

err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    BN_free(priv);

    return ret;
}

static int test_evp_get_ec_pub_legacy(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    unsigned char *pad = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int ret = 0;

    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
        goto err;

    /* Create the legacy key */
    if (!TEST_ptr(eckey = EC_KEY_new_by_curve_name_ex(libctx, NULL,
                      NID_X9_62_prime256v1)))
        goto err;

    if (!TEST_ptr(priv = BN_bin2bn(ec_priv, sizeof(ec_priv), NULL)))
        goto err;

    if (!TEST_true(EC_KEY_set_private_key(eckey, priv)))
```

## Call pattern 17

```c
if (!TEST_true(EVP_PKEY_assign_EC_KEY(pkey, eckey)))
        goto err;
    eckey = NULL;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x))
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);

    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
```

## Call pattern 18

```c
goto err;
    eckey = NULL;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x))
        || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)))
        goto err;

    if (!TEST_ptr(pad = OPENSSL_zalloc(sizeof(ec_pub))))
        goto err;

    pad[0] = ec_pub[0];
    BN_bn2bin(x, &pad[1]);
    BN_bn2bin(y, &pad[33]);

    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
```

## Call pattern 19

```c
BN_bn2bin(y, &pad[33]);

    if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char tbs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    };

    if (tst == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
            goto out;
    } else if (tst == 1) {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
            goto out;
```

## Call pattern 20

```c
if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char tbs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    };

    if (tst == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
            goto out;
    } else if (tst == 1) {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
            goto out;
#else
```

## Call pattern 21

```c
if (!TEST_true(memcmp(ec_pub, pad, sizeof(ec_pub)) == 0))
        goto err;

    ret = 1;

err:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
    OPENSSL_free(pad);
    BN_free(priv);
    BN_free(x);
    BN_free(y);

    return ret;
}
#endif /* OPENSSL_NO_DEPRECATED_3_0 */
#endif /* OPENSSL_NO_EC */

static int test_EVP_PKEY_sign(int tst)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0, shortsig_len = 1;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char tbs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    };

    if (tst == 0) {
        if (!TEST_ptr(pkey = load_example_rsa_key()))
            goto out;
    } else if (tst == 1) {
#ifndef OPENSSL_NO_DSA
        if (!TEST_ptr(pkey = load_example_dsa_key()))
            goto out;
#else
        ret = 1;
```

## Call pattern 22

```c
OSSL_PARAM *params = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);
```

## Call pattern 23

```c
BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
```

## Call pattern 24

```c
EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
```

## Call pattern 25

```c
EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
```

## Call pattern 26

```c
int ret = 0;

    /*
     * Setup the parameters for our DSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "DSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(q = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pub = BN_new())
        || !TEST_ptr(priv = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pub))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            priv)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
```

## Call pattern 27

```c
goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;
```

## Call pattern 28

```c
if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;
```

## Call pattern 29

```c
if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
```

## Call pattern 30

```c
goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
```

## Call pattern 31

```c
ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);

    return ret;
}

/*
 * Test combinations of private, public, missing and private + public key
 * params to ensure they are all accepted
 */
static int test_DSA_priv_pub(void)
{
    return test_EVP_PKEY_ffc_priv_pub("DSA");
}

#endif /* !OPENSSL_NO_DSA */

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
```

## Call pattern 32

```c
OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
```

## Call pattern 33

```c
BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
```

## Call pattern 34

```c
EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                            params),
            0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);
```

## Call pattern 35

```c
goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

static int test_RSA_OAEP_set_get_params(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    {
        int padding = RSA_PKCS1_OAEP_PADDING;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
            OSSL_DIGEST_NAME_SHA2_256, 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
```

## Call pattern 36

```c
if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

static int test_RSA_OAEP_set_get_params(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    {
        int padding = RSA_PKCS1_OAEP_PADDING;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
            OSSL_DIGEST_NAME_SHA2_256, 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
            OSSL_DIGEST_NAME_SHA1, 0);
```

## Call pattern 37

```c
if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

static int test_RSA_OAEP_set_get_params(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    {
        int padding = RSA_PKCS1_OAEP_PADDING;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
            OSSL_DIGEST_NAME_SHA2_256, 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
            OSSL_DIGEST_NAME_SHA1, 0);
        params[3] = OSSL_PARAM_construct_end();
```

## Call pattern 38

```c
rsa = NULL;

    if (!TEST_true(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)))
        goto err;

    ret = 1;

err:
    RSA_free(rsa);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
static int test_decrypt_null_chunks(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1
    };
    unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    unsigned char msg[] = "It was the best of times, it was the worst of times";
    unsigned char ciphertext[80];
    unsigned char plaintext[80];
    /* We initialise tmp to a non zero value on purpose */
    int ctlen, ptlen, tmp = 99;
```

## Call pattern 39

```c
rsa = NULL;

    if (!TEST_true(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)))
        goto err;

    ret = 1;

err:
    RSA_free(rsa);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
static int test_decrypt_null_chunks(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1
    };
    unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    unsigned char msg[] = "It was the best of times, it was the worst of times";
    unsigned char ciphertext[80];
    unsigned char plaintext[80];
    /* We initialise tmp to a non zero value on purpose */
    int ctlen, ptlen, tmp = 99;
    int ret = 0;
```

## Call pattern 40

```c
if (!TEST_true(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)))
        goto err;

    ret = 1;

err:
    RSA_free(rsa);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
static int test_decrypt_null_chunks(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1
    };
    unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    unsigned char msg[] = "It was the best of times, it was the worst of times";
    unsigned char ciphertext[80];
    unsigned char plaintext[80];
    /* We initialise tmp to a non zero value on purpose */
    int ctlen, ptlen, tmp = 99;
    int ret = 0;
    const int enc_offset = 10, dec_offset = 20;
```

## Call pattern 41

```c
goto err;

    ret = 1;

err:
    RSA_free(rsa);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
static int test_decrypt_null_chunks(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1
    };
    unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    unsigned char msg[] = "It was the best of times, it was the worst of times";
    unsigned char ciphertext[80];
    unsigned char plaintext[80];
    /* We initialise tmp to a non zero value on purpose */
    int ctlen, ptlen, tmp = 99;
    int ret = 0;
    const int enc_offset = 10, dec_offset = 20;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, "ChaCha20-Poly1305", testpropq))
```

## Call pattern 42

```c
#ifndef OPENSSL_NO_DEPRECATED_3_0
static int test_EVP_PKEY_set1_DH(void)
{
    DH *x942dh = NULL, *noqdh = NULL;
    EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;
```

## Call pattern 43

```c
static int test_EVP_PKEY_set1_DH(void)
{
    DH *x942dh = NULL, *noqdh = NULL;
    EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
```

## Call pattern 44

```c
{
    DH *x942dh = NULL, *noqdh = NULL;
    EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
            &pubkey))
```

## Call pattern 45

```c
DH *x942dh = NULL, *noqdh = NULL;
    EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
            &pubkey))
        || !TEST_ptr(pubkey))
```

## Call pattern 46

```c
EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
    int ret = 0;
    BIGNUM *p, *g = NULL;
    BIGNUM *pubkey = NULL;
    unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
            &pubkey))
        || !TEST_ptr(pubkey))
        goto err;
```

## Call pattern 47

```c
unsigned char pub[2048 / 8];
    size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
            &pubkey))
        || !TEST_ptr(pubkey))
        goto err;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey2, noqdh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey2), EVP_PKEY_DH))
        goto err;
```

## Call pattern 48

```c
size_t len = 0;

    if (!TEST_ptr(p = BN_new())
        || !TEST_ptr(g = BN_new())
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(p, 9999))
        || !TEST_true(BN_set_word(g, 2))
        || !TEST_true(BN_set_word(pubkey, 4321))
        || !TEST_ptr(noqdh = DH_new())
        || !TEST_true(DH_set0_pqg(noqdh, p, NULL, g))
        || !TEST_true(DH_set0_key(noqdh, pubkey, NULL))
        || !TEST_ptr(pubkey = BN_new())
        || !TEST_true(BN_set_word(pubkey, 4321)))
        goto err;
    p = g = NULL;

    x942dh = DH_get_2048_256();
    pkey1 = EVP_PKEY_new();
    pkey2 = EVP_PKEY_new();
    if (!TEST_ptr(x942dh)
        || !TEST_ptr(noqdh)
        || !TEST_ptr(pkey1)
        || !TEST_ptr(pkey2)
        || !TEST_true(DH_set0_key(x942dh, pubkey, NULL)))
        goto err;
    pubkey = NULL;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey1, x942dh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey1), EVP_PKEY_DHX))
        goto err;

    if (!TEST_true(EVP_PKEY_get_bn_param(pkey1, OSSL_PKEY_PARAM_PUB_KEY,
            &pubkey))
        || !TEST_ptr(pubkey))
        goto err;

    if (!TEST_true(EVP_PKEY_set1_DH(pkey2, noqdh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey2), EVP_PKEY_DH))
        goto err;
```

## Call pattern 49

```c
if (!TEST_true(EVP_PKEY_set1_DH(pkey2, noqdh))
        || !TEST_int_eq(EVP_PKEY_get_id(pkey2), EVP_PKEY_DH))
        goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey2,
            OSSL_PKEY_PARAM_PUB_KEY,
            pub, sizeof(pub), &len))
        || !TEST_size_t_ne(len, 0))
        goto err;

    ret = 1;
err:
    BN_free(p);
    BN_free(g);
    BN_free(pubkey);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    DH_free(x942dh);
    DH_free(noqdh);

    return ret;
}
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */
#endif /* !OPENSSL_NO_DH */

/*
 * We test what happens with an empty template.  For the sake of this test,
 * the template must be ignored, and we know that's the case for RSA keys
 * (this might arguably be a misfeature, but that's what we currently do,
 * even in provider code, since that's how the legacy RSA implementation
 * does things)
 */
static int test_keygen_with_empty_template(int n)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *tkey = NULL;
    int ret = 0;

    if (nullprov != NULL)
```

## Call pattern 50

```c
|| !TEST_int_eq(EVP_PKEY_get_id(pkey2), EVP_PKEY_DH))
        goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey2,
            OSSL_PKEY_PARAM_PUB_KEY,
            pub, sizeof(pub), &len))
        || !TEST_size_t_ne(len, 0))
        goto err;

    ret = 1;
err:
    BN_free(p);
    BN_free(g);
    BN_free(pubkey);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    DH_free(x942dh);
    DH_free(noqdh);

    return ret;
}
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */
#endif /* !OPENSSL_NO_DH */

/*
 * We test what happens with an empty template.  For the sake of this test,
 * the template must be ignored, and we know that's the case for RSA keys
 * (this might arguably be a misfeature, but that's what we currently do,
 * even in provider code, since that's how the legacy RSA implementation
 * does things)
 */
static int test_keygen_with_empty_template(int n)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *tkey = NULL;
    int ret = 0;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");
```

## Call pattern 51

```c
goto err;

    if (!TEST_true(EVP_PKEY_get_octet_string_param(pkey2,
            OSSL_PKEY_PARAM_PUB_KEY,
            pub, sizeof(pub), &len))
        || !TEST_size_t_ne(len, 0))
        goto err;

    ret = 1;
err:
    BN_free(p);
    BN_free(g);
    BN_free(pubkey);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    DH_free(x942dh);
    DH_free(noqdh);

    return ret;
}
#endif /* !OPENSSL_NO_DEPRECATED_3_0 */
#endif /* !OPENSSL_NO_DH */

/*
 * We test what happens with an empty template.  For the sake of this test,
 * the template must be ignored, and we know that's the case for RSA keys
 * (this might arguably be a misfeature, but that's what we currently do,
 * even in provider code, since that's how the legacy RSA implementation
 * does things)
 */
static int test_keygen_with_empty_template(int n)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *tkey = NULL;
    int ret = 0;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");
```

