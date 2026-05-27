# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/evp_pkey_dhkem_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
/* Fail if ikm len is too small*/
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
        "P-256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM,
        (char *)t->ikm, t->ikmlen - 1);
    params[2] = OSSL_PARAM_construct_end();
    if (!TEST_int_eq(EVP_PKEY_CTX_set_params(genctx, params), 1)
        || !TEST_int_eq(EVP_PKEY_generate(genctx, &pkey), 0))
        goto err;

    ret = 1;
err:
    BN_free(priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    return ret;
}

/* Succeed even if the operation parameter is not set */
static int test_no_operation_set(int tstid)
{
    EVP_PKEY_CTX *ctx = rctx[tstid];
    const TEST_ENCAPDATA *t = &ec_encapdata[tstid];
    size_t len = 0;

    return TEST_int_eq(EVP_PKEY_encapsulate_init(ctx, NULL), 1)
        && TEST_int_eq(EVP_PKEY_encapsulate(ctx, NULL, &len, NULL, NULL), 1)
        && TEST_int_eq(EVP_PKEY_decapsulate_init(ctx, NULL), 1)
        && TEST_int_eq(EVP_PKEY_decapsulate(ctx, NULL, &len,
                           t->expected_enc,
                           t->expected_enclen),
            1);
}

/* Fail if the ikm is too small */
static int test_ikm_small(int tstid)
{
    unsigned char tmp[16] = { 0 };
    unsigned char secret[256];
    unsigned char enc[256];
```

## Call pattern 2

```c
(char *)t->ikm, t->ikmlen);
    params[2] = OSSL_PARAM_construct_end();

    ret = TEST_ptr(genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL))
        && TEST_int_eq(EVP_PKEY_keygen_init(genctx), 1)
        && TEST_int_eq(EVP_PKEY_CTX_set_params(genctx, params), 1)
        && TEST_int_eq(EVP_PKEY_generate(genctx, &pkey), 1)
        && TEST_true(EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            pubkey, sizeof(pubkey), &pubkeylen))
        && TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
            &priv))
        && TEST_int_gt(privkeylen = BN_bn2bin(priv, privkey), 0)
        && TEST_int_le(privkeylen, sizeof(privkey))
        && TEST_mem_eq(privkey, privkeylen, t->priv, t->privlen)
        && TEST_mem_eq(pubkey, pubkeylen, t->pub, t->publen);

    BN_free(priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    return ret;
}

/*
 * Test that encapsulation uses a random seed if the ikm is not specified,
 * and verify that the shared secret matches the decapsulate result.
 */
static int test_ec_noikme(int tstid)
{
    int ret = 0, auth = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *recip = NULL;
    EVP_PKEY *sender_auth = NULL;
    unsigned char sender_secret[256];
    unsigned char recip_secret[256];
    unsigned char sender_pub[256];
    size_t sender_secretlen = sizeof(sender_secret);
    size_t recip_secretlen = sizeof(recip_secret);
    size_t sender_publen = sizeof(sender_pub);
    const char *curve;
```

## Call pattern 3

```c
&& TEST_int_eq(EVP_PKEY_CTX_set_params(genctx, params), 1)
        && TEST_int_eq(EVP_PKEY_generate(genctx, &pkey), 1)
        && TEST_true(EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            pubkey, sizeof(pubkey), &pubkeylen))
        && TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
            &priv))
        && TEST_int_gt(privkeylen = BN_bn2bin(priv, privkey), 0)
        && TEST_int_le(privkeylen, sizeof(privkey))
        && TEST_mem_eq(privkey, privkeylen, t->priv, t->privlen)
        && TEST_mem_eq(pubkey, pubkeylen, t->pub, t->publen);

    BN_free(priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    return ret;
}

/*
 * Test that encapsulation uses a random seed if the ikm is not specified,
 * and verify that the shared secret matches the decapsulate result.
 */
static int test_ec_noikme(int tstid)
{
    int ret = 0, auth = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *recip = NULL;
    EVP_PKEY *sender_auth = NULL;
    unsigned char sender_secret[256];
    unsigned char recip_secret[256];
    unsigned char sender_pub[256];
    size_t sender_secretlen = sizeof(sender_secret);
    size_t recip_secretlen = sizeof(recip_secret);
    size_t sender_publen = sizeof(sender_pub);
    const char *curve;
    int sz = OSSL_NELEM(dhkem_supported_curves);
    const char *op = OSSL_KEM_PARAM_OPERATION_DHKEM;

    if (tstid >= sz) {
        auth = 1;
```

