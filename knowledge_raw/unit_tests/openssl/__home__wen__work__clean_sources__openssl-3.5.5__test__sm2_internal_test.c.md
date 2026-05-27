# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/sm2_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
|| !TEST_true(BN_hex2bn(&g_y, y_hex))
        || !TEST_true(EC_POINT_set_affine_coordinates(group, generator, g_x,
            g_y, NULL)))
        goto done;

    if (!TEST_true(BN_hex2bn(&order, order_hex))
        || !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
```

## Call pattern 2

```c
|| !TEST_true(EC_POINT_set_affine_coordinates(group, generator, g_x,
            g_y, NULL)))
        goto done;

    if (!TEST_true(BN_hex2bn(&order, order_hex))
        || !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
```

## Call pattern 3

```c
g_y, NULL)))
        goto done;

    if (!TEST_true(BN_hex2bn(&order, order_hex))
        || !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
```

## Call pattern 4

```c
goto done;

    if (!TEST_true(BN_hex2bn(&order, order_hex))
        || !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
```

## Call pattern 5

```c
if (!TEST_true(BN_hex2bn(&order, order_hex))
        || !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
```

## Call pattern 6

```c
|| !TEST_true(BN_hex2bn(&cof, cof_hex))
        || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
    int rc = 0;
```

## Call pattern 7

```c
|| !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
        goto done;

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
    const EVP_MD *digest,
    const char *privkey_hex,
    const char *message,
    const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
    int rc = 0;

    if (!TEST_ptr(expected)
```

## Call pattern 8

```c
goto done;

    recovered = OPENSSL_zalloc(ptext_len);
    if (!TEST_ptr(recovered)
        || !TEST_true(ossl_sm2_decrypt(key, digest, ctext, ctext_len,
            recovered, &recovered_len))
        || !TEST_int_eq(recovered_len, msg_len)
        || !TEST_mem_eq(recovered, recovered_len, message, msg_len))
        goto done;

    rc = 1;
done:
    BN_free(priv);
    EC_POINT_free(pt);
    OPENSSL_free(ctext);
    OPENSSL_free(recovered);
    OPENSSL_free(expected);
    EC_KEY_free(key);
    return rc;
}

static int sm2_crypt_test(void)
{
    int testresult = 0;
    EC_GROUP *gm_group = NULL;
    EC_GROUP *test_group = create_EC_group("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        "1");

    if (!TEST_ptr(test_group))
        goto done;

    if (!test_sm2_crypt(
            test_group,
            EVP_sm3(),
            "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
```

## Call pattern 9

```c
goto done;

    ok = ossl_sm2_do_verify(key, EVP_sm3(), sig, (const uint8_t *)userid,
        strlen(userid), (const uint8_t *)message, msg_len);

    /* We goto done whether this passes or fails */
    TEST_true(ok);

done:
    ECDSA_SIG_free(sig);
    EC_POINT_free(pt);
    EC_KEY_free(key);
    BN_free(priv);
    BN_free(r);
    BN_free(s);

    return ok;
}

static int sm2_sig_test(void)
{
    int testresult = 0;
    EC_GROUP *gm_group = NULL;
    /* From draft-shen-sm2-ecdsa-02 */
    EC_GROUP *test_group = create_EC_group("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        "1");

    if (!TEST_ptr(test_group))
        goto done;

    if (!TEST_true(test_sm2_sign(
            test_group,
            "ALICE123@YAHOO.COM",
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
            "message digest",
```

## Call pattern 10

```c
ok = ossl_sm2_do_verify(key, EVP_sm3(), sig, (const uint8_t *)userid,
        strlen(userid), (const uint8_t *)message, msg_len);

    /* We goto done whether this passes or fails */
    TEST_true(ok);

done:
    ECDSA_SIG_free(sig);
    EC_POINT_free(pt);
    EC_KEY_free(key);
    BN_free(priv);
    BN_free(r);
    BN_free(s);

    return ok;
}

static int sm2_sig_test(void)
{
    int testresult = 0;
    EC_GROUP *gm_group = NULL;
    /* From draft-shen-sm2-ecdsa-02 */
    EC_GROUP *test_group = create_EC_group("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        "1");

    if (!TEST_ptr(test_group))
        goto done;

    if (!TEST_true(test_sm2_sign(
            test_group,
            "ALICE123@YAHOO.COM",
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
            "message digest",
            "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"
```

## Call pattern 11

```c
ok = ossl_sm2_do_verify(key, EVP_sm3(), sig, (const uint8_t *)userid,
        strlen(userid), (const uint8_t *)message, msg_len);

    /* We goto done whether this passes or fails */
    TEST_true(ok);

done:
    ECDSA_SIG_free(sig);
    EC_POINT_free(pt);
    EC_KEY_free(key);
    BN_free(priv);
    BN_free(r);
    BN_free(s);

    return ok;
}

static int sm2_sig_test(void)
{
    int testresult = 0;
    EC_GROUP *gm_group = NULL;
    /* From draft-shen-sm2-ecdsa-02 */
    EC_GROUP *test_group = create_EC_group("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
        "1");

    if (!TEST_ptr(test_group))
        goto done;

    if (!TEST_true(test_sm2_sign(
            test_group,
            "ALICE123@YAHOO.COM",
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
            "message digest",
            "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"
            "007c47811054c6f99613a578eb8453706ccb96384fe7df5c171671e760bfa8be3a",
```

