# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/evp_extra_test2.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
{
    int ret = 0;

    if (use_octstring) {
        unsigned char buf[64];

        ret = EVP_PKEY_get_octet_string_param(key, privtag, buf, sizeof(buf),
            NULL);
    } else {
        BIGNUM *bn = NULL;

        ret = EVP_PKEY_get_bn_param(key, privtag, &bn);
        BN_free(bn);
    }
    return ret;
}

static int do_pkey_tofrom_data_select(EVP_PKEY *key, const char *keytype)
{
    int ret = 0;
    OSSL_PARAM *pub_params = NULL, *keypair_params = NULL;
    EVP_PKEY *fromkey = NULL, *fromkeypair = NULL;
    EVP_PKEY_CTX *fromctx = NULL;
    const char *privtag = strcmp(keytype, "RSA") == 0 ? "d" : "priv";
    const int use_octstring = strcmp(keytype, "X25519") == 0;

    /*
     * Select only the public key component when using EVP_PKEY_todata() and
     * check that the resulting param array does not contain a private key.
     */
    if (!TEST_int_eq(EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &pub_params), 1)
        || !TEST_ptr_null(OSSL_PARAM_locate(pub_params, privtag)))
        goto end;
    /*
     * Select the keypair when using EVP_PKEY_todata() and check that
     * the param array contains a private key.
     */
    if (!TEST_int_eq(EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &keypair_params), 1)
        || !TEST_ptr(OSSL_PARAM_locate(keypair_params, privtag)))
        goto end;
```

## Call pattern 2

```c
goto done;
    }

    if (ak->evptype == EVP_PKEY_DH) {
        if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p_bn))
            || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G,
                &g_bn)))
            goto done;
    }

    ret = 1;
done:
    BN_free(p_bn);
    BN_free(g_bn);
    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_DES
static int test_pkcs8key_nid_bio(void)
{
    int ret;
    const int nid = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    static const char pwd[] = "PASSWORD";
    EVP_PKEY *pkey = NULL, *pkey_dec = NULL;
    BIO *in = NULL, *enc_bio = NULL;
    char *enc_data = NULL;
    long enc_datalen = 0;
    OSSL_PROVIDER *provider = NULL;

    ret = TEST_ptr(provider = OSSL_PROVIDER_load(NULL, "default"))
        && TEST_ptr(enc_bio = BIO_new(BIO_s_mem()))
        && TEST_ptr(in = BIO_new_mem_buf(kExampleRSAKeyPKCS8,
                        sizeof(kExampleRSAKeyPKCS8)))
        && TEST_ptr(pkey = d2i_PrivateKey_ex_bio(in, NULL, NULL, NULL))
        && TEST_int_eq(i2d_PKCS8PrivateKey_nid_bio(enc_bio, pkey, nid,
                           pwd, sizeof(pwd) - 1,
                           NULL, NULL),
            1)
```

## Call pattern 3

```c
}

    if (ak->evptype == EVP_PKEY_DH) {
        if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p_bn))
            || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G,
                &g_bn)))
            goto done;
    }

    ret = 1;
done:
    BN_free(p_bn);
    BN_free(g_bn);
    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_DES
static int test_pkcs8key_nid_bio(void)
{
    int ret;
    const int nid = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    static const char pwd[] = "PASSWORD";
    EVP_PKEY *pkey = NULL, *pkey_dec = NULL;
    BIO *in = NULL, *enc_bio = NULL;
    char *enc_data = NULL;
    long enc_datalen = 0;
    OSSL_PROVIDER *provider = NULL;

    ret = TEST_ptr(provider = OSSL_PROVIDER_load(NULL, "default"))
        && TEST_ptr(enc_bio = BIO_new(BIO_s_mem()))
        && TEST_ptr(in = BIO_new_mem_buf(kExampleRSAKeyPKCS8,
                        sizeof(kExampleRSAKeyPKCS8)))
        && TEST_ptr(pkey = d2i_PrivateKey_ex_bio(in, NULL, NULL, NULL))
        && TEST_int_eq(i2d_PKCS8PrivateKey_nid_bio(enc_bio, pkey, nid,
                           pwd, sizeof(pwd) - 1,
                           NULL, NULL),
            1)
        && TEST_int_gt(enc_datalen = BIO_get_mem_data(enc_bio, &enc_data), 0)
```

## Call pattern 4

```c
if (ak->evptype == EVP_PKEY_DH) {
        if (!TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p_bn))
            || !TEST_true(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G,
                &g_bn)))
            goto done;
    }

    ret = 1;
done:
    BN_free(p_bn);
    BN_free(g_bn);
    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_DES
static int test_pkcs8key_nid_bio(void)
{
    int ret;
    const int nid = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    static const char pwd[] = "PASSWORD";
    EVP_PKEY *pkey = NULL, *pkey_dec = NULL;
    BIO *in = NULL, *enc_bio = NULL;
    char *enc_data = NULL;
    long enc_datalen = 0;
    OSSL_PROVIDER *provider = NULL;

    ret = TEST_ptr(provider = OSSL_PROVIDER_load(NULL, "default"))
        && TEST_ptr(enc_bio = BIO_new(BIO_s_mem()))
        && TEST_ptr(in = BIO_new_mem_buf(kExampleRSAKeyPKCS8,
                        sizeof(kExampleRSAKeyPKCS8)))
        && TEST_ptr(pkey = d2i_PrivateKey_ex_bio(in, NULL, NULL, NULL))
        && TEST_int_eq(i2d_PKCS8PrivateKey_nid_bio(enc_bio, pkey, nid,
                           pwd, sizeof(pwd) - 1,
                           NULL, NULL),
            1)
        && TEST_int_gt(enc_datalen = BIO_get_mem_data(enc_bio, &enc_data), 0)
        && TEST_ptr(pkey_dec = d2i_PKCS8PrivateKey_bio(enc_bio, NULL, NULL,
```

## Call pattern 5

```c
}

static int do_check_bn(OSSL_PARAM params[], const char *key,
    const unsigned char *expected, size_t expected_len)
{
    OSSL_PARAM *p;
    BIGNUM *bn = NULL;
    unsigned char buffer[256 + 1];
    int ret, len;

    ret = TEST_ptr(p = OSSL_PARAM_locate(params, key))
        && TEST_true(OSSL_PARAM_get_BN(p, &bn))
        && TEST_int_gt(len = BN_bn2binpad(bn, buffer, expected_len), 0)
        && TEST_mem_eq(expected, expected_len, buffer, len);
    BN_free(bn);
    return ret;
}

static int do_check_int(OSSL_PARAM params[], const char *key, int expected)
{
    OSSL_PARAM *p;
    int val = 0;

    return TEST_ptr(p = OSSL_PARAM_locate(params, key))
        && TEST_true(OSSL_PARAM_get_int(p, &val))
        && TEST_int_eq(val, expected);
}

static int test_dsa_tofrom_data_select(void)
{
    int ret;
    EVP_PKEY *key = NULL;
    const unsigned char *pkeydata = dsa_key;

    ret = TEST_ptr(key = d2i_AutoPrivateKey_ex(NULL, &pkeydata, sizeof(dsa_key),
                       mainctx, NULL))
        && TEST_true(do_pkey_tofrom_data_select(key, "DSA"));

    EVP_PKEY_free(key);
    return ret;
```

## Call pattern 6

```c
static int do_check_bn(OSSL_PARAM params[], const char *key,
    const unsigned char *expected, size_t expected_len)
{
    OSSL_PARAM *p;
    BIGNUM *bn = NULL;
    unsigned char buffer[256 + 1];
    int ret, len;

    ret = TEST_ptr(p = OSSL_PARAM_locate(params, key))
        && TEST_true(OSSL_PARAM_get_BN(p, &bn))
        && TEST_int_gt(len = BN_bn2binpad(bn, buffer, expected_len), 0)
        && TEST_mem_eq(expected, expected_len, buffer, len);
    BN_free(bn);
    return ret;
}

static int do_check_int(OSSL_PARAM params[], const char *key, int expected)
{
    OSSL_PARAM *p;
    int val = 0;

    return TEST_ptr(p = OSSL_PARAM_locate(params, key))
        && TEST_true(OSSL_PARAM_get_int(p, &val))
        && TEST_int_eq(val, expected);
}

static int test_dsa_tofrom_data_select(void)
{
    int ret;
    EVP_PKEY *key = NULL;
    const unsigned char *pkeydata = dsa_key;

    ret = TEST_ptr(key = d2i_AutoPrivateKey_ex(NULL, &pkeydata, sizeof(dsa_key),
                       mainctx, NULL))
        && TEST_true(do_pkey_tofrom_data_select(key, "DSA"));

    EVP_PKEY_free(key);
    return ret;
}
```

