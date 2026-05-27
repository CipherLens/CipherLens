# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/sslapitest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
user_pwd->v = verifier;
    user_pwd->s = salt;
    verifier = salt = NULL;

    if (sk_SRP_user_pwd_insert(vbase->users_pwd, user_pwd, 0) == 0)
        goto end;
    user_pwd = NULL;

    ret = 1;
end:
    SRP_user_pwd_free(user_pwd);
    BN_free(salt);
    BN_free(verifier);

    return ret;
}

/*
 * SRP tests
 *
 * Test 0: Simple successful SRP connection, new vbase
 * Test 1: Connection failure due to bad password, new vbase
 * Test 2: Simple successful SRP connection, vbase loaded from existing file
 * Test 3: Connection failure due to bad password, vbase loaded from existing
 *         file
 * Test 4: Simple successful SRP connection, vbase loaded from new file
 * Test 5: Connection failure due to bad password, vbase loaded from new file
 */
static int test_srp(int tst)
{
    char *userid = "test", *password = "password", *tstsrpfile;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret, testresult = 0;

    vbase = SRP_VBASE_new(NULL);
    if (!TEST_ptr(vbase))
        goto end;
```

## Call pattern 2

```c
user_pwd->v = verifier;
    user_pwd->s = salt;
    verifier = salt = NULL;

    if (sk_SRP_user_pwd_insert(vbase->users_pwd, user_pwd, 0) == 0)
        goto end;
    user_pwd = NULL;

    ret = 1;
end:
    SRP_user_pwd_free(user_pwd);
    BN_free(salt);
    BN_free(verifier);

    return ret;
}

/*
 * SRP tests
 *
 * Test 0: Simple successful SRP connection, new vbase
 * Test 1: Connection failure due to bad password, new vbase
 * Test 2: Simple successful SRP connection, vbase loaded from existing file
 * Test 3: Connection failure due to bad password, vbase loaded from existing
 *         file
 * Test 4: Simple successful SRP connection, vbase loaded from new file
 * Test 5: Connection failure due to bad password, vbase loaded from new file
 */
static int test_srp(int tst)
{
    char *userid = "test", *password = "password", *tstsrpfile;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret, testresult = 0;

    vbase = SRP_VBASE_new(NULL);
    if (!TEST_ptr(vbase))
        goto end;

    if (tst == 0 || tst == 1) {
```

## Call pattern 3

```c
goto end;

        params = OSSL_PARAM_BLD_to_param(tmpl);
        if (!TEST_ptr(params)
            || !TEST_int_eq(EVP_PKEY_fromdata(pctx, &dhpkey,
                                EVP_PKEY_KEY_PARAMETERS,
                                params),
                1))
            goto end;

        tmp_dh_params = dhpkey;
    end:
        BN_free(p);
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_BLD_free(tmpl);
        OSSL_PARAM_free(params);
    }

    if (tmp_dh_params != NULL && !EVP_PKEY_up_ref(tmp_dh_params))
        return NULL;

    return tmp_dh_params;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* Callback used by test_set_tmp_dh() */
static DH *tmp_dh_callback(SSL *s, int is_export, int keylen)
{
    EVP_PKEY *dhpkey = get_tmp_dh_params();
    DH *ret = NULL;

    if (!TEST_ptr(dhpkey))
        return NULL;

    /*
     * libssl does not free the returned DH, so we free it now knowing that even
     * after we free dhpkey, there will still be a reference to the owning
     * EVP_PKEY in tmp_dh_params, and so the DH object will live for the length
     * of time we need it for.
     */
```

