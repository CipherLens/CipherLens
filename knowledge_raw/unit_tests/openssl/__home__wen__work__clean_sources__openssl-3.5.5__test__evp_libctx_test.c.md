# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/evp_libctx_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pkey))
            || !TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), 1))
            goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DSA_free(dsa);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int do_dh_param_keygen(int tstid, const BIGNUM **bn)
{
    int ret = 0;
    int expected;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY *pkey_parm = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    DH *dh = NULL;
    int pind, qind, gind;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    /*
     * These tests are using bad values for p, q, g by reusing the values.
     * A value of 0 uses p, 1 uses q and 2 uses g.
     * There are 27 different combinations, with only the 1 valid combination.
     */
    pind = tstid / 9;
    qind = (tstid / 3) % 3;
    gind = tstid % 3;
    expected = (pind == 0 && qind == 1 && gind == 2);
```

## Call pattern 2

```c
|| !TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), 1))
            goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DSA_free(dsa);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int do_dh_param_keygen(int tstid, const BIGNUM **bn)
{
    int ret = 0;
    int expected;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY *pkey_parm = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    DH *dh = NULL;
    int pind, qind, gind;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    /*
     * These tests are using bad values for p, q, g by reusing the values.
     * A value of 0 uses p, 1 uses q and 2 uses g.
     * There are 27 different combinations, with only the 1 valid combination.
     */
    pind = tstid / 9;
    qind = (tstid / 3) % 3;
    gind = tstid % 3;
    expected = (pind == 0 && qind == 1 && gind == 2);
```

## Call pattern 3

```c
goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DSA_free(dsa);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int do_dh_param_keygen(int tstid, const BIGNUM **bn)
{
    int ret = 0;
    int expected;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY *pkey_parm = NULL;
    EVP_PKEY *pkey = NULL, *dup_pk = NULL;
    DH *dh = NULL;
    int pind, qind, gind;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    /*
     * These tests are using bad values for p, q, g by reusing the values.
     * A value of 0 uses p, 1 uses q and 2 uses g.
     * There are 27 different combinations, with only the 1 valid combination.
     */
    pind = tstid / 9;
    qind = (tstid / 3) % 3;
    gind = tstid % 3;
    expected = (pind == 0 && qind == 1 && gind == 2);

    TEST_note("Testing with (p, q, g) = (%s, %s, %s)", getname(pind),
```

## Call pattern 4

```c
if (!TEST_ptr(dup_pk = EVP_PKEY_dup(pkey))
            || !TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), 1))
            goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DH_free(dh);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}

/*
 * Note that we get the fips186-4 path being run for most of these cases since
 * the internal code will detect that the p, q, g does not match a safe prime
 * group (Except for when tstid = 5, which sets the correct p, q, g)
 */
static int test_dh_safeprime_param_keygen(int tstid)
{
    static const BIGNUM *bn[] = {
        &ossl_bignum_ffdhe2048_p, &ossl_bignum_ffdhe2048_q,
        &ossl_bignum_const_2
    };
    return do_dh_param_keygen(tstid, bn);
}

static int dhx_cert_load(void)
{
    int ret = 0;
    X509 *cert = NULL;
    BIO *bio = NULL;

    static const unsigned char dhx_cert[] = {
        0x30, 0x82, 0x03, 0xff, 0x30, 0x82, 0x02, 0xe7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
```

## Call pattern 5

```c
|| !TEST_int_eq(EVP_PKEY_eq(pkey, dup_pk), 1))
            goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DH_free(dh);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}

/*
 * Note that we get the fips186-4 path being run for most of these cases since
 * the internal code will detect that the p, q, g does not match a safe prime
 * group (Except for when tstid = 5, which sets the correct p, q, g)
 */
static int test_dh_safeprime_param_keygen(int tstid)
{
    static const BIGNUM *bn[] = {
        &ossl_bignum_ffdhe2048_p, &ossl_bignum_ffdhe2048_q,
        &ossl_bignum_const_2
    };
    return do_dh_param_keygen(tstid, bn);
}

static int dhx_cert_load(void)
{
    int ret = 0;
    X509 *cert = NULL;
    BIO *bio = NULL;

    static const unsigned char dhx_cert[] = {
        0x30, 0x82, 0x03, 0xff, 0x30, 0x82, 0x02, 0xe7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
        0xdb, 0xf5, 0x4d, 0x22, 0xa0, 0x7a, 0x67, 0xa6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
```

## Call pattern 6

```c
goto err;
    }

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(dup_pk);
    EVP_PKEY_CTX_free(gen_ctx);
    EVP_PKEY_free(pkey_parm);
    DH_free(dh);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    return ret;
}

/*
 * Note that we get the fips186-4 path being run for most of these cases since
 * the internal code will detect that the p, q, g does not match a safe prime
 * group (Except for when tstid = 5, which sets the correct p, q, g)
 */
static int test_dh_safeprime_param_keygen(int tstid)
{
    static const BIGNUM *bn[] = {
        &ossl_bignum_ffdhe2048_p, &ossl_bignum_ffdhe2048_q,
        &ossl_bignum_const_2
    };
    return do_dh_param_keygen(tstid, bn);
}

static int dhx_cert_load(void)
{
    int ret = 0;
    X509 *cert = NULL;
    BIO *bio = NULL;

    static const unsigned char dhx_cert[] = {
        0x30, 0x82, 0x03, 0xff, 0x30, 0x82, 0x02, 0xe7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
        0xdb, 0xf5, 0x4d, 0x22, 0xa0, 0x7a, 0x67, 0xa6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
```

