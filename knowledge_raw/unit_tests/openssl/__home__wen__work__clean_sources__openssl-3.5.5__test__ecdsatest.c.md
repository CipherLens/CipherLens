# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/ecdsatest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
static EC_builtin_curve *curves = NULL;
static OSSL_PROVIDER *fake_rand = NULL;

static int fbytes(unsigned char *buf, size_t num, ossl_unused const char *name,
    EVP_RAND_CTX *ctx)
{
    int ret = 0;
    static int fbytes_counter = 0;
    BIGNUM *tmp = NULL;

    fake_rand_set_callback(ctx, NULL);

    if (!TEST_ptr(tmp = BN_new())
        || !TEST_int_lt(fbytes_counter, OSSL_NELEM(numbers))
        || !TEST_true(BN_hex2bn(&tmp, numbers[fbytes_counter]))
        /* tmp might need leading zeros so pad it out */
        || !TEST_int_le(BN_num_bytes(tmp), num)
        || !TEST_int_gt(BN_bn2binpad(tmp, buf, num), 0))
        goto err;

    fbytes_counter = (fbytes_counter + 1) % OSSL_NELEM(numbers);
    ret = 1;
err:
    BN_free(tmp);
    return ret;
}

/*-
 * This function hijacks the RNG to feed it the chosen ECDSA key and nonce.
 * The ECDSA KATs are from:
 * - the X9.62 draft (4)
 * - NIST CAVP (720)
 *
 * It uses the low-level ECDSA_sign_setup instead of EVP to control the RNG.
 * NB: This is not how applications should use ECDSA; this is only for testing.
 *
 * Tests the library can successfully:
 * - generate public keys that matches those KATs
 * - create ECDSA signatures that match those KATs
 * - accept those signatures as valid
```

## Call pattern 2

```c
{
    int ret = 0;
    static int fbytes_counter = 0;
    BIGNUM *tmp = NULL;

    fake_rand_set_callback(ctx, NULL);

    if (!TEST_ptr(tmp = BN_new())
        || !TEST_int_lt(fbytes_counter, OSSL_NELEM(numbers))
        || !TEST_true(BN_hex2bn(&tmp, numbers[fbytes_counter]))
        /* tmp might need leading zeros so pad it out */
        || !TEST_int_le(BN_num_bytes(tmp), num)
        || !TEST_int_gt(BN_bn2binpad(tmp, buf, num), 0))
        goto err;

    fbytes_counter = (fbytes_counter + 1) % OSSL_NELEM(numbers);
    ret = 1;
err:
    BN_free(tmp);
    return ret;
}

/*-
 * This function hijacks the RNG to feed it the chosen ECDSA key and nonce.
 * The ECDSA KATs are from:
 * - the X9.62 draft (4)
 * - NIST CAVP (720)
 *
 * It uses the low-level ECDSA_sign_setup instead of EVP to control the RNG.
 * NB: This is not how applications should use ECDSA; this is only for testing.
 *
 * Tests the library can successfully:
 * - generate public keys that matches those KATs
 * - create ECDSA signatures that match those KATs
 * - accept those signatures as valid
 */
static int x9_62_tests(int n)
{
    int nid, md_nid, ret = 0;
    const char *r_in = NULL, *s_in = NULL, *tbs = NULL;
```

## Call pattern 3

```c
if (!TEST_ptr(tmp = BN_new())
        || !TEST_int_lt(fbytes_counter, OSSL_NELEM(numbers))
        || !TEST_true(BN_hex2bn(&tmp, numbers[fbytes_counter]))
        /* tmp might need leading zeros so pad it out */
        || !TEST_int_le(BN_num_bytes(tmp), num)
        || !TEST_int_gt(BN_bn2binpad(tmp, buf, num), 0))
        goto err;

    fbytes_counter = (fbytes_counter + 1) % OSSL_NELEM(numbers);
    ret = 1;
err:
    BN_free(tmp);
    return ret;
}

/*-
 * This function hijacks the RNG to feed it the chosen ECDSA key and nonce.
 * The ECDSA KATs are from:
 * - the X9.62 draft (4)
 * - NIST CAVP (720)
 *
 * It uses the low-level ECDSA_sign_setup instead of EVP to control the RNG.
 * NB: This is not how applications should use ECDSA; this is only for testing.
 *
 * Tests the library can successfully:
 * - generate public keys that matches those KATs
 * - create ECDSA signatures that match those KATs
 * - accept those signatures as valid
 */
static int x9_62_tests(int n)
{
    int nid, md_nid, ret = 0;
    const char *r_in = NULL, *s_in = NULL, *tbs = NULL;
    unsigned char *pbuf = NULL, *qbuf = NULL, *message = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dgst_len = 0;
    long q_len, msg_len = 0;
    size_t p_len;
    EVP_MD_CTX *mctx = NULL;
```

## Call pattern 4

```c
return TEST_skip("skip non approved curves");
#endif /* FIPS_MODULE */

    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
        /* get the message digest */
        || !TEST_ptr(message = OPENSSL_hexstr2buf(tbs, &msg_len))
        || !TEST_true(EVP_DigestInit_ex(mctx, EVP_get_digestbynid(md_nid), NULL))
        || !TEST_true(EVP_DigestUpdate(mctx, message, msg_len))
        || !TEST_true(EVP_DigestFinal_ex(mctx, digest, &dgst_len))
        /* create the key */
        || !TEST_ptr(key = EC_KEY_new_by_curve_name(nid))
        /* load KAT variables */
        || !TEST_ptr(r = BN_new())
        || !TEST_ptr(s = BN_new())
        || !TEST_true(BN_hex2bn(&r, r_in))
        || !TEST_true(BN_hex2bn(&s, s_in)))
        goto err;

    /* public key must match KAT */
    fake_rand_set_callback(RAND_get0_private(NULL), &fbytes);
    if (!TEST_true(EC_KEY_generate_key(key))
        || !TEST_true(p_len = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED,
                          &pbuf, NULL))
        || !TEST_ptr(qbuf = OPENSSL_hexstr2buf(ecdsa_cavs_kats[n].Q, &q_len))
        || !TEST_int_eq(q_len, p_len)
        || !TEST_mem_eq(qbuf, q_len, pbuf, p_len))
        goto err;

    /* create the signature via ECDSA_sign_setup to avoid use of ECDSA nonces */
    fake_rand_set_callback(RAND_get0_private(NULL), &fbytes);
    if (!TEST_true(ECDSA_sign_setup(key, NULL, &kinv, &rp))
        || !TEST_ptr(signature = ECDSA_do_sign_ex(digest, dgst_len,
                         kinv, rp, key))
        /* verify the signature */
        || !TEST_int_eq(ECDSA_do_verify(digest, dgst_len, signature, key), 1))
        goto err;

    /* compare the created signature with the expected signature */
    ECDSA_SIG_get0(signature, &sig_r, &sig_s);
    if (!TEST_BN_eq(sig_r, r)
```

## Call pattern 5

```c
#endif /* FIPS_MODULE */

    if (!TEST_ptr(mctx = EVP_MD_CTX_new())
        /* get the message digest */
        || !TEST_ptr(message = OPENSSL_hexstr2buf(tbs, &msg_len))
        || !TEST_true(EVP_DigestInit_ex(mctx, EVP_get_digestbynid(md_nid), NULL))
        || !TEST_true(EVP_DigestUpdate(mctx, message, msg_len))
        || !TEST_true(EVP_DigestFinal_ex(mctx, digest, &dgst_len))
        /* create the key */
        || !TEST_ptr(key = EC_KEY_new_by_curve_name(nid))
        /* load KAT variables */
        || !TEST_ptr(r = BN_new())
        || !TEST_ptr(s = BN_new())
        || !TEST_true(BN_hex2bn(&r, r_in))
        || !TEST_true(BN_hex2bn(&s, s_in)))
        goto err;

    /* public key must match KAT */
    fake_rand_set_callback(RAND_get0_private(NULL), &fbytes);
    if (!TEST_true(EC_KEY_generate_key(key))
        || !TEST_true(p_len = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED,
                          &pbuf, NULL))
        || !TEST_ptr(qbuf = OPENSSL_hexstr2buf(ecdsa_cavs_kats[n].Q, &q_len))
        || !TEST_int_eq(q_len, p_len)
        || !TEST_mem_eq(qbuf, q_len, pbuf, p_len))
        goto err;

    /* create the signature via ECDSA_sign_setup to avoid use of ECDSA nonces */
    fake_rand_set_callback(RAND_get0_private(NULL), &fbytes);
    if (!TEST_true(ECDSA_sign_setup(key, NULL, &kinv, &rp))
        || !TEST_ptr(signature = ECDSA_do_sign_ex(digest, dgst_len,
                         kinv, rp, key))
        /* verify the signature */
        || !TEST_int_eq(ECDSA_do_verify(digest, dgst_len, signature, key), 1))
        goto err;

    /* compare the created signature with the expected signature */
    ECDSA_SIG_get0(signature, &sig_r, &sig_s);
    if (!TEST_BN_eq(sig_r, r)
        || !TEST_BN_eq(sig_s, s))
```

## Call pattern 6

```c
if (!TEST_BN_eq(sig_r, r)
        || !TEST_BN_eq(sig_s, s))
        goto err;

    ret = 1;

err:
    OPENSSL_free(message);
    OPENSSL_free(pbuf);
    OPENSSL_free(qbuf);
    EC_KEY_free(key);
    ECDSA_SIG_free(signature);
    BN_free(r);
    BN_free(s);
    EVP_MD_CTX_free(mctx);
    BN_clear_free(kinv);
    BN_clear_free(rp);
    return ret;
}

/*-
 * Positive and negative ECDSA testing through EVP interface:
 * - EVP_DigestSign (this is the one-shot version)
 * - EVP_DigestVerify
 *
 * Tests the library can successfully:
 * - create a key
 * - create a signature
 * - accept that signature
 * - reject that signature with a different public key
 * - reject that signature if its length is not correct
 * - reject that signature after modifying the message
 * - accept that signature after un-modifying the message
 * - reject that signature after modifying the signature
 * - accept that signature after un-modifying the signature
 */
static int set_sm2_id(EVP_MD_CTX *mctx, EVP_PKEY *pkey)
{
    /* With the SM2 key type, the SM2 ID is mandatory */
    static const char sm2_id[] = { 1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r' };
```

## Call pattern 7

```c
|| !TEST_BN_eq(sig_s, s))
        goto err;

    ret = 1;

err:
    OPENSSL_free(message);
    OPENSSL_free(pbuf);
    OPENSSL_free(qbuf);
    EC_KEY_free(key);
    ECDSA_SIG_free(signature);
    BN_free(r);
    BN_free(s);
    EVP_MD_CTX_free(mctx);
    BN_clear_free(kinv);
    BN_clear_free(rp);
    return ret;
}

/*-
 * Positive and negative ECDSA testing through EVP interface:
 * - EVP_DigestSign (this is the one-shot version)
 * - EVP_DigestVerify
 *
 * Tests the library can successfully:
 * - create a key
 * - create a signature
 * - accept that signature
 * - reject that signature with a different public key
 * - reject that signature if its length is not correct
 * - reject that signature after modifying the message
 * - accept that signature after un-modifying the message
 * - reject that signature after modifying the signature
 * - accept that signature after un-modifying the signature
 */
static int set_sm2_id(EVP_MD_CTX *mctx, EVP_PKEY *pkey)
{
    /* With the SM2 key type, the SM2 ID is mandatory */
    static const char sm2_id[] = { 1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r' };
    EVP_PKEY_CTX *pctx;
```

## Call pattern 8

```c
1)
        && TEST_int_gt(siglen, 0)
        && TEST_int_le(siglen, siglen0)
        && TEST_int_eq(ECDSA_sign_ex(0, dgst, sizeof(dgst), sig, &siglen0,
                           kinv, rp, eckey),
            1)
        && TEST_int_eq(siglen, siglen0)
        && TEST_int_eq(ECDSA_verify(0, dgst, sizeof(dgst), sig, siglen,
                           eckey),
            1);
    EC_KEY_free(eckey);
    OPENSSL_free(sig);
    BN_free(kinv);
    BN_free(rp);
    return ret;
}

#endif /* OPENSSL_NO_EC */

int setup_tests(void)
{
#ifdef OPENSSL_NO_EC
    TEST_note("Elliptic curves are disabled.");
#else
    fake_rand = fake_rand_start(NULL);
    if (fake_rand == NULL)
        return 0;

    /* get a list of all internal curves */
    crv_len = EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc(sizeof(*curves) * crv_len))
        || !TEST_true(EC_get_builtin_curves(curves, crv_len))) {
        fake_rand_finish(fake_rand);
        return 0;
    }
    ADD_ALL_TESTS(test_builtin_as_ec, crv_len);
    ADD_TEST(test_ecdsa_sig_NULL);
#ifndef OPENSSL_NO_SM2
    ADD_ALL_TESTS(test_builtin_as_sm2, crv_len);
#endif
```

## Call pattern 9

```c
&& TEST_int_gt(siglen, 0)
        && TEST_int_le(siglen, siglen0)
        && TEST_int_eq(ECDSA_sign_ex(0, dgst, sizeof(dgst), sig, &siglen0,
                           kinv, rp, eckey),
            1)
        && TEST_int_eq(siglen, siglen0)
        && TEST_int_eq(ECDSA_verify(0, dgst, sizeof(dgst), sig, siglen,
                           eckey),
            1);
    EC_KEY_free(eckey);
    OPENSSL_free(sig);
    BN_free(kinv);
    BN_free(rp);
    return ret;
}

#endif /* OPENSSL_NO_EC */

int setup_tests(void)
{
#ifdef OPENSSL_NO_EC
    TEST_note("Elliptic curves are disabled.");
#else
    fake_rand = fake_rand_start(NULL);
    if (fake_rand == NULL)
        return 0;

    /* get a list of all internal curves */
    crv_len = EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc(sizeof(*curves) * crv_len))
        || !TEST_true(EC_get_builtin_curves(curves, crv_len))) {
        fake_rand_finish(fake_rand);
        return 0;
    }
    ADD_ALL_TESTS(test_builtin_as_ec, crv_len);
    ADD_TEST(test_ecdsa_sig_NULL);
#ifndef OPENSSL_NO_SM2
    ADD_ALL_TESTS(test_builtin_as_sm2, crv_len);
#endif
    ADD_ALL_TESTS(x9_62_tests, OSSL_NELEM(ecdsa_cavs_kats));
```

