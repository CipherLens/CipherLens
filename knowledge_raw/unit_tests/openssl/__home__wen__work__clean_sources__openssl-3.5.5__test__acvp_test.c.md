# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/acvp_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    BIGNUM *bn = NULL;
    int sz;

    if (!EVP_PKEY_get_bn_param(pkey, name, &bn))
        goto err;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (BN_bn2binpad(bn, buf, sz) <= 0)
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}

static int sig_gen(EVP_PKEY *pkey, OSSL_PARAM *params, const char *digest_name,
    const unsigned char *msg, size_t msg_len,
    unsigned char **sig_out, size_t *sig_out_len)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len;
    size_t sz = EVP_PKEY_get_size(pkey);
    OSSL_PARAM *p = pass_sig_gen_params ? params : NULL;

    sig_len = sz;
    if (!TEST_ptr(sig = OPENSSL_malloc(sz))
        || !TEST_ptr(md_ctx = EVP_MD_CTX_new())
        || !TEST_int_eq(EVP_DigestSignInit_ex(md_ctx, NULL, digest_name, libctx,
```

## Call pattern 2

```c
if (!EVP_PKEY_get_bn_param(pkey, name, &bn))
        goto err;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (BN_bn2binpad(bn, buf, sz) <= 0)
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}

static int sig_gen(EVP_PKEY *pkey, OSSL_PARAM *params, const char *digest_name,
    const unsigned char *msg, size_t msg_len,
    unsigned char **sig_out, size_t *sig_out_len)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len;
    size_t sz = EVP_PKEY_get_size(pkey);
    OSSL_PARAM *p = pass_sig_gen_params ? params : NULL;

    sig_len = sz;
    if (!TEST_ptr(sig = OPENSSL_malloc(sz))
        || !TEST_ptr(md_ctx = EVP_MD_CTX_new())
        || !TEST_int_eq(EVP_DigestSignInit_ex(md_ctx, NULL, digest_name, libctx,
                            NULL, pkey, p),
            1)
        || !TEST_int_gt(EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len), 0))
        goto err;
    *sig_out = sig;
```

## Call pattern 3

```c
buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (BN_bn2binpad(bn, buf, sz) <= 0)
        goto err;

    *out_len = sz;
    *out = buf;
    BN_free(bn);
    return 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return 0;
}

static int sig_gen(EVP_PKEY *pkey, OSSL_PARAM *params, const char *digest_name,
    const unsigned char *msg, size_t msg_len,
    unsigned char **sig_out, size_t *sig_out_len)
{
    int ret = 0;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len;
    size_t sz = EVP_PKEY_get_size(pkey);
    OSSL_PARAM *p = pass_sig_gen_params ? params : NULL;

    sig_len = sz;
    if (!TEST_ptr(sig = OPENSSL_malloc(sz))
        || !TEST_ptr(md_ctx = EVP_MD_CTX_new())
        || !TEST_int_eq(EVP_DigestSignInit_ex(md_ctx, NULL, digest_name, libctx,
                            NULL, pkey, p),
            1)
        || !TEST_int_gt(EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len), 0))
        goto err;
    *sig_out = sig;
    *sig_out_len = sig_len;
    sig = NULL;
    ret = 1;
err:
```

## Call pattern 4

```c
return 0;
    r1 = ECDSA_SIG_get0_r(sign);
    s1 = ECDSA_SIG_get0_s(sign);
    if (r1 == NULL || s1 == NULL)
        goto err;

    r1_len = BN_num_bytes(r1);
    s1_len = BN_num_bytes(s1);
    rbuf = OPENSSL_zalloc(r1_len);
    sbuf = OPENSSL_zalloc(s1_len);
    if (rbuf == NULL || sbuf == NULL)
        goto err;
    if (BN_bn2binpad(r1, rbuf, r1_len) <= 0)
        goto err;
    if (BN_bn2binpad(s1, sbuf, s1_len) <= 0)
        goto err;
    *r = rbuf;
    *s = sbuf;
    *rlen = r1_len;
    *slen = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    ECDSA_SIG_free(sign);
    return ret;
}

static int ecdsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    size_t sig_len = 0, rlen = 0, slen = 0;
    unsigned char *sig = NULL;
    unsigned char *r = NULL, *s = NULL;
    const struct ecdsa_siggen_st *tst = &ecdsa_siggen_data[id];

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", tst->curve_name)))
```

## Call pattern 5

```c
s1 = ECDSA_SIG_get0_s(sign);
    if (r1 == NULL || s1 == NULL)
        goto err;

    r1_len = BN_num_bytes(r1);
    s1_len = BN_num_bytes(s1);
    rbuf = OPENSSL_zalloc(r1_len);
    sbuf = OPENSSL_zalloc(s1_len);
    if (rbuf == NULL || sbuf == NULL)
        goto err;
    if (BN_bn2binpad(r1, rbuf, r1_len) <= 0)
        goto err;
    if (BN_bn2binpad(s1, sbuf, s1_len) <= 0)
        goto err;
    *r = rbuf;
    *s = sbuf;
    *rlen = r1_len;
    *slen = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    ECDSA_SIG_free(sign);
    return ret;
}

static int ecdsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    size_t sig_len = 0, rlen = 0, slen = 0;
    unsigned char *sig = NULL;
    unsigned char *r = NULL, *s = NULL;
    const struct ecdsa_siggen_st *tst = &ecdsa_siggen_data[id];

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", tst->curve_name)))
        goto err;
```

## Call pattern 6

```c
|| !TEST_ptr(pkey_ctx = EVP_MD_CTX_get_pkey_ctx(md_ctx))
        || !check_verify_message(pkey_ctx, 1)
        || !TEST_int_eq(EVP_DigestVerify(md_ctx, sig, sig_len,
                            tst->msg, tst->msg_len),
            tst->pass)
        || !check_verify_message(pkey_ctx, 1)
        || !TEST_true(EVP_PKEY_verify_init(pkey_ctx))
        || !check_verify_message(pkey_ctx, 0))
        goto err;

    ret = 1;
err:
    BN_free(rbn);
    BN_free(sbn);
    OPENSSL_free(sig);
    ECDSA_SIG_free(sign);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int ecdh_cofactor_derive_test(int tstid)
{
    int ret = 0;
    const struct ecdh_cofactor_derive_st *t = &ecdh_cofactor_derive_data[tstid];
    unsigned char secret1[16];
    size_t secret1_len = sizeof(secret1);
    const char *curve = "K-283"; /* A curve that has a cofactor that it not 1 */
    EVP_PKEY *peer1 = NULL, *peer2 = NULL;
    EVP_PKEY_CTX *p1ctx = NULL;
    OSSL_PARAM params[2], *prms = NULL;
    int use_cofactordh = t->key_cofactor;
    int cofactor_mode = t->derive_cofactor_mode;

    if (!ec_cofactors)
        return TEST_skip("not supported by FIPS provider version");

    if (!TEST_ptr(peer1 = EVP_PKEY_Q_keygen(libctx, NULL, "EC", curve)))
        return TEST_skip("Curve %s not supported by the FIPS provider", curve);
```

## Call pattern 7

```c
|| !check_verify_message(pkey_ctx, 1)
        || !TEST_int_eq(EVP_DigestVerify(md_ctx, sig, sig_len,
                            tst->msg, tst->msg_len),
            tst->pass)
        || !check_verify_message(pkey_ctx, 1)
        || !TEST_true(EVP_PKEY_verify_init(pkey_ctx))
        || !check_verify_message(pkey_ctx, 0))
        goto err;

    ret = 1;
err:
    BN_free(rbn);
    BN_free(sbn);
    OPENSSL_free(sig);
    ECDSA_SIG_free(sign);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int ecdh_cofactor_derive_test(int tstid)
{
    int ret = 0;
    const struct ecdh_cofactor_derive_st *t = &ecdh_cofactor_derive_data[tstid];
    unsigned char secret1[16];
    size_t secret1_len = sizeof(secret1);
    const char *curve = "K-283"; /* A curve that has a cofactor that it not 1 */
    EVP_PKEY *peer1 = NULL, *peer2 = NULL;
    EVP_PKEY_CTX *p1ctx = NULL;
    OSSL_PARAM params[2], *prms = NULL;
    int use_cofactordh = t->key_cofactor;
    int cofactor_mode = t->derive_cofactor_mode;

    if (!ec_cofactors)
        return TEST_skip("not supported by FIPS provider version");

    if (!TEST_ptr(peer1 = EVP_PKEY_Q_keygen(libctx, NULL, "EC", curve)))
        return TEST_skip("Curve %s not supported by the FIPS provider", curve);

    if (!TEST_ptr(peer2 = EVP_PKEY_Q_keygen(libctx, NULL, "EC", curve)))
```

## Call pattern 8

```c
if (sign == NULL)
        return 0;
    DSA_SIG_get0(sign, &r1, &s1);
    if (r1 == NULL || s1 == NULL)
        goto err;

    r1_len = BN_num_bytes(r1);
    s1_len = BN_num_bytes(s1);
    rbuf = OPENSSL_zalloc(r1_len);
    sbuf = OPENSSL_zalloc(s1_len);
    if (rbuf == NULL || sbuf == NULL)
        goto err;
    if (BN_bn2binpad(r1, rbuf, r1_len) <= 0)
        goto err;
    if (BN_bn2binpad(s1, sbuf, s1_len) <= 0)
        goto err;
    *r = rbuf;
    *s = sbuf;
    *r_len = r1_len;
    *s_len = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    DSA_SIG_free(sign);
    return ret;
}

static int dsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *r = NULL, *s = NULL;
    size_t sig_len = 0, rlen = 0, slen = 0;
    const struct dsa_siggen_st *tst = &dsa_siggen_data[id];

    if (!dsasign_allowed) {
        if (!TEST_ptr_null(pkey = dsa_keygen(tst->L, tst->N)))
```

## Call pattern 9

```c
DSA_SIG_get0(sign, &r1, &s1);
    if (r1 == NULL || s1 == NULL)
        goto err;

    r1_len = BN_num_bytes(r1);
    s1_len = BN_num_bytes(s1);
    rbuf = OPENSSL_zalloc(r1_len);
    sbuf = OPENSSL_zalloc(s1_len);
    if (rbuf == NULL || sbuf == NULL)
        goto err;
    if (BN_bn2binpad(r1, rbuf, r1_len) <= 0)
        goto err;
    if (BN_bn2binpad(s1, sbuf, s1_len) <= 0)
        goto err;
    *r = rbuf;
    *s = sbuf;
    *r_len = r1_len;
    *s_len = s1_len;
    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(rbuf);
        OPENSSL_free(sbuf);
    }
    DSA_SIG_free(sign);
    return ret;
}

static int dsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *r = NULL, *s = NULL;
    size_t sig_len = 0, rlen = 0, slen = 0;
    const struct dsa_siggen_st *tst = &dsa_siggen_data[id];

    if (!dsasign_allowed) {
        if (!TEST_ptr_null(pkey = dsa_keygen(tst->L, tst->N)))
            goto err;
    } else {
```

## Call pattern 10

```c
|| !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ""))
        || !TEST_int_gt(EVP_PKEY_verify_init(ctx), 0)
        || !TEST_int_eq(EVP_PKEY_verify(ctx, sig, sig_len, digest, digest_len),
            tst->pass))
        goto err;
    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);
    EVP_MD_free(md);
    DSA_SIG_free(sign);
    EVP_PKEY_free(pkey);
    BN_free(rbn);
    BN_free(sbn);
    BN_CTX_free(bn_ctx);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

/* cipher encrypt/decrypt */
static int cipher_enc(const char *alg,
    const unsigned char *pt, size_t pt_len,
    const unsigned char *key, size_t key_len,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *ct, size_t ct_len,
    int enc)
{
    int ret = 0, out_len = 0, len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char out[256] = { 0 };

    TEST_note("%s : %s", alg, enc ? "encrypt" : "decrypt");
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, alg, ""))
        || !TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_CipherUpdate(ctx, out, &len, pt, pt_len))
        || !TEST_true(EVP_CipherFinal_ex(ctx, out + len, &out_len)))
        goto err;
```

## Call pattern 11

```c
|| !TEST_int_gt(EVP_PKEY_verify_init(ctx), 0)
        || !TEST_int_eq(EVP_PKEY_verify(ctx, sig, sig_len, digest, digest_len),
            tst->pass))
        goto err;
    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(sig);
    EVP_MD_free(md);
    DSA_SIG_free(sign);
    EVP_PKEY_free(pkey);
    BN_free(rbn);
    BN_free(sbn);
    BN_CTX_free(bn_ctx);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

/* cipher encrypt/decrypt */
static int cipher_enc(const char *alg,
    const unsigned char *pt, size_t pt_len,
    const unsigned char *key, size_t key_len,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *ct, size_t ct_len,
    int enc)
{
    int ret = 0, out_len = 0, len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char out[256] = { 0 };

    TEST_note("%s : %s", alg, enc ? "encrypt" : "decrypt");
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, alg, ""))
        || !TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_CipherUpdate(ctx, out, &len, pt, pt_len))
        || !TEST_true(EVP_CipherFinal_ex(ctx, out + len, &out_len)))
        goto err;
    out_len += len;
```

## Call pattern 12

```c
goto err;

    test_output_memory("p1", p1, p1_len);
    test_output_memory("p2", p2, p2_len);
    test_output_memory("p", p, p_len);
    test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
```

## Call pattern 13

```c
test_output_memory("p1", p1, p1_len);
    test_output_memory("p2", p2, p2_len);
    test_output_memory("p", p, p_len);
    test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
```

## Call pattern 14

```c
test_output_memory("p1", p1, p1_len);
    test_output_memory("p2", p2, p2_len);
    test_output_memory("p", p, p_len);
    test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
    const struct rsa_siggen_st *tst = &rsa_siggen_data[id];
```

## Call pattern 15

```c
test_output_memory("p2", p2, p2_len);
    test_output_memory("p", p, p_len);
    test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
    const struct rsa_siggen_st *tst = &rsa_siggen_data[id];
    int salt_len = tst->pss_salt_len;
```

## Call pattern 16

```c
test_output_memory("p", p, p_len);
    test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
    const struct rsa_siggen_st *tst = &rsa_siggen_data[id];
    int salt_len = tst->pss_salt_len;
```

## Call pattern 17

```c
test_output_memory("q1", q1, q1_len);
    test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
    const struct rsa_siggen_st *tst = &rsa_siggen_data[id];
    int salt_len = tst->pss_salt_len;

    if (!rsa_sign_x931_pad_allowed
```

## Call pattern 18

```c
test_output_memory("q2", q2, q2_len);
    test_output_memory("q", q, q_len);
    test_output_memory("n", n, n_len);
    test_output_memory("d", d, d_len);
    ret = 1;
err:
    BN_free(xp1_bn);
    BN_free(xp2_bn);
    BN_free(xp_bn);
    BN_free(xq1_bn);
    BN_free(xq2_bn);
    BN_free(xq_bn);
    BN_free(e_bn);
    OPENSSL_free(p1);
    OPENSSL_free(p2);
    OPENSSL_free(q1);
    OPENSSL_free(q2);
    OPENSSL_free(p);
    OPENSSL_free(q);
    OPENSSL_free(n);
    OPENSSL_free(d);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static int rsa_siggen_test(int id)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL, *n = NULL, *e = NULL;
    size_t sig_len = 0, n_len = 0, e_len = 0;
    OSSL_PARAM params[4], *p;
    const struct rsa_siggen_st *tst = &rsa_siggen_data[id];
    int salt_len = tst->pss_salt_len;

    if (!rsa_sign_x931_pad_allowed
        && (strcmp(tst->sig_pad_mode, OSSL_PKEY_RSA_PAD_MODE_X931) == 0))
```

