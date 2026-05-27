# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/dsatest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
BN_GENCB_set(cb, dsa_cb, NULL);
    if (!TEST_ptr(dsa = DSA_new())
        || !TEST_true(DSA_generate_parameters_ex(dsa, 512, seed, 20,
            &counter, &h, cb)))
        goto end;

    if (!TEST_int_eq(counter, 105))
        goto end;
    if (!TEST_int_eq(h, 2))
        goto end;

    DSA_get0_pqg(dsa, &p, &q, &g);
    i = BN_bn2bin(q, buf);
    j = sizeof(out_q);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_q, i))
        goto end;

    i = BN_bn2bin(p, buf);
    j = sizeof(out_p);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_p, i))
        goto end;

    i = BN_bn2bin(g, buf);
    j = sizeof(out_g);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_g, i))
        goto end;

    if (!TEST_true(DSA_generate_key(dsa)))
        goto end;
    if (!TEST_true(DSA_sign(0, str1, 20, sig, &siglen, dsa)))
        goto end;
    if (TEST_int_gt(DSA_verify(0, str1, 20, sig, siglen, dsa), 0))
        ret = 1;
end:
    DSA_free(dsa);
    BN_GENCB_free(cb);
    return ret;
}

static int dsa_cb(int p, int n, BN_GENCB *arg)
```

## Call pattern 2

```c
if (!TEST_int_eq(counter, 105))
        goto end;
    if (!TEST_int_eq(h, 2))
        goto end;

    DSA_get0_pqg(dsa, &p, &q, &g);
    i = BN_bn2bin(q, buf);
    j = sizeof(out_q);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_q, i))
        goto end;

    i = BN_bn2bin(p, buf);
    j = sizeof(out_p);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_p, i))
        goto end;

    i = BN_bn2bin(g, buf);
    j = sizeof(out_g);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_g, i))
        goto end;

    if (!TEST_true(DSA_generate_key(dsa)))
        goto end;
    if (!TEST_true(DSA_sign(0, str1, 20, sig, &siglen, dsa)))
        goto end;
    if (TEST_int_gt(DSA_verify(0, str1, 20, sig, siglen, dsa), 0))
        ret = 1;
end:
    DSA_free(dsa);
    BN_GENCB_free(cb);
    return ret;
}

static int dsa_cb(int p, int n, BN_GENCB *arg)
{
    static int ok = 0, num = 0;

    if (p == 0)
        num++;
```

## Call pattern 3

```c
DSA_get0_pqg(dsa, &p, &q, &g);
    i = BN_bn2bin(q, buf);
    j = sizeof(out_q);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_q, i))
        goto end;

    i = BN_bn2bin(p, buf);
    j = sizeof(out_p);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_p, i))
        goto end;

    i = BN_bn2bin(g, buf);
    j = sizeof(out_g);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_g, i))
        goto end;

    if (!TEST_true(DSA_generate_key(dsa)))
        goto end;
    if (!TEST_true(DSA_sign(0, str1, 20, sig, &siglen, dsa)))
        goto end;
    if (TEST_int_gt(DSA_verify(0, str1, 20, sig, siglen, dsa), 0))
        ret = 1;
end:
    DSA_free(dsa);
    BN_GENCB_free(cb);
    return ret;
}

static int dsa_cb(int p, int n, BN_GENCB *arg)
{
    static int ok = 0, num = 0;

    if (p == 0)
        num++;
    if (p == 2)
        ok++;

    if (!ok && (p == 0) && (num > 1)) {
        TEST_error("dsa_cb error");
```

## Call pattern 4

```c
|| !TEST_int_eq(hcount_out, expected_h)
        || !TEST_true(EVP_PKEY_get_int_param(key,
            OSSL_PKEY_PARAM_FFC_PCOUNTER,
            &pcount_out))
        || !TEST_int_eq(pcount_out, expected_c)
        || !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);
```

## Call pattern 5

```c
|| !TEST_true(EVP_PKEY_get_int_param(key,
            OSSL_PKEY_PARAM_FFC_PCOUNTER,
            &pcount_out))
        || !TEST_int_eq(pcount_out, expected_c)
        || !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);

    EVP_PKEY_free(params);
```

## Call pattern 6

```c
OSSL_PKEY_PARAM_FFC_PCOUNTER,
            &pcount_out))
        || !TEST_int_eq(pcount_out, expected_c)
        || !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(check_ctx);
```

## Call pattern 7

```c
&pcount_out))
        || !TEST_int_eq(pcount_out, expected_c)
        || !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(check_ctx);
    EVP_PKEY_CTX_free(gen_ctx);
```

## Call pattern 8

```c
|| !TEST_int_eq(pcount_out, expected_c)
        || !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(check_ctx);
    EVP_PKEY_CTX_free(gen_ctx);
    return ret;
```

## Call pattern 9

```c
|| !TEST_false(EVP_PKEY_get_utf8_string_param(key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_out,
            sizeof(group_out), &len)))
        goto end;
    ret = 1;
end:
    BN_free(p_in);
    BN_free(q_in);
    BN_free(g_in);
    BN_free(p_out);
    BN_free(q_out);
    BN_free(g_out);
    EVP_PKEY_free(param_key);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg_ctx);
    EVP_PKEY_CTX_free(pg_ctx);
    return ret;
}

static int test_dsa_default_paramgen_validate(int i)
{
    int ret;
    EVP_PKEY_CTX *gen_ctx = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;
    EVP_PKEY *params = NULL;

    ret = TEST_ptr(gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(gen_ctx), 0)
        && (i == 0
            || TEST_true(EVP_PKEY_CTX_set_dsa_paramgen_bits(gen_ctx, 512)))
        && TEST_int_gt(EVP_PKEY_generate(gen_ctx, &params), 0)
        && TEST_ptr(check_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL))
        && TEST_int_gt(EVP_PKEY_param_check(check_ctx), 0);

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(check_ctx);
    EVP_PKEY_CTX_free(gen_ctx);
    return ret;
}
```

## Call pattern 10

```c
0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(priv2 = BN_dup(priv))
        || !TEST_ptr(badq = BN_new())
        || !TEST_true(BN_set_word(badq, 1))
        || !TEST_ptr(badpriv = BN_new())
        || !TEST_true(BN_set_word(badpriv, 0))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    if (!TEST_int_le(DSA_size(dsa), sizeof(signature)))
        goto err;

    /* Test passing signature as NULL */
    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), NULL, &signature_len0, dsa))
        || !TEST_int_gt(signature_len0, 0))
        goto err;

    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa))
        || !TEST_int_gt(signature_len, 0)
        || !TEST_int_le(signature_len, signature_len0))
        goto err;
```

## Call pattern 11

```c
0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(priv2 = BN_dup(priv))
        || !TEST_ptr(badq = BN_new())
        || !TEST_true(BN_set_word(badq, 1))
        || !TEST_ptr(badpriv = BN_new())
        || !TEST_true(BN_set_word(badpriv, 0))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    if (!TEST_int_le(DSA_size(dsa), sizeof(signature)))
        goto err;

    /* Test passing signature as NULL */
    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), NULL, &signature_len0, dsa))
        || !TEST_int_gt(signature_len0, 0))
        goto err;

    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa))
        || !TEST_int_gt(signature_len, 0)
        || !TEST_int_le(signature_len, signature_len0))
        goto err;

    /* Test using a private key of zero fails - this causes an infinite loop without the retry test */
```

## Call pattern 12

```c
0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(priv2 = BN_dup(priv))
        || !TEST_ptr(badq = BN_new())
        || !TEST_true(BN_set_word(badq, 1))
        || !TEST_ptr(badpriv = BN_new())
        || !TEST_true(BN_set_word(badpriv, 0))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    if (!TEST_int_le(DSA_size(dsa), sizeof(signature)))
        goto err;

    /* Test passing signature as NULL */
    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), NULL, &signature_len0, dsa))
        || !TEST_int_gt(signature_len0, 0))
        goto err;

    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa))
        || !TEST_int_gt(signature_len, 0)
        || !TEST_int_le(signature_len, signature_len0))
        goto err;

    /* Test using a private key of zero fails - this causes an infinite loop without the retry test */
    if (!TEST_true(DSA_set0_key(dsa, NULL, badpriv)))
```

## Call pattern 13

```c
0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(priv2 = BN_dup(priv))
        || !TEST_ptr(badq = BN_new())
        || !TEST_true(BN_set_word(badq, 1))
        || !TEST_ptr(badpriv = BN_new())
        || !TEST_true(BN_set_word(badpriv, 0))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    if (!TEST_int_le(DSA_size(dsa), sizeof(signature)))
        goto err;

    /* Test passing signature as NULL */
    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), NULL, &signature_len0, dsa))
        || !TEST_int_gt(signature_len0, 0))
        goto err;

    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa))
        || !TEST_int_gt(signature_len, 0)
        || !TEST_int_le(signature_len, signature_len0))
        goto err;

    /* Test using a private key of zero fails - this causes an infinite loop without the retry test */
    if (!TEST_true(DSA_set0_key(dsa, NULL, badpriv)))
        goto err;
```

## Call pattern 14

```c
/* Restore private and set a bad q - this caused an infinite loop in the setup */
    if (!TEST_true(DSA_set0_key(dsa, NULL, priv2)))
        goto err;
    priv2 = NULL;
    if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
```

## Call pattern 15

```c
if (!TEST_true(DSA_set0_key(dsa, NULL, priv2)))
        goto err;
    priv2 = NULL;
    if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
```

## Call pattern 16

```c
goto err;
    priv2 = NULL;
    if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
```

## Call pattern 17

```c
priv2 = NULL;
    if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
```

## Call pattern 18

```c
if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
```

## Call pattern 19

```c
goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
```

## Call pattern 20

```c
badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
```

## Call pattern 21

```c
if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
```

## Call pattern 22

```c
|| !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    setpqg = 1;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
```

## Call pattern 23

```c
if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    setpqg = 1;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
```

## Call pattern 24

```c
goto err;
    setpqg = 1;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}
```

## Call pattern 25

```c
goto err;
    pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
```

## Call pattern 26

```c
pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
```

## Call pattern 27

```c
goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
```

## Call pattern 28

```c
BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
```

## Call pattern 29

```c
BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
```

## Call pattern 30

```c
BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
#endif
    return 1;
}
```

## Call pattern 31

```c
if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
#endif
    return 1;
}
```

## Call pattern 32

```c
BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
#endif
    return 1;
}
```

## Call pattern 33

```c
BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
#endif
    return 1;
}
```

## Call pattern 34

```c
BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(dsa_keygen_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
    ADD_ALL_TESTS(test_dsa_default_paramgen_validate, 2);
#endif
    return 1;
}
```

