# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/dsa_no_digest_size_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
0x7D, 0xDA, 0x66, 0xC9, 0xC0, 0x72, 0x72, 0x22, 0x0F, 0x1A,
        0xCC, 0x23, 0xD9, 0xB7, 0x5F, 0x1B
    };
    DSA *dsa = DSA_new();
    BIGNUM *p, *q, *g;

    if (dsa == NULL)
        return NULL;
    if (!DSA_set0_pqg(dsa, p = BN_bin2bn(dsap_2048, sizeof(dsap_2048), NULL),
            q = BN_bin2bn(dsaq_2048, sizeof(dsaq_2048), NULL),
            g = BN_bin2bn(dsag_2048, sizeof(dsag_2048), NULL))) {
        DSA_free(dsa);
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return NULL;
    }
    return dsa;
}

static int genkeys(void)
{
    if (!TEST_ptr(dsakey = load_dsa_params()))
        return 0;

    if (!TEST_int_eq(DSA_generate_key(dsakey), 1))
        return 0;

    return 1;
}

static int sign_and_verify(int len)
{
    /*
     * Per FIPS 186-4, the hash is recommended to be the same length as q.
     * If the hash is longer than q, the leftmost N bits are used; if the hash
     * is shorter, then we left-pad (see appendix C.2.1).
     */
    size_t sigLength;
    int digestlen = BN_num_bytes(DSA_get0_q(dsakey));
```

## Call pattern 2

```c
0xCC, 0x23, 0xD9, 0xB7, 0x5F, 0x1B
    };
    DSA *dsa = DSA_new();
    BIGNUM *p, *q, *g;

    if (dsa == NULL)
        return NULL;
    if (!DSA_set0_pqg(dsa, p = BN_bin2bn(dsap_2048, sizeof(dsap_2048), NULL),
            q = BN_bin2bn(dsaq_2048, sizeof(dsaq_2048), NULL),
            g = BN_bin2bn(dsag_2048, sizeof(dsag_2048), NULL))) {
        DSA_free(dsa);
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return NULL;
    }
    return dsa;
}

static int genkeys(void)
{
    if (!TEST_ptr(dsakey = load_dsa_params()))
        return 0;

    if (!TEST_int_eq(DSA_generate_key(dsakey), 1))
        return 0;

    return 1;
}

static int sign_and_verify(int len)
{
    /*
     * Per FIPS 186-4, the hash is recommended to be the same length as q.
     * If the hash is longer than q, the leftmost N bits are used; if the hash
     * is shorter, then we left-pad (see appendix C.2.1).
     */
    size_t sigLength;
    int digestlen = BN_num_bytes(DSA_get0_q(dsakey));
    int ok = 0;
```

## Call pattern 3

```c
};
    DSA *dsa = DSA_new();
    BIGNUM *p, *q, *g;

    if (dsa == NULL)
        return NULL;
    if (!DSA_set0_pqg(dsa, p = BN_bin2bn(dsap_2048, sizeof(dsap_2048), NULL),
            q = BN_bin2bn(dsaq_2048, sizeof(dsaq_2048), NULL),
            g = BN_bin2bn(dsag_2048, sizeof(dsag_2048), NULL))) {
        DSA_free(dsa);
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return NULL;
    }
    return dsa;
}

static int genkeys(void)
{
    if (!TEST_ptr(dsakey = load_dsa_params()))
        return 0;

    if (!TEST_int_eq(DSA_generate_key(dsakey), 1))
        return 0;

    return 1;
}

static int sign_and_verify(int len)
{
    /*
     * Per FIPS 186-4, the hash is recommended to be the same length as q.
     * If the hash is longer than q, the leftmost N bits are used; if the hash
     * is shorter, then we left-pad (see appendix C.2.1).
     */
    size_t sigLength;
    int digestlen = BN_num_bytes(DSA_get0_q(dsakey));
    int ok = 0;
```

