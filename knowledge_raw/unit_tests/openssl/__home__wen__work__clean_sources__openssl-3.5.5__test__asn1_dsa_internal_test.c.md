# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/asn1_dsa_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
0x30, 0x07, /* SEQUENCE tag + length */
    0x02, 0x02, 0x00, 0x81, /* INTEGER tag + length */
    0x02, 0x02, 0x00, 0x82 /* INTEGER tag + length */
};

static int test_decode(void)
{
    int rv = 0;
    BIGNUM *r;
    BIGNUM *s;
    const unsigned char *pder;

    r = BN_new();
    s = BN_new();

    /* Positive tests */
    pder = t_dsa_sig;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig)) == 0
        || !TEST_ptr_eq(pder, (t_dsa_sig + sizeof(t_dsa_sig)))
        || !TEST_BN_eq_word(r, 1) || !TEST_BN_eq_word(s, 2)) {
        TEST_info("asn1_dsa test_decode: t_dsa_sig failed");
        goto fail;
    }

    BN_clear(r);
    BN_clear(s);
    pder = t_dsa_sig_extra;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig_extra)) == 0
        || !TEST_ptr_eq(pder,
            (t_dsa_sig_extra + sizeof(t_dsa_sig_extra) - 2))
        || !TEST_BN_eq_word(r, 1) || !TEST_BN_eq_word(s, 2)) {
        TEST_info("asn1_dsa test_decode: t_dsa_sig_extra failed");
        goto fail;
    }

    BN_clear(r);
    BN_clear(s);
    pder = t_dsa_sig_msb;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig_msb)) == 0
        || !TEST_ptr_eq(pder, (t_dsa_sig_msb + sizeof(t_dsa_sig_msb)))
```

## Call pattern 2

```c
0x02, 0x02, 0x00, 0x81, /* INTEGER tag + length */
    0x02, 0x02, 0x00, 0x82 /* INTEGER tag + length */
};

static int test_decode(void)
{
    int rv = 0;
    BIGNUM *r;
    BIGNUM *s;
    const unsigned char *pder;

    r = BN_new();
    s = BN_new();

    /* Positive tests */
    pder = t_dsa_sig;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig)) == 0
        || !TEST_ptr_eq(pder, (t_dsa_sig + sizeof(t_dsa_sig)))
        || !TEST_BN_eq_word(r, 1) || !TEST_BN_eq_word(s, 2)) {
        TEST_info("asn1_dsa test_decode: t_dsa_sig failed");
        goto fail;
    }

    BN_clear(r);
    BN_clear(s);
    pder = t_dsa_sig_extra;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig_extra)) == 0
        || !TEST_ptr_eq(pder,
            (t_dsa_sig_extra + sizeof(t_dsa_sig_extra) - 2))
        || !TEST_BN_eq_word(r, 1) || !TEST_BN_eq_word(s, 2)) {
        TEST_info("asn1_dsa test_decode: t_dsa_sig_extra failed");
        goto fail;
    }

    BN_clear(r);
    BN_clear(s);
    pder = t_dsa_sig_msb;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_dsa_sig_msb)) == 0
        || !TEST_ptr_eq(pder, (t_dsa_sig_msb + sizeof(t_dsa_sig_msb)))
        || !TEST_BN_eq_word(r, 0x81) || !TEST_BN_eq_word(s, 0x82)) {
```

## Call pattern 3

```c
}

    BN_clear(r);
    BN_clear(s);
    pder = t_trunc_seq;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_trunc_seq)) != 0) {
        TEST_info("asn1_dsa test_decode: Expected fail t_trunc_seq");
        goto fail;
    }

    rv = 1;
fail:
    BN_free(r);
    BN_free(s);
    return rv;
}

int setup_tests(void)
{
    ADD_TEST(test_decode);
    return 1;
}
```

## Call pattern 4

```c
BN_clear(r);
    BN_clear(s);
    pder = t_trunc_seq;
    if (ossl_decode_der_dsa_sig(r, s, &pder, sizeof(t_trunc_seq)) != 0) {
        TEST_info("asn1_dsa test_decode: Expected fail t_trunc_seq");
        goto fail;
    }

    rv = 1;
fail:
    BN_free(r);
    BN_free(s);
    return rv;
}

int setup_tests(void)
{
    ADD_TEST(test_decode);
    return 1;
}
```

