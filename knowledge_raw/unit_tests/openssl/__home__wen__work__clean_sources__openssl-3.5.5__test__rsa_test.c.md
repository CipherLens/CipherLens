# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/rsa_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
};

    if (!TEST_ptr(rsa = RSA_new()))
        return NULL;
    pn = BN_bin2bn(n, sizeof(n), NULL);
    pe = BN_bin2bn(e, sizeof(e), NULL);
    if (priv)
        pd = BN_bin2bn(d, sizeof(d), NULL);
    if (!TEST_false(pn == NULL
            || pe == NULL
            || (priv && pd == NULL)
            || !RSA_set0_key(rsa, pn, pe, pd))) {
        BN_free(pn);
        BN_free(pe);
        BN_free(pd);
        RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

static int test_rsa_saos(void)
{
    int ret = 0;
    unsigned int siglen = 0;
    RSA *rsa_priv = NULL, *rsa_pub = NULL;
    static const unsigned char in[256] = { 0 };
    unsigned char sig[256];
    /* Maximum length allowed: The 3 relates to the octet byte 0x04 followed by a 2 byte length */
    unsigned int inlen = sizeof(in) - RSA_PKCS1_PADDING_SIZE - 3;

    /* A generated signature when in[inlen]= { 1 }. */
    static const unsigned char sig_mismatch[256] = {
        0x5f, 0x64, 0xab, 0xd3, 0x86, 0xdf, 0x6e, 0x91,
        0xa8, 0xdb, 0x9d, 0x36, 0x7a, 0x15, 0xe5, 0x75,
        0xe4, 0x27, 0xdf, 0xeb, 0x8d, 0xaf, 0xb0, 0x60,
        0xec, 0x36, 0x8b, 0x00, 0x36, 0xb4, 0x61, 0x38,
        0xfe, 0xfa, 0x49, 0x55, 0xcf, 0xb7, 0xff, 0xeb,
        0x25, 0xa5, 0x41, 0x1e, 0xaa, 0x74, 0x3d, 0x57,
        0xed, 0x5c, 0x4a, 0x01, 0x9e, 0xb2, 0x50, 0xbc,
```

## Call pattern 2

```c
if (!TEST_ptr(rsa = RSA_new()))
        return NULL;
    pn = BN_bin2bn(n, sizeof(n), NULL);
    pe = BN_bin2bn(e, sizeof(e), NULL);
    if (priv)
        pd = BN_bin2bn(d, sizeof(d), NULL);
    if (!TEST_false(pn == NULL
            || pe == NULL
            || (priv && pd == NULL)
            || !RSA_set0_key(rsa, pn, pe, pd))) {
        BN_free(pn);
        BN_free(pe);
        BN_free(pd);
        RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

static int test_rsa_saos(void)
{
    int ret = 0;
    unsigned int siglen = 0;
    RSA *rsa_priv = NULL, *rsa_pub = NULL;
    static const unsigned char in[256] = { 0 };
    unsigned char sig[256];
    /* Maximum length allowed: The 3 relates to the octet byte 0x04 followed by a 2 byte length */
    unsigned int inlen = sizeof(in) - RSA_PKCS1_PADDING_SIZE - 3;

    /* A generated signature when in[inlen]= { 1 }. */
    static const unsigned char sig_mismatch[256] = {
        0x5f, 0x64, 0xab, 0xd3, 0x86, 0xdf, 0x6e, 0x91,
        0xa8, 0xdb, 0x9d, 0x36, 0x7a, 0x15, 0xe5, 0x75,
        0xe4, 0x27, 0xdf, 0xeb, 0x8d, 0xaf, 0xb0, 0x60,
        0xec, 0x36, 0x8b, 0x00, 0x36, 0xb4, 0x61, 0x38,
        0xfe, 0xfa, 0x49, 0x55, 0xcf, 0xb7, 0xff, 0xeb,
        0x25, 0xa5, 0x41, 0x1e, 0xaa, 0x74, 0x3d, 0x57,
        0xed, 0x5c, 0x4a, 0x01, 0x9e, 0xb2, 0x50, 0xbc,
        0x50, 0x15, 0xd5, 0x97, 0x93, 0x91, 0x97, 0xa3,
```

## Call pattern 3

```c
if (!TEST_ptr(rsa = RSA_new()))
        return NULL;
    pn = BN_bin2bn(n, sizeof(n), NULL);
    pe = BN_bin2bn(e, sizeof(e), NULL);
    if (priv)
        pd = BN_bin2bn(d, sizeof(d), NULL);
    if (!TEST_false(pn == NULL
            || pe == NULL
            || (priv && pd == NULL)
            || !RSA_set0_key(rsa, pn, pe, pd))) {
        BN_free(pn);
        BN_free(pe);
        BN_free(pd);
        RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

static int test_rsa_saos(void)
{
    int ret = 0;
    unsigned int siglen = 0;
    RSA *rsa_priv = NULL, *rsa_pub = NULL;
    static const unsigned char in[256] = { 0 };
    unsigned char sig[256];
    /* Maximum length allowed: The 3 relates to the octet byte 0x04 followed by a 2 byte length */
    unsigned int inlen = sizeof(in) - RSA_PKCS1_PADDING_SIZE - 3;

    /* A generated signature when in[inlen]= { 1 }. */
    static const unsigned char sig_mismatch[256] = {
        0x5f, 0x64, 0xab, 0xd3, 0x86, 0xdf, 0x6e, 0x91,
        0xa8, 0xdb, 0x9d, 0x36, 0x7a, 0x15, 0xe5, 0x75,
        0xe4, 0x27, 0xdf, 0xeb, 0x8d, 0xaf, 0xb0, 0x60,
        0xec, 0x36, 0x8b, 0x00, 0x36, 0xb4, 0x61, 0x38,
        0xfe, 0xfa, 0x49, 0x55, 0xcf, 0xb7, 0xff, 0xeb,
        0x25, 0xa5, 0x41, 0x1e, 0xaa, 0x74, 0x3d, 0x57,
        0xed, 0x5c, 0x4a, 0x01, 0x9e, 0xb2, 0x50, 0xbc,
        0x50, 0x15, 0xd5, 0x97, 0x93, 0x91, 0x97, 0xa3,
        0xff, 0x67, 0x2a, 0xe9, 0x04, 0xdd, 0x31, 0x6f,
```

