# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/helpers/predefined_dhparams.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
BIGNUM *p = NULL, *g = NULL, *q = NULL;

    p = BN_bin2bn(pdata, plen, NULL);
    g = BN_bin2bn(gdata, glen, NULL);
    if (p == NULL || g == NULL)
        goto err;
    if (qdata != NULL && (q = BN_bin2bn(qdata, qlen, NULL)) == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, type, p, g, q);

err:
    BN_free(p);
    BN_free(g);
    BN_free(q);
    return dhpkey;
}

EVP_PKEY *get_dh512(OSSL_LIB_CTX *libctx)
{
    static unsigned char dh512_p[] = {
        0xCB,
        0xC8,
        0xE1,
        0x86,
        0xD0,
        0x1F,
        0x94,
        0x17,
        0xA6,
        0x99,
        0xF0,
        0xC6,
        0x1F,
        0x0D,
        0xAC,
        0xB6,
        0x25,
        0x3E,
        0x06,
```

## Call pattern 2

```c
p = BN_bin2bn(pdata, plen, NULL);
    g = BN_bin2bn(gdata, glen, NULL);
    if (p == NULL || g == NULL)
        goto err;
    if (qdata != NULL && (q = BN_bin2bn(qdata, qlen, NULL)) == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, type, p, g, q);

err:
    BN_free(p);
    BN_free(g);
    BN_free(q);
    return dhpkey;
}

EVP_PKEY *get_dh512(OSSL_LIB_CTX *libctx)
{
    static unsigned char dh512_p[] = {
        0xCB,
        0xC8,
        0xE1,
        0x86,
        0xD0,
        0x1F,
        0x94,
        0x17,
        0xA6,
        0x99,
        0xF0,
        0xC6,
        0x1F,
        0x0D,
        0xAC,
        0xB6,
        0x25,
        0x3E,
        0x06,
        0x39,
```

## Call pattern 3

```c
p = BN_bin2bn(pdata, plen, NULL);
    g = BN_bin2bn(gdata, glen, NULL);
    if (p == NULL || g == NULL)
        goto err;
    if (qdata != NULL && (q = BN_bin2bn(qdata, qlen, NULL)) == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, type, p, g, q);

err:
    BN_free(p);
    BN_free(g);
    BN_free(q);
    return dhpkey;
}

EVP_PKEY *get_dh512(OSSL_LIB_CTX *libctx)
{
    static unsigned char dh512_p[] = {
        0xCB,
        0xC8,
        0xE1,
        0x86,
        0xD0,
        0x1F,
        0x94,
        0x17,
        0xA6,
        0x99,
        0xF0,
        0xC6,
        0x1F,
        0x0D,
        0xAC,
        0xB6,
        0x25,
        0x3E,
        0x06,
        0x39,
        0xCA,
```

## Call pattern 4

```c
0xA2,
    };

    return get_dh_from_pg(libctx, "DH", dh1024_p, sizeof(dh1024_p),
        dh1024_g, sizeof(dh1024_g), NULL, 0);
}

EVP_PKEY *get_dh2048(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_2048(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

EVP_PKEY *get_dh4096(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_4096(NULL);
    if (p == NULL)
        goto err;
```

## Call pattern 5

```c
};

    return get_dh_from_pg(libctx, "DH", dh1024_p, sizeof(dh1024_p),
        dh1024_g, sizeof(dh1024_g), NULL, 0);
}

EVP_PKEY *get_dh2048(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_2048(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

EVP_PKEY *get_dh4096(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_4096(NULL);
    if (p == NULL)
        goto err;
```

## Call pattern 6

```c
g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_2048(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

EVP_PKEY *get_dh4096(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_4096(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

#endif
```

## Call pattern 7

```c
err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

EVP_PKEY *get_dh4096(OSSL_LIB_CTX *libctx)
{
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY *dhpkey = NULL;

    g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_4096(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

#endif
```

## Call pattern 8

```c
g = BN_new();
    if (g == NULL || !BN_set_word(g, 2))
        goto err;

    p = BN_get_rfc3526_prime_4096(NULL);
    if (p == NULL)
        goto err;

    dhpkey = get_dh_from_pg_bn(libctx, "DH", p, g, NULL);

err:
    BN_free(p);
    BN_free(g);
    return dhpkey;
}

#endif
```

