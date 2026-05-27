# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/ssl_old_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
#ifndef OPENSSL_NO_PSK
/* convert the PSK key (psk_key) in ascii to binary (psk) */
static int psk_key2bn(const char *pskkey, unsigned char *psk,
    unsigned int max_psk_len)
{
    int ret;
    BIGNUM *bn = NULL;

    ret = BN_hex2bn(&bn, pskkey);
    if (!ret) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
            pskkey);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
            "psk buffer of callback is too small (%d) for key (%d)\n",
            max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }
    ret = BN_bn2bin(bn, psk);
    BN_free(bn);
    return ret;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len)
{
    int ret;
    unsigned int psk_len = 0;

    ret = BIO_snprintf(identity, max_identity_len, "Client_identity");
    if (ret < 0)
        goto out_err;
    if (debug)
```

## Call pattern 2

```c
ret = BN_hex2bn(&bn, pskkey);
    if (!ret) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
            pskkey);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
            "psk buffer of callback is too small (%d) for key (%d)\n",
            max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }
    ret = BN_bn2bin(bn, psk);
    BN_free(bn);
    return ret;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len)
{
    int ret;
    unsigned int psk_len = 0;

    ret = BIO_snprintf(identity, max_identity_len, "Client_identity");
    if (ret < 0)
        goto out_err;
    if (debug)
        fprintf(stderr, "client: created identity '%s' len=%d\n", identity,
            ret);
    ret = psk_key2bn(psk_key, psk, max_psk_len);
    if (ret < 0)
        goto out_err;
    psk_len = ret;
out_err:
```

## Call pattern 3

```c
BIO_printf(bio_err, "Could not convert PSK key '%s' to BIGNUM\n",
            pskkey);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
            "psk buffer of callback is too small (%d) for key (%d)\n",
            max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }
    ret = BN_bn2bin(bn, psk);
    BN_free(bn);
    return ret;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len)
{
    int ret;
    unsigned int psk_len = 0;

    ret = BIO_snprintf(identity, max_identity_len, "Client_identity");
    if (ret < 0)
        goto out_err;
    if (debug)
        fprintf(stderr, "client: created identity '%s' len=%d\n", identity,
            ret);
    ret = psk_key2bn(psk_key, psk, max_psk_len);
    if (ret < 0)
        goto out_err;
    psk_len = ret;
out_err:
    return psk_len;
}
```

## Call pattern 4

```c
pskkey);
        BN_free(bn);
        return 0;
    }
    if (BN_num_bytes(bn) > (int)max_psk_len) {
        BIO_printf(bio_err,
            "psk buffer of callback is too small (%d) for key (%d)\n",
            max_psk_len, BN_num_bytes(bn));
        BN_free(bn);
        return 0;
    }
    ret = BN_bn2bin(bn, psk);
    BN_free(bn);
    return ret;
}

static unsigned int psk_client_callback(SSL *ssl, const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len)
{
    int ret;
    unsigned int psk_len = 0;

    ret = BIO_snprintf(identity, max_identity_len, "Client_identity");
    if (ret < 0)
        goto out_err;
    if (debug)
        fprintf(stderr, "client: created identity '%s' len=%d\n", identity,
            ret);
    ret = psk_key2bn(psk_key, psk, max_psk_len);
    if (ret < 0)
        goto out_err;
    psk_len = ret;
out_err:
    return psk_len;
}

static unsigned int psk_server_callback(SSL *ssl, const char *identity,
```

