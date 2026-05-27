# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/genrsa.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,

    OPT_PARAMETERS(),
    { "numbits", 0, 0, "Size of key in bits" },
    { NULL }
};

int genrsa_main(int argc, char **argv)
{
    BN_GENCB *cb = BN_GENCB_new();
    ENGINE *eng = NULL;
    BIGNUM *bn = BN_new();
    BIO *out = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_CIPHER *enc = NULL;
    int ret = 1, num = DEFBITS, private = 0, primes = DEFPRIMES;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL;
    char *prog, *hexe, *dece, *ciphername = NULL;
    OPTION_CHOICE o;
    int traditional = 0;

    if (bn == NULL || cb == NULL)
        goto end;

    opt_set_unknown_name("cipher");
    prog = opt_init(argc, argv, genrsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
        opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(genrsa_options);
            goto end;
```

## Call pattern 2

```c
if (!init_gen_str(&ctx, "RSA", eng, 0, app_get0_libctx(),
            app_get0_propq()))
        goto end;

    if (verbose)
        EVP_PKEY_CTX_set_cb(ctx, progress_cb);
    EVP_PKEY_CTX_set_app_data(ctx, bio_err);

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, num) <= 0) {
        BIO_printf(bio_err, "Error setting RSA length\n");
        goto end;
    }
    if (!BN_set_word(bn, f4)) {
        BIO_printf(bio_err, "Error allocating RSA public exponent\n");
        goto end;
    }
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <= 0) {
        BIO_printf(bio_err, "Error setting RSA public exponent\n");
        goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) <= 0) {
        BIO_printf(bio_err, "Error setting number of primes\n");
        goto end;
    }
    pkey = app_keygen(ctx, "RSA", num, verbose);
    if (pkey == NULL)
        goto end;

    if (verbose) {
        BIGNUM *e = NULL;

        /* Every RSA key has an 'e' */
        EVP_PKEY_get_bn_param(pkey, "e", &e);
        if (e == NULL) {
            BIO_printf(bio_err, "Error cannot access RSA e\n");
            goto end;
        }
        hexe = BN_bn2hex(e);
        dece = BN_bn2dec(e);
        if (hexe && dece) {
```

## Call pattern 3

```c
if (pkey == NULL)
        goto end;

    if (verbose) {
        BIGNUM *e = NULL;

        /* Every RSA key has an 'e' */
        EVP_PKEY_get_bn_param(pkey, "e", &e);
        if (e == NULL) {
            BIO_printf(bio_err, "Error cannot access RSA e\n");
            goto end;
        }
        hexe = BN_bn2hex(e);
        dece = BN_bn2dec(e);
        if (hexe && dece) {
            BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
        }
        OPENSSL_free(hexe);
        OPENSSL_free(dece);
        BN_free(e);
    }
    if (traditional) {
        if (!PEM_write_bio_PrivateKey_traditional(out, pkey, enc, NULL, 0,
                NULL, passout))
            goto end;
    } else {
        if (!PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, passout))
            goto end;
    }

    ret = 0;
end:
    BN_free(bn);
    BN_GENCB_free(cb);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_CIPHER_free(enc);
    BIO_free_all(out);
    release_engine(eng);
    OPENSSL_free(passout);
```

## Call pattern 4

```c
goto end;

    if (verbose) {
        BIGNUM *e = NULL;

        /* Every RSA key has an 'e' */
        EVP_PKEY_get_bn_param(pkey, "e", &e);
        if (e == NULL) {
            BIO_printf(bio_err, "Error cannot access RSA e\n");
            goto end;
        }
        hexe = BN_bn2hex(e);
        dece = BN_bn2dec(e);
        if (hexe && dece) {
            BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
        }
        OPENSSL_free(hexe);
        OPENSSL_free(dece);
        BN_free(e);
    }
    if (traditional) {
        if (!PEM_write_bio_PrivateKey_traditional(out, pkey, enc, NULL, 0,
                NULL, passout))
            goto end;
    } else {
        if (!PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, passout))
            goto end;
    }

    ret = 0;
end:
    BN_free(bn);
    BN_GENCB_free(cb);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_CIPHER_free(enc);
    BIO_free_all(out);
    release_engine(eng);
    OPENSSL_free(passout);
    if (ret != 0)
```

## Call pattern 5

```c
EVP_PKEY_get_bn_param(pkey, "e", &e);
        if (e == NULL) {
            BIO_printf(bio_err, "Error cannot access RSA e\n");
            goto end;
        }
        hexe = BN_bn2hex(e);
        dece = BN_bn2dec(e);
        if (hexe && dece) {
            BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
        }
        OPENSSL_free(hexe);
        OPENSSL_free(dece);
        BN_free(e);
    }
    if (traditional) {
        if (!PEM_write_bio_PrivateKey_traditional(out, pkey, enc, NULL, 0,
                NULL, passout))
            goto end;
    } else {
        if (!PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, passout))
            goto end;
    }

    ret = 0;
end:
    BN_free(bn);
    BN_GENCB_free(cb);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_CIPHER_free(enc);
    BIO_free_all(out);
    release_engine(eng);
    OPENSSL_free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    return ret;
}
```

## Call pattern 6

```c
}
    if (traditional) {
        if (!PEM_write_bio_PrivateKey_traditional(out, pkey, enc, NULL, 0,
                NULL, passout))
            goto end;
    } else {
        if (!PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, passout))
            goto end;
    }

    ret = 0;
end:
    BN_free(bn);
    BN_GENCB_free(cb);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_CIPHER_free(enc);
    BIO_free_all(out);
    release_engine(eng);
    OPENSSL_free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    return ret;
}
```

