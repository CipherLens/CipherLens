# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/rsa.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
goto end;
        }
    }

    if (modulus) {
        BIGNUM *n = NULL;

        /* Every RSA key has an 'n' */
        EVP_PKEY_get_bn_param(pkey, "n", &n);
        BIO_printf(out, "Modulus=");
        BN_print(out, n);
        BIO_printf(out, "\n");
        BN_free(n);
    }

    if (check) {
        int r;

        pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (pctx == NULL) {
            BIO_printf(bio_err, "RSA unable to create PKEY context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        r = EVP_PKEY_check(pctx);
        EVP_PKEY_CTX_free(pctx);

        if (r == 1) {
            BIO_printf(out, "RSA key ok\n");
        } else if (r == 0) {
            BIO_printf(bio_err, "RSA key not ok\n");
            ERR_print_errors(bio_err);
        } else if (r < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (noout) {
        ret = 0;
```

