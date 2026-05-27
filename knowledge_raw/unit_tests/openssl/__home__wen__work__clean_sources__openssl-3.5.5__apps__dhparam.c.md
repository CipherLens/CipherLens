# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/dhparam.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
ctx = EVP_PKEY_CTX_new_from_name(app_get0_libctx(), "DHX", app_get0_propq());
    if (ctx == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params) <= 0) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_g);
    return pkey;
}
```

## Call pattern 2

```c
if (ctx == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params) <= 0) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_g);
    return pkey;
}
```

## Call pattern 3

```c
|| EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params) <= 0) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_g);
    return pkey;
}
```

