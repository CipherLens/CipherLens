# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/testdsa.h
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
pub_key)
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto err;

    if (EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
               params)
            <= 0)
        pkey = NULL;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(priv_key);
    BN_free(pub_key);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
```

## Call pattern 2

```c
|| (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto err;

    if (EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
               params)
            <= 0)
        pkey = NULL;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(priv_key);
    BN_free(pub_key);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
```

## Call pattern 3

```c
goto err;

    if (EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
               params)
            <= 0)
        pkey = NULL;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(priv_key);
    BN_free(pub_key);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
```

## Call pattern 4

```c
if (EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
               params)
            <= 0)
        pkey = NULL;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(priv_key);
    BN_free(pub_key);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
```

