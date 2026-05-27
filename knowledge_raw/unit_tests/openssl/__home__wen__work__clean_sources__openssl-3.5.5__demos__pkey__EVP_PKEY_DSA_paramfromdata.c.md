# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/demos/pkey/EVP_PKEY_DSA_paramfromdata.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
goto cleanup;
    }

    if (!dsa_print_key(dsaparamkey, 0, libctx, propq))
        goto cleanup;

    ret = EXIT_SUCCESS;
cleanup:
    EVP_PKEY_free(dsaparamkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(g);
    BN_free(q);
    BN_free(p);

    return ret;
}
```

## Call pattern 2

```c
}

    if (!dsa_print_key(dsaparamkey, 0, libctx, propq))
        goto cleanup;

    ret = EXIT_SUCCESS;
cleanup:
    EVP_PKEY_free(dsaparamkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(g);
    BN_free(q);
    BN_free(p);

    return ret;
}
```

## Call pattern 3

```c
if (!dsa_print_key(dsaparamkey, 0, libctx, propq))
        goto cleanup;

    ret = EXIT_SUCCESS;
cleanup:
    EVP_PKEY_free(dsaparamkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(g);
    BN_free(q);
    BN_free(p);

    return ret;
}
```

