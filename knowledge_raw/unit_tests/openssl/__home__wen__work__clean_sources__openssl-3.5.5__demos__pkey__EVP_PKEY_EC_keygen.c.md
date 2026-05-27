# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/demos/pkey/EVP_PKEY_EC_keygen.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
            out_pubkey, sizeof(out_pubkey),
            &out_pubkey_len)) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &out_priv)) {
        fprintf(stderr, "Failed to get private key\n");
        goto cleanup;
    }

    out_privkey_len = BN_bn2bin(out_priv, out_privkey);
    if (out_privkey_len <= 0 || out_privkey_len > sizeof(out_privkey)) {
        fprintf(stderr, "BN_bn2bin failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Curve name: %s\n", out_curvename);
    fprintf(stdout, "Public key:\n");
    BIO_dump_indent_fp(stdout, out_pubkey, out_pubkey_len, 2);
    fprintf(stdout, "Private Key:\n");
    BIO_dump_indent_fp(stdout, out_privkey, out_privkey_len, 2);

    ret = 1;
cleanup:
    /* Zeroize the private key data when we free it */
    BN_clear_free(out_priv);
    return ret;
}

int main(void)
{
    int ret = EXIT_FAILURE;
    EVP_PKEY *pkey;

    pkey = do_ec_keygen();
    if (pkey == NULL)
        goto cleanup;
```

## Call pattern 2

```c
&out_pubkey_len)) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &out_priv)) {
        fprintf(stderr, "Failed to get private key\n");
        goto cleanup;
    }

    out_privkey_len = BN_bn2bin(out_priv, out_privkey);
    if (out_privkey_len <= 0 || out_privkey_len > sizeof(out_privkey)) {
        fprintf(stderr, "BN_bn2bin failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Curve name: %s\n", out_curvename);
    fprintf(stdout, "Public key:\n");
    BIO_dump_indent_fp(stdout, out_pubkey, out_pubkey_len, 2);
    fprintf(stdout, "Private Key:\n");
    BIO_dump_indent_fp(stdout, out_privkey, out_privkey_len, 2);

    ret = 1;
cleanup:
    /* Zeroize the private key data when we free it */
    BN_clear_free(out_priv);
    return ret;
}

int main(void)
{
    int ret = EXIT_FAILURE;
    EVP_PKEY *pkey;

    pkey = do_ec_keygen();
    if (pkey == NULL)
        goto cleanup;

    if (!get_key_values(pkey))
        goto cleanup;
```

