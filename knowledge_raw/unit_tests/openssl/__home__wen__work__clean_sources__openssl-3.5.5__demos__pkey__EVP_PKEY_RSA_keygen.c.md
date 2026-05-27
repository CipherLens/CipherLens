# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/demos/pkey/EVP_PKEY_RSA_keygen.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
/*
     * Output a PEM encoding of the private key. Please note that this output is
     * not encrypted. You may wish to use the arguments to specify encryption of
     * the key if you are storing it on disk. See PEM_write_PrivateKey(3).
     */
    if (PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded private key\n");
        goto cleanup;
    }

    ret = 1;
cleanup:
    BN_free(n); /* not secret */
    BN_free(e); /* not secret */
    BN_clear_free(d); /* secret - scrub before freeing */
    BN_clear_free(p); /* secret - scrub before freeing */
    BN_clear_free(q); /* secret - scrub before freeing */
    return ret;
}

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int bits = 4096;
    int bits_i, use_short = 0;

    /* usage: [-s] [<bits>] */
    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        --argc;
        ++argv;
        use_short = 1;
    }

    if (argc > 1) {
        bits_i = atoi(argv[1]);
        if (bits_i < 512) {
            fprintf(stderr, "Invalid RSA key size\n");
            return EXIT_FAILURE;
```

## Call pattern 2

```c
* Output a PEM encoding of the private key. Please note that this output is
     * not encrypted. You may wish to use the arguments to specify encryption of
     * the key if you are storing it on disk. See PEM_write_PrivateKey(3).
     */
    if (PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded private key\n");
        goto cleanup;
    }

    ret = 1;
cleanup:
    BN_free(n); /* not secret */
    BN_free(e); /* not secret */
    BN_clear_free(d); /* secret - scrub before freeing */
    BN_clear_free(p); /* secret - scrub before freeing */
    BN_clear_free(q); /* secret - scrub before freeing */
    return ret;
}

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int bits = 4096;
    int bits_i, use_short = 0;

    /* usage: [-s] [<bits>] */
    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        --argc;
        ++argv;
        use_short = 1;
    }

    if (argc > 1) {
        bits_i = atoi(argv[1]);
        if (bits_i < 512) {
            fprintf(stderr, "Invalid RSA key size\n");
            return EXIT_FAILURE;
        }
```

