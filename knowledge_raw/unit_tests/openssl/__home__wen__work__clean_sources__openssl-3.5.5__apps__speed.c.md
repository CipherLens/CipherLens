# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/speed.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (RAND_bytes(loopargs[i].buf, 36) <= 0)
            goto end;

    for (testnum = 0; testnum < RSA_NUM; testnum++) {
        EVP_PKEY *rsa_key = NULL;
        int st = 0;

        if (!rsa_doit[testnum])
            continue;

        if (primes > RSA_DEFAULT_PRIME_NUM) {
            /* we haven't set keys yet,  generate multi-prime RSA keys */
            bn = BN_new();
            st = bn != NULL
                && BN_set_word(bn, RSA_F4)
                && init_gen_str(&genctx, "RSA", NULL, 0, NULL, NULL)
                && EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, rsa_keys[testnum].bits) > 0
                && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(genctx, bn) > 0
                && EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) > 0
                && EVP_PKEY_keygen(genctx, &rsa_key) > 0;
            BN_free(bn);
            bn = NULL;
            EVP_PKEY_CTX_free(genctx);
            genctx = NULL;
        } else {
            const unsigned char *p = rsa_keys[testnum].data;

            st = (rsa_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p,
                      rsa_keys[testnum].length))
                != NULL;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].rsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].rsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].rsa_sign_ctx[testnum]) <= 0
                || EVP_PKEY_sign(loopargs[i].rsa_sign_ctx[testnum],
                       loopargs[i].buf2,
                       &loopargs[i].sigsize,
```

## Call pattern 2

```c
for (testnum = 0; testnum < RSA_NUM; testnum++) {
        EVP_PKEY *rsa_key = NULL;
        int st = 0;

        if (!rsa_doit[testnum])
            continue;

        if (primes > RSA_DEFAULT_PRIME_NUM) {
            /* we haven't set keys yet,  generate multi-prime RSA keys */
            bn = BN_new();
            st = bn != NULL
                && BN_set_word(bn, RSA_F4)
                && init_gen_str(&genctx, "RSA", NULL, 0, NULL, NULL)
                && EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, rsa_keys[testnum].bits) > 0
                && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(genctx, bn) > 0
                && EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) > 0
                && EVP_PKEY_keygen(genctx, &rsa_key) > 0;
            BN_free(bn);
            bn = NULL;
            EVP_PKEY_CTX_free(genctx);
            genctx = NULL;
        } else {
            const unsigned char *p = rsa_keys[testnum].data;

            st = (rsa_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p,
                      rsa_keys[testnum].length))
                != NULL;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].rsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].rsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].rsa_sign_ctx[testnum]) <= 0
                || EVP_PKEY_sign(loopargs[i].rsa_sign_ctx[testnum],
                       loopargs[i].buf2,
                       &loopargs[i].sigsize,
                       loopargs[i].buf, 36)
                    <= 0)
```

## Call pattern 3

```c
continue;

        if (primes > RSA_DEFAULT_PRIME_NUM) {
            /* we haven't set keys yet,  generate multi-prime RSA keys */
            bn = BN_new();
            st = bn != NULL
                && BN_set_word(bn, RSA_F4)
                && init_gen_str(&genctx, "RSA", NULL, 0, NULL, NULL)
                && EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, rsa_keys[testnum].bits) > 0
                && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(genctx, bn) > 0
                && EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) > 0
                && EVP_PKEY_keygen(genctx, &rsa_key) > 0;
            BN_free(bn);
            bn = NULL;
            EVP_PKEY_CTX_free(genctx);
            genctx = NULL;
        } else {
            const unsigned char *p = rsa_keys[testnum].data;

            st = (rsa_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p,
                      rsa_keys[testnum].length))
                != NULL;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].rsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].rsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].rsa_sign_ctx[testnum]) <= 0
                || EVP_PKEY_sign(loopargs[i].rsa_sign_ctx[testnum],
                       loopargs[i].buf2,
                       &loopargs[i].sigsize,
                       loopargs[i].buf, 36)
                    <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                "RSA sign setup failure.  No RSA sign will be done.\n");
            dofail();
```

## Call pattern 4

```c
sigs_results[k][1], sigs_results[k][2]);
    }
    ret = 0;

end:
    if (ret == 0 && testmode)
        ret = testmoderesult;
    ERR_print_errors(bio_err);
    for (i = 0; i < loopargs_len; i++) {
        OPENSSL_free(loopargs[i].buf_malloc);
        OPENSSL_free(loopargs[i].buf2_malloc);

        BN_free(bn);
        EVP_PKEY_CTX_free(genctx);
        for (k = 0; k < RSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].rsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].rsa_verify_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].rsa_encrypt_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].rsa_decrypt_ctx[k]);
        }
#ifndef OPENSSL_NO_DH
        OPENSSL_free(loopargs[i].secret_ff_a);
        OPENSSL_free(loopargs[i].secret_ff_b);
        for (k = 0; k < FFDH_NUM; k++)
            EVP_PKEY_CTX_free(loopargs[i].ffdh_ctx[k]);
#endif
#ifndef OPENSSL_NO_DSA
        for (k = 0; k < DSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].dsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].dsa_verify_ctx[k]);
        }
#endif
        for (k = 0; k < ECDSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].ecdsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].ecdsa_verify_ctx[k]);
        }
        for (k = 0; k < EC_NUM; k++)
            EVP_PKEY_CTX_free(loopargs[i].ecdh_ctx[k]);
#ifndef OPENSSL_NO_ECX
        for (k = 0; k < EdDSA_NUM; k++) {
```

