# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_rand.c
Knowledge type: api_constraints

## Snippet 1

```c
if (mdctx == NULL)
        goto end;

    k_bytes = OPENSSL_malloc(num_k_bytes);
    if (k_bytes == NULL)
        goto end;
    /* Ensure top byte is set to avoid non-constant time in bin2bn */
    k_bytes[0] = 0xff;

    /* We copy |priv| into a local buffer to avoid exposing its length. */
    if (BN_bn2binpad(priv, private_bytes, sizeof(private_bytes)) < 0) {
        /*
         * No reasonable DSA or ECDSA key should have a private key this
         * large and we don't handle this case in order to avoid leaking the
         * length of the private key.
         */
        ERR_raise(ERR_LIB_BN, BN_R_PRIVATE_KEY_TOO_LARGE);
        goto end;
    }

    md = EVP_MD_fetch(libctx, "SHA512", NULL);
    if (md == NULL) {
        ERR_raise(ERR_LIB_BN, BN_R_NO_SUITABLE_DIGEST);
        goto end;
    }
    for (n = 0; n < max_n; n++) {
        unsigned char i = 0;
```

