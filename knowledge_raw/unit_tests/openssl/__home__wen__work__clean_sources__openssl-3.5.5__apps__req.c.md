# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/req.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
tpubkey = X509_REQ_get0_pubkey(req);
        if (tpubkey == NULL) {
            BIO_puts(bio_err, "Modulus is unavailable\n");
            goto end;
        }
        BIO_puts(out, "Modulus=");
        if (EVP_PKEY_is_a(tpubkey, "RSA") || EVP_PKEY_is_a(tpubkey, "RSA-PSS")) {
            BIGNUM *n = NULL;

            if (!EVP_PKEY_get_bn_param(tpubkey, "n", &n))
                goto end;
            BN_print(out, n);
            BN_free(n);
        } else {
            BIO_puts(out, "Wrong Algorithm type");
        }
        BIO_puts(out, "\n");
    }

    if (!noout && !gen_x509) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_REQ_bio(out, req);
        else if (newhdr)
            i = PEM_write_bio_X509_REQ_NEW(out, req);
        else
            i = PEM_write_bio_X509_REQ(out, req);
        if (!i) {
            BIO_printf(bio_err, "Unable to write certificate request\n");
            goto end;
        }
    }
    if (!noout && gen_x509 && new_x509 != NULL) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_bio(out, new_x509);
        else
            i = PEM_write_bio_X509(out, new_x509);
        if (!i) {
            BIO_printf(bio_err, "Unable to write X509 certificate\n");
            goto end;
        }
```

