# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/dsa.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
}

    if (modulus) {
        BIGNUM *pub_key = NULL;

        if (!EVP_PKEY_get_bn_param(pkey, "pub", &pub_key)) {
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(out, "Public Key=");
        BN_print(out, pub_key);
        BIO_printf(out, "\n");
        BN_free(pub_key);
    }

    if (noout) {
        ret = 0;
        goto end;
    }
    BIO_printf(bio_err, "writing DSA key\n");
    if (outformat == FORMAT_ASN1) {
        output_type = "DER";
    } else if (outformat == FORMAT_PEM) {
        output_type = "PEM";
    } else if (outformat == FORMAT_MSBLOB) {
        output_type = "MSBLOB";
    } else if (outformat == FORMAT_PVK) {
        if (pubin) {
            BIO_printf(bio_err, "PVK form impossible with public key input\n");
            goto end;
        }
        output_type = "PVK";
    } else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }

    if (outformat == FORMAT_ASN1 || outformat == FORMAT_PEM) {
        if (pubout || pubin)
            output_structure = "SubjectPublicKeyInfo";
```

