# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/ts.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
goto err;
        if ((serial = BN_to_ASN1_INTEGER(bn, NULL)) == NULL)
            goto err;
    }
    ret = 1;

err:
    if (!ret) {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    BIO_free_all(in);
    BN_free(bn);
    return serial;
}

static int save_ts_serial(const char *serialfile, ASN1_INTEGER *serial)
{
    int ret = 0;
    BIO *out = NULL;

    if ((out = BIO_new_file(serialfile, "w")) == NULL)
        goto err;
    if (i2a_ASN1_INTEGER(out, serial) <= 0)
        goto err;
    if (BIO_puts(out, "\n") <= 0)
        goto err;
    ret = 1;
err:
    if (!ret)
        BIO_printf(bio_err, "could not save serial number to %s\n",
            serialfile);
    BIO_free_all(out);
    return ret;
}

/*
 * Verify-related method definitions.
 */
```

