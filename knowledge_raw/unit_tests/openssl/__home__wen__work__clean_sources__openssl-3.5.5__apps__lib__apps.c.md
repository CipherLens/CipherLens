# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/lib/apps.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
}
}

void print_bignum_var(BIO *out, const BIGNUM *in, const char *var,
    int len, unsigned char *buffer)
{
    BIO_printf(out, "    static unsigned char %s_%d[] = {", var, len);
    if (BN_is_zero(in)) {
        BIO_printf(out, "\n        0x00");
    } else {
        int i, l;

        l = BN_bn2bin(in, buffer);
        for (i = 0; i < l; i++) {
            BIO_printf(out, (i % 10) == 0 ? "\n        " : " ");
            if (i < l - 1)
                BIO_printf(out, "0x%02X,", buffer[i]);
            else
                BIO_printf(out, "0x%02X", buffer[i]);
        }
    }
    BIO_printf(out, "\n    };\n");
}

void print_array(BIO *out, const char *title, int len, const unsigned char *d)
{
    int i;

    BIO_printf(out, "unsigned char %s[%d] = {", title, len);
    for (i = 0; i < len; i++) {
        if ((i % 10) == 0)
            BIO_printf(out, "\n    ");
        if (i < len - 1)
            BIO_printf(out, "0x%02X, ", d[i]);
        else
            BIO_printf(out, "0x%02X", d[i]);
    }
    BIO_printf(out, "\n};\n");
}
```

## Call pattern 2

```c
if (ai == NULL)
        goto err;

    in = BIO_new_file(serialfile, "r");
    if (exists != NULL)
        *exists = in != NULL;
    if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        ERR_clear_error();
        ret = BN_new();
        if (ret == NULL) {
            BIO_printf(bio_err, "Out of memory\n");
        } else if (!rand_serial(ret, ai)) {
            BIO_printf(bio_err, "Error creating random number to store in %s\n",
                serialfile);
            BN_free(ret);
            ret = NULL;
        }
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            BIO_printf(bio_err, "Unable to load number from %s\n",
                serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            BIO_printf(bio_err, "Error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret != NULL && retai != NULL) {
        *retai = ai;
        ai = NULL;
    }
err:
    if (ret == NULL)
```

## Call pattern 3

```c
if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        ERR_clear_error();
        ret = BN_new();
        if (ret == NULL) {
            BIO_printf(bio_err, "Out of memory\n");
        } else if (!rand_serial(ret, ai)) {
            BIO_printf(bio_err, "Error creating random number to store in %s\n",
                serialfile);
            BN_free(ret);
            ret = NULL;
        }
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            BIO_printf(bio_err, "Unable to load number from %s\n",
                serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            BIO_printf(bio_err, "Error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret != NULL && retai != NULL) {
        *retai = ai;
        ai = NULL;
    }
err:
    if (ret == NULL)
        ERR_print_errors(bio_err);
    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return ret;
}
```

## Call pattern 4

```c
}
    return 1;
err:
    ERR_print_errors(bio_err);
    return 0;
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr)
{
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    BIO *in;
    CONF *dbattr_conf = NULL;
    char buf[BSIZE];
#ifndef OPENSSL_NO_POSIX_IO
    FILE *dbfp;
```

## Call pattern 5

```c
return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr)
{
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    BIO *in;
    CONF *dbattr_conf = NULL;
    char buf[BSIZE];
#ifndef OPENSSL_NO_POSIX_IO
    FILE *dbfp;
    struct stat dbst;
#endif

    in = BIO_new_file(dbfile, "r");
    if (in == NULL)
        goto err;

#ifndef OPENSSL_NO_POSIX_IO
    BIO_get_fp(in, &dbfp);
    if (fstat(fileno(dbfp), &dbst) == -1) {
        ERR_raise_data(ERR_LIB_SYS, errno,
            "calling fstat(%s)", dbfile);
        goto err;
    }
```

