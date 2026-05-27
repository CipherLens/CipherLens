# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/x509.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
} else if (i == serial) {
            BIO_printf(out, "serial=");
            i2a_ASN1_INTEGER(out, X509_get0_serialNumber(x));
            BIO_printf(out, "\n");
        } else if (i == next_serial) {
            ASN1_INTEGER *ser;
            BIGNUM *bnser = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x), NULL);

            if (bnser == NULL)
                goto err;
            if (!BN_add_word(bnser, 1)
                || (ser = BN_to_ASN1_INTEGER(bnser, NULL)) == NULL) {
                BN_free(bnser);
                goto err;
            }
            BN_free(bnser);
            i2a_ASN1_INTEGER(out, ser);
            ASN1_INTEGER_free(ser);
            BIO_puts(out, "\n");
        } else if (i == email || i == ocsp_uri) {
            STACK_OF(OPENSSL_STRING) *emlst = i == email ? X509_get1_email(x) : X509_get1_ocsp(x);

            for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
                BIO_printf(out, "%s\n", sk_OPENSSL_STRING_value(emlst, j));
            X509_email_free(emlst);
        } else if (i == aliasout) {
            unsigned char *alstr = X509_alias_get0(x, NULL);

            if (alstr)
                BIO_printf(out, "%s\n", alstr);
            else
                BIO_puts(out, "<No Alias>\n");
        } else if (i == subject_hash) {
            BIO_printf(out, "%08lx\n", X509_subject_name_hash(x));
#ifndef OPENSSL_NO_MD5
        } else if (i == subject_hash_old) {
            BIO_printf(out, "%08lx\n", X509_subject_name_hash_old(x));
#endif
        } else if (i == issuer_hash) {
            BIO_printf(out, "%08lx\n", X509_issuer_name_hash(x));
```

## Call pattern 2

```c
BIO_printf(out, "\n");
        } else if (i == next_serial) {
            ASN1_INTEGER *ser;
            BIGNUM *bnser = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x), NULL);

            if (bnser == NULL)
                goto err;
            if (!BN_add_word(bnser, 1)
                || (ser = BN_to_ASN1_INTEGER(bnser, NULL)) == NULL) {
                BN_free(bnser);
                goto err;
            }
            BN_free(bnser);
            i2a_ASN1_INTEGER(out, ser);
            ASN1_INTEGER_free(ser);
            BIO_puts(out, "\n");
        } else if (i == email || i == ocsp_uri) {
            STACK_OF(OPENSSL_STRING) *emlst = i == email ? X509_get1_email(x) : X509_get1_ocsp(x);

            for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
                BIO_printf(out, "%s\n", sk_OPENSSL_STRING_value(emlst, j));
            X509_email_free(emlst);
        } else if (i == aliasout) {
            unsigned char *alstr = X509_alias_get0(x, NULL);

            if (alstr)
                BIO_printf(out, "%s\n", alstr);
            else
                BIO_puts(out, "<No Alias>\n");
        } else if (i == subject_hash) {
            BIO_printf(out, "%08lx\n", X509_subject_name_hash(x));
#ifndef OPENSSL_NO_MD5
        } else if (i == subject_hash_old) {
            BIO_printf(out, "%08lx\n", X509_subject_name_hash_old(x));
#endif
        } else if (i == issuer_hash) {
            BIO_printf(out, "%08lx\n", X509_issuer_name_hash(x));
#ifndef OPENSSL_NO_MD5
        } else if (i == issuer_hash_old) {
            BIO_printf(out, "%08lx\n", X509_issuer_name_hash_old(x));
```

## Call pattern 3

```c
} else if (i == pprint) {
            BIO_printf(out, "Certificate purposes:\n");
            for (j = 0; j < X509_PURPOSE_get_count(); j++)
                purpose_print(out, x, X509_PURPOSE_get0(j));
        } else if (i == modulus) {
            BIO_printf(out, "Modulus=");
            if (EVP_PKEY_is_a(pkey, "RSA") || EVP_PKEY_is_a(pkey, "RSA-PSS")) {
                BIGNUM *n = NULL;

                /* Every RSA key has an 'n' */
                EVP_PKEY_get_bn_param(pkey, "n", &n);
                BN_print(out, n);
                BN_free(n);
            } else if (EVP_PKEY_is_a(pkey, "DSA")) {
                BIGNUM *dsapub = NULL;

                /* Every DSA key has a 'pub' */
                EVP_PKEY_get_bn_param(pkey, "pub", &dsapub);
                BN_print(out, dsapub);
                BN_free(dsapub);
            } else {
                BIO_printf(out, "No modulus for this public key type");
            }
            BIO_printf(out, "\n");
        } else if (i == print_pubkey) {
            PEM_write_bio_PUBKEY(out, pkey);
        } else if (i == text) {
            X509_print_ex(out, x, get_nameopt(), certflag);
        } else if (i == startdate) {
            BIO_puts(out, "notBefore=");
            ASN1_TIME_print_ex(out, X509_get0_notBefore(x), dateopt);
            BIO_puts(out, "\n");
        } else if (i == enddate) {
            BIO_puts(out, "notAfter=");
            ASN1_TIME_print_ex(out, X509_get0_notAfter(x), dateopt);
            BIO_puts(out, "\n");
        } else if (i == fingerprint) {
            unsigned int n;
            unsigned char md[EVP_MAX_MD_SIZE];
            const char *fdigname = digest;
```

## Call pattern 4

```c
BIGNUM *n = NULL;

                /* Every RSA key has an 'n' */
                EVP_PKEY_get_bn_param(pkey, "n", &n);
                BN_print(out, n);
                BN_free(n);
            } else if (EVP_PKEY_is_a(pkey, "DSA")) {
                BIGNUM *dsapub = NULL;

                /* Every DSA key has a 'pub' */
                EVP_PKEY_get_bn_param(pkey, "pub", &dsapub);
                BN_print(out, dsapub);
                BN_free(dsapub);
            } else {
                BIO_printf(out, "No modulus for this public key type");
            }
            BIO_printf(out, "\n");
        } else if (i == print_pubkey) {
            PEM_write_bio_PUBKEY(out, pkey);
        } else if (i == text) {
            X509_print_ex(out, x, get_nameopt(), certflag);
        } else if (i == startdate) {
            BIO_puts(out, "notBefore=");
            ASN1_TIME_print_ex(out, X509_get0_notBefore(x), dateopt);
            BIO_puts(out, "\n");
        } else if (i == enddate) {
            BIO_puts(out, "notAfter=");
            ASN1_TIME_print_ex(out, X509_get0_notAfter(x), dateopt);
            BIO_puts(out, "\n");
        } else if (i == fingerprint) {
            unsigned int n;
            unsigned char md[EVP_MAX_MD_SIZE];
            const char *fdigname = digest;
            EVP_MD *fdig;
            int digres;

            if (fdigname == NULL)
                fdigname = "SHA1";

            if ((fdig = EVP_MD_fetch(app_get0_libctx(), fdigname,
```

## Call pattern 5

```c
if (!BN_add_word(serial, 1)) {
        BIO_printf(bio_err, "Serial number increment failure\n");
        goto end;
    }

    if (file_exists || create)
        save_serial(serialfile, NULL, serial, &bs);
    else
        bs = BN_to_ASN1_INTEGER(serial, NULL);

end:
    OPENSSL_free(buf);
    BN_free(serial);
    return bs;
}

static int callb(int ok, X509_STORE_CTX *ctx)
{
    int err;
    X509 *err_cert;

    /*
     * It is ok to use a self-signed certificate. This case will catch both
     * the initial ok == 0 and the final ok == 1 calls to this function.
     */
    err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        return 1;

    if (!ok) {
        err_cert = X509_STORE_CTX_get_current_cert(ctx);
        print_name(bio_err, "subject=", X509_get_subject_name(err_cert));
        BIO_printf(bio_err,
            "Error with certificate - error %d at depth %d\n%s\n", err,
            X509_STORE_CTX_get_error_depth(ctx),
            X509_verify_cert_error_string(err));
        return 1;
    }

    return 1;
```

